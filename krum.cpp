#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <numeric>
#include <random>
#include <chrono>

using namespace std;
using namespace seal;

// === CONFIGURATION ===
constexpr int num_clients = 200;
constexpr int param_size = 500000 / 4;  // Number of model parameters 1199882 (MNIST)
constexpr int beta = 1;             // Number of Byzantine clients

size_t ciphertext_size_bytes(const Ciphertext &cipher)
{
    std::stringstream ss;
    cipher.save(ss);
    return ss.str().size();
}

// === Encrypt a vector using CKKS ===
Ciphertext encrypt_vector(const vector<double> &input, Encryptor &encryptor, CKKSEncoder &encoder, double scale)
{
    Plaintext plain;
    encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    return encrypted;
}

// === Compute squared L2 distance between two encrypted models (chunked) ===
Ciphertext compute_pairwise_distance(const vector<Ciphertext> &model_i,
                                     const vector<Ciphertext> &model_j,
                                     Evaluator &evaluator,
                                     RelinKeys &relin_keys)
{
    Ciphertext total_dist;
    bool first = true;

    for (size_t k = 0; k < model_i.size(); ++k)
    {
        Ciphertext diff;
        evaluator.sub(model_i[k], model_j[k], diff);
        evaluator.square_inplace(diff);
        evaluator.relinearize_inplace(diff, relin_keys);

        if (first)
        {
            total_dist = diff;
            first = false;
        }
        else
        {
            evaluator.add_inplace(total_dist, diff);
        }
    }

    return total_dist;
}

int main()
{
    // === SETUP CKKS PARAMETERS ===
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    //print_parameters(context);
    cout << endl;

    // === KEYGEN AND ENCODER ===
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);
    size_t slot_count = encoder.slot_count();  // 16384 for poly_modulus_degree = 32768
    size_t num_chunks = (param_size + slot_count - 1) / slot_count;

    // === GENERATE RANDOM MODELS AND ENCRYPT ===
    vector<vector<Ciphertext>> encrypted_models(num_clients);
    mt19937 rng(1000);  // Reproducible
    uniform_real_distribution<double> dist(0.0, 100.0);

    for (int i = 0; i < num_clients; ++i)
    {
        vector<double> model(param_size);
        for (int j = 0; j < param_size; ++j)
        {
            model[j] = dist(rng);
        }

        vector<Ciphertext> encrypted_model_chunks;
        for (size_t chunk = 0; chunk < num_chunks; ++chunk)
        {
            size_t start = chunk * slot_count;
            size_t end = min(start + slot_count, static_cast<size_t>(param_size));
            vector<double> chunk_data(model.begin() + start, model.begin() + end);
            chunk_data.resize(slot_count, 0.0);  // Zero-padding

            Ciphertext encrypted = encrypt_vector(chunk_data, encryptor, encoder, scale);
            encrypted_model_chunks.push_back(encrypted);
        }

        encrypted_models[i] = encrypted_model_chunks;
    }

    // To multiply with a random number
    double rand_scalar = 3.0;
    Plaintext plain_rand;
    encoder.encode(rand_scalar, scale, plain_rand);
    Ciphertext enc_rand_scalar;
    encryptor.encrypt(plain_rand, enc_rand_scalar);

    cout << "Encryption Done.\n";

    // === COMPUTE PAIRWISE DISTANCES ===
    vector<vector<Ciphertext>> distance_matrix(num_clients, vector<Ciphertext>(num_clients));
    auto start = chrono::high_resolution_clock::now();

    int count = 0;
    for (int i = 0; i < num_clients; ++i)
    {
        for (int j = i + 1; j < num_clients; ++j)
        {
            Ciphertext dist = compute_pairwise_distance(encrypted_models[i], encrypted_models[j], evaluator, relin_keys);
            evaluator.multiply_inplace(dist, enc_rand_scalar);
            evaluator.relinearize_inplace(dist, relin_keys);
            distance_matrix[i][j] = dist;
            distance_matrix[j][i] = dist;
            count += 1;
        }
    }

    cout << "Computation Done";
    auto end1 = chrono::high_resolution_clock::now();
    chrono::duration<double> duration1 = end1 - start;
    cout << "Time to compute: " << duration1.count() << " seconds.\n";

    // === OPTIONAL: DECRYPT & PRINT ONE DISTANCE FOR DEBUGGING ===
    /*for (int i = 0; i < num_clients; ++i)
    {
        for (int j = i + 1; j < num_clients; ++j)
        {
            Plaintext plain_result;
            vector<double> decoded;
            decryptor.decrypt(distance_matrix[i][j], plain_result);
            encoder.decode(plain_result, decoded);

            double l2_squared = accumulate(decoded.begin(), decoded.end(), 0.0);
            //cout << "Decrypted squared distance[" << i << "][" << j << "] = " << l2_squared << endl;

            break;  // Just one example, remove this if you want all
        }
        break;
    }*/

    vector<Ciphertext> client_scores(num_clients);

    // Step 1: Sum each row
    for (int i = 0; i < num_clients; ++i)
    {
        Ciphertext sum;
        bool first = true;

        for (int j = 0; j < num_clients; ++j)
        {
            if (i == j) continue; // skip uninitialized diagonal

            if (first)
            {
                sum = distance_matrix[i][j];
                first = false;
            }
            else
            {
                evaluator.add_inplace(sum, distance_matrix[i][j]);
            }
        }

        client_scores[i] = sum;
    }

    // Step 2: Decrypt and decode each score
    for (int i = 0; i < num_clients; ++i)
    {
        Plaintext plain_result;
        decryptor.decrypt(client_scores[i], plain_result);

        // For CKKS
        vector<double> decoded;
        encoder.decode(plain_result, decoded);
        //cout << "Client " << i << " score: " << decoded[0] << endl;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << "Time to compute and decrypt pairwise distances: " << duration.count() << " seconds.\n";
    cout << "Count, Size of one encrypted packet is: " << count << "\t" << ciphertext_size_bytes(distance_matrix[0][1]) << " in bytes.\n";
    cout << "Total encrypted packet size is: " << count * ciphertext_size_bytes(distance_matrix[0][1]) << " in bytes.\n";

    // === TODO: ADD KRUM LOGIC BASED ON DECRYPTED DISTANCES ===

    return 0;
}
