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
constexpr int num_clients = 10;
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

    vector<Ciphertext> encrypted_dot_products(num_clients);
    
    auto start = chrono::high_resolution_clock::now();
    // Loop over each client (excluding client 0 if self-dot is not needed)
    for (int i = 0; i < num_clients; ++i)
    {
        Ciphertext dot_product_sum;
        bool first = true;

        for (size_t chunk = 0; chunk < num_chunks; ++chunk)
        {
            Ciphertext m1 = encrypted_models[0][chunk];
            Ciphertext m2 = encrypted_models[i][chunk];

            // Step 2: Multiply chunk-wise and rescale
            Ciphertext mult;
            evaluator.multiply(m1, m2, mult);
            //evaluator.relinearize_inplace(mult, relin_keys);
            //evaluator.rescale_to_next_inplace(mult);

            // Step 3: Sum all slots within the chunk (dot product)
            /*Ciphertext chunk_sum = mult;
            int log_slots = static_cast<int>(log2(slot_count));
            for (int j = 1; j < slot_count; j <<= 1)
            {
                Ciphertext rotated;
                GaloisKeys gal_keys = keygen.galois_keys_local(); // or use precomputed galois keys
                evaluator.rotate_vector(chunk_sum, j, gal_keys, rotated);
                evaluator.add_inplace(chunk_sum, rotated);
            }*/

            // Step 4: Accumulate across chunks
            if (first)
            {
                dot_product_sum = mult;
                first = false;
            }
            else
            {
                // Align modulus/scale again before addition
                evaluator.add_inplace(dot_product_sum, mult);
            }
        }

        evaluator.multiply_inplace(dot_product_sum, enc_rand_scalar);
        //evaluator.relinearize_inplace(dot_product_sum, relin_keys);
        encrypted_dot_products[i] = dot_product_sum;

    }

    cout << "partial computation Done\n";

    //Remaining operations
    for (int i = 0; i < num_clients; ++i)
    {
        Plaintext plain_result;
        decryptor.decrypt(encrypted_dot_products[i], plain_result);

        vector<double> decoded_result;
        encoder.decode(plain_result, decoded_result);

        double sum = 0.0;
        for (double val : decoded_result)
        {
            sum += val;
        }

        //cout << "Decrypted dot product result for model " << i << " is " << sum << endl;

        vector<double> repeated_scalar(encoder.slot_count(), sum);
        Plaintext plain_scalar;
        encoder.encode(repeated_scalar, scale, plain_scalar);

        for (Ciphertext &chunk : encrypted_models[i]) {
            evaluator.multiply_plain_inplace(chunk, plain_scalar);
        }

    }

    cout << "computation Done\n";

    auto end1 = chrono::high_resolution_clock::now();
    chrono::duration<double> duration1 = end1 - start;
    cout << "Time to compute: " << duration1.count() << " seconds.\n";

    // Decrypt
    for (int i = 0; i < num_clients; ++i)
    {
        vector<double> full_model;
        for (const auto &chunk : encrypted_models[i]) {
            Plaintext plain;
            decryptor.decrypt(chunk, plain);

            vector<double> decoded;
            encoder.decode(plain, decoded);

            full_model.insert(full_model.end(), decoded.begin(), decoded.end());
        }
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << "Time to compute and decrypt: " << duration.count() << " seconds.\n";
    //cout << "Count, Size of one encrypted packet is: " << count << "\t" << ciphertext_size_bytes(distance_matrix[0][1]) << " in bytes.\n";
    cout << "Total encrypted packet size is: " << num_clients * ciphertext_size_bytes(encrypted_dot_products[0]) << " in bytes.\n";

    // === TODO: ADD KRUM LOGIC BASED ON DECRYPTED DISTANCES ===

    return 0;
}
