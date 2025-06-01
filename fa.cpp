#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// === CONFIGURATION ===
constexpr int num_clients = 200;
constexpr int param_size = 273000 / 4;  // Number of model parameters 1199882 (MNIST)
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

int main() {
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

    cout << "Encryption Done.\n";
    
    auto start = chrono::high_resolution_clock::now();

    // Initialize result with a deep copy of the first model
    vector<Ciphertext> sum_chunks = encrypted_models[0];

    for (size_t i = 1; i < num_clients; ++i)
    {
        for (size_t j = 0; j < num_chunks; ++j)
        {
            evaluator.add_inplace(sum_chunks[j], encrypted_models[i][j]);
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
        break;
    }

    //print_decrypted_model(encrypted_models[0], decryptor, encoder);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << "Time to compute and decrypt pairwise distances: " << duration.count() << " seconds.\n";
    //cout << "Count, Size of one encrypted packet is: " << count << "\t" << ciphertext_size_bytes(distance_matrix[0][1]) << " in bytes.\n";
    //cout << "Total encrypted packet size is: " << size(index_pairs) * ciphertext_size_bytes(diff) / 1073741824.0 << " in GB.\n";
    //cout << "Total encrypted packet size is: " << num_clients * ciphertext_size_bytes(encrypted_models[0]) << " in bytes.\n";


    size_t total_size = 0;
    for (const auto &chunk : encrypted_models[0]) {
        std::stringstream ss;
        chunk.save(ss);
        total_size += ss.str().size();
    }
    std::cout << "Total Ciphertext size (serialized): " << total_size / 1073741824.0 << " GB" << std::endl;


    return 0;
}