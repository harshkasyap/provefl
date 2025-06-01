#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// === CONFIGURATION ===
constexpr int num_clients = 200;
constexpr int param_size = 818000 / 4;  // Number of model parameters 1199882 (MNIST)
constexpr int beta = 1;             // Number of Byzantine clients

size_t ciphertext_size_bytes(const Ciphertext &cipher)
{
    std::stringstream ss;
    cipher.save(ss);
    return ss.str().size();
}


void print_decrypted_model(const vector<Ciphertext> &model_chunks,
                           Decryptor &decryptor,
                           CKKSEncoder &encoder,
                           size_t values_to_show = param_size)
{
    vector<double> full_model;

    for (const auto &chunk : model_chunks)
    {
        Plaintext plain;
        decryptor.decrypt(chunk, plain);

        vector<double> decoded;
        encoder.decode(plain, decoded);

        full_model.insert(full_model.end(), decoded.begin(), decoded.end());
    }

    // Optional: truncate trailing zero padding
    while (!full_model.empty() && abs(full_model.back()) < 1e-6)
        full_model.pop_back();

    // Print first few values
    cout << "Decrypted model (" << full_model.size() << " values):\n";
    for (size_t i = 0; i < min(values_to_show, full_model.size()); ++i)
        cout << full_model[i] << " ";
    if (values_to_show < full_model.size())
        cout << "...";
    cout << endl;
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

// --- Batcher's Odd-Even Mergesort Network ---
void merge(int lo, int n, int r, int total_size, vector<pair<int,int>> &pairs) {
    int step = r * 2;
    if (step < n) {
        merge(lo, n, step, total_size, pairs);
        merge(lo + r, n, step, total_size, pairs);
        for (int i = lo + r; i + r < lo + n; i += step) {
            if (i + r < total_size) {
                pairs.emplace_back(i, i + r);
            }
        }
    } else {
        if (lo + r < total_size) {
            pairs.emplace_back(lo, lo + r);
        }
    }
}

void sort_network(int lo, int n, int total_size, vector<pair<int,int>> &pairs) {
    if (n > 1) {
        int m = n / 2;
        sort_network(lo, m, total_size, pairs);
        sort_network(lo + m, n - m, total_size, pairs);
        merge(lo, n, 1, total_size, pairs);
    }
}

vector<pair<int,int>> batcher_sort_indices(int n) {
    vector<pair<int,int>> index_pairs;
    sort_network(0, n, n, index_pairs);  // Pass total size `n`
    return index_pairs;
}

// Compute the mask value based on decrypted value of 'diff'
int compute_mask(const Ciphertext &diff, Decryptor &decryptor, CKKSEncoder &encoder)
{
    Plaintext plain_diff;
    decryptor.decrypt(diff, plain_diff);

    vector<double> decoded_diff;
    encoder.decode(plain_diff, decoded_diff);

    return decoded_diff[0] > 0 ? 1 : 0;
}

// Perform conditional swap using mask
pair<Ciphertext, Ciphertext> conditional_swap(const Ciphertext &arr1, const Ciphertext &arr2,
                                              const Ciphertext &enc_r,
                                              Decryptor &decryptor,
                                              Evaluator &evaluator,
                                              CKKSEncoder &encoder,
                                              double scale)
{
    // Step 1: Compute diff = arr1 - arr2
    Ciphertext diff;
    evaluator.sub(arr1, arr2, diff);

    cout << "sub done";

    // Step 2: Match enc_r to diff's level
    /*Ciphertext enc_r_local = enc_r;
    if (enc_r_local.parms_id() != diff.parms_id()) {
        evaluator.mod_switch_to_inplace(enc_r_local, diff.parms_id());
    }

    // Step 3: Match scales before multiplication
    double target_scale = diff.scale();
    if (fabs(enc_r_local.scale() - target_scale) > 0.01)
        throw std::runtime_error("enc_r and diff have mismatched scales before multiplication.");
    */
    
    // Step 4: Multiply diff * enc_r
    //evaluator.multiply_inplace(diff, enc_r);
    //evaluator.rescale_to_next_inplace(diff);

    // Step 5: Get mask from decrypted diff
    /*int mask = compute_mask(diff, decryptor, encoder); // Semi-honest assumption
    int inv_mask = 1 - mask;

    // Step 6: Encode mask values with proper scale
    Plaintext plain_mask, plain_inv_mask;
    encoder.encode(static_cast<double>(mask), scale, plain_mask);
    encoder.encode(static_cast<double>(inv_mask), scale, plain_inv_mask);*/

    // Step 7: Match levels of masks to arr1/arr2
    /*if (plain_mask.parms_id() != arr1.parms_id())
        evaluator.mod_switch_to_inplace(plain_mask, arr1.parms_id());
    if (plain_inv_mask.parms_id() != arr1.parms_id())
        evaluator.mod_switch_to_inplace(plain_inv_mask, arr1.parms_id());*/

    // Step 8: Match arr2 level to arr1
    /*Ciphertext arr2_mod = arr2;
    if (arr2_mod.parms_id() != arr1.parms_id()) {
        evaluator.mod_switch_to_inplace(arr2_mod, arr1.parms_id());
    }

    // Step 9: Check scale match between arr1 and arr2_mod
    if (fabs(arr1.scale() - arr2_mod.scale()) > 0.01)
        throw std::runtime_error("arr1 and arr2_mod have mismatched scales.");*/

    // Step 10: Compute new_arr1 = arr1 * (1 - mask) + arr2 * mask
    Ciphertext part1, part2, new_arr1, new_arr2;
    /*evaluator.multiply_plain(arr1, plain_inv_mask, part1);
    evaluator.multiply_plain(arr2, plain_mask, part2);
    evaluator.add(part1, part2, new_arr1);

    // Step 11: Compute new_arr2 = arr1 * mask + arr2 * (1 - mask)
    evaluator.multiply_plain(arr1, plain_mask, part1);
    evaluator.multiply_plain(arr2, plain_inv_mask, part2);
    evaluator.add(part1, part2, new_arr2);*/

    //return {new_arr1, new_arr2};
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

    int n = (int)encrypted_models.size();

    vector<double> r_vec(slot_count, 3.0);
    Ciphertext enc_r = encrypt_vector(r_vec, encryptor, encoder, scale);

    auto start = chrono::high_resolution_clock::now();

    // Get Batcher's sorting network pairs
    auto index_pairs = batcher_sort_indices(n);

    // Perform sorting network with conditional swaps
    vector<Ciphertext> new_model_i, new_model_j;
    Ciphertext diff;
    for (auto &[i, j] : index_pairs) {
        auto &model_i = encrypted_models[i];
        auto &model_j = encrypted_models[j];

        for (size_t k = 0; k < num_chunks; ++k) {
            //auto [swapped1, swapped2] = 
            //conditional_swap(model_i[k], model_j[k], enc_r, decryptor, evaluator, encoder, scale);
            evaluator.sub(model_i[k], model_j[k], diff);
            evaluator.multiply_inplace(diff, enc_r);

            int mask = compute_mask(diff, decryptor, encoder); // Semi-honest assumption
            int inv_mask = 1 - mask;

            Plaintext plain_mask, plain_inv_mask;
            encoder.encode(static_cast<double>(mask), scale, plain_mask);
            encoder.encode(static_cast<double>(inv_mask), scale, plain_inv_mask);

            Ciphertext part1, part2, new_arr1, new_arr2;
            evaluator.multiply_plain(model_i[k], plain_inv_mask, part1);
            evaluator.multiply_plain(model_j[k], plain_mask, part2);
            evaluator.add(part1, part2, new_arr1);

            // Step 11: Compute new_arr2 = arr1 * mask + arr2 * (1 - mask)
            evaluator.multiply_plain(model_i[k], plain_mask, part1);
            evaluator.multiply_plain(model_j[k], plain_inv_mask, part2);
            evaluator.add(part1, part2, new_arr2);
            new_model_i.push_back(new_arr1);
            new_model_j.push_back(new_arr2);
        }

        //encrypted_models[i] = new_model_i;
        //encrypted_models[j] = new_model_j;
    }

    cout << "Decryption Done.\n";

    //print_decrypted_model(encrypted_models[0], decryptor, encoder);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << "Time to compute and decrypt pairwise distances: " << duration.count() << " seconds.\n";
    //cout << "Count, Size of one encrypted packet is: " << count << "\t" << ciphertext_size_bytes(distance_matrix[0][1]) << " in bytes.\n";
    cout << "Total encrypted packet size is: " << size(index_pairs) * ciphertext_size_bytes(diff) / 1073741824.0 << " in GB.\n";

    return 0;
}