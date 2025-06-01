#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <random>
#include <chrono>

using namespace std;

// Generate random client models
typedef vector<double> Model;

double l2_norm(const Model &model) {
    double sum = 0.0;
    for (double x : model)
        sum += x * x;
    return sqrt(sum);
}

Model fedavg(const vector<Model> &models) {
    int n = models.size(), d = models[0].size();
    Model avg(d, 0.0);
    for (const auto &model : models)
        for (int i = 0; i < d; ++i)
            avg[i] += model[i];
    for (int i = 0; i < d; ++i)
        avg[i] /= n;
    return avg;
}

Model trimmed_mean(const vector<Model> &models, int trim_k) {
    int n = models.size(), d = models[0].size();
    Model result(d);
    for (int i = 0; i < d; ++i) {
        vector<double> values;
        for (const auto &model : models)
            values.push_back(model[i]);
        sort(values.begin(), values.end());
        double sum = 0.0;
        for (int j = trim_k; j < n - trim_k; ++j)
            sum += values[j];
        result[i] = sum / (n - 2 * trim_k);
    }
    return result;
}

Model krum(const vector<Model> &models, int num_adv) {
    int n = models.size(), d = models[0].size();
    vector<double> scores(n, 0.0);
    for (int i = 0; i < n; ++i) {
        vector<pair<double, int>> dists;
        for (int j = 0; j < n; ++j) {
            if (i == j) continue;
            double dist = 0.0;
            for (int k = 0; k < d; ++k)
                dist += pow(models[i][k] - models[j][k], 2);
            dists.emplace_back(dist, j);
        }
        sort(dists.begin(), dists.end());
        for (int k = 0; k < n - num_adv - 2; ++k)
            scores[i] += dists[k].first;
    }
    int best = min_element(scores.begin(), scores.end()) - scores.begin();
    return models[best];
}

Model fltrust(const vector<Model> &models, const Model &server_model) {
    int n = models.size(), d = server_model.size();
    Model result(d, 0.0);
    double sum_weights = 0.0;
    for (const auto &model : models) {
        double dot = 0.0;
        for (int i = 0; i < d; ++i)
            dot += server_model[i] * model[i];
        double norm_s = l2_norm(server_model);
        double norm_m = l2_norm(model);
        double trust = dot / (norm_s * norm_m + 1e-8);
        for (int i = 0; i < d; ++i)
            result[i] += trust * model[i];
        sum_weights += trust;
    }
    for (int i = 0; i < d; ++i)
        result[i] /= sum_weights;
    return result;
}

Model l2_clip(const Model &model, double threshold) {
    double norm = l2_norm(model);
    if (norm <= threshold) return model;
    Model clipped(model.size());
    for (int i = 0; i < model.size(); ++i)
        clipped[i] = model[i] * (threshold / norm);
    return clipped;
}

int main() {
    int num_clients = 10;
    int param_size = 100000;
    int num_adv = 2;
    double clip_threshold = 5.0;

    // Random model generation
    random_device rd;
    mt19937 gen(rd());
    normal_distribution<> dist(0, 1);

    vector<Model> models(num_clients, Model(param_size));
    for (auto &model : models)
        for (auto &x : model)
            x = dist(gen);

    // Clipping all models for L2 defense
    vector<Model> clipped_models;
    for (const auto &m : models)
        clipped_models.push_back(l2_clip(m, clip_threshold));

    Model server_model = models[0];

    size_t bytes_per_model = param_size * sizeof(double);
    size_t total_comm = num_clients * bytes_per_model;

    cout << "Communication per round (upload): " << total_comm / 1024.0 << " KB\n\n";

    auto time_it = [&](auto func, string name) {
        auto start = chrono::high_resolution_clock::now();
        Model agg = func();
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double, milli> dur = end - start;
        cout << name << " Time: " << dur.count() << " ms\n";
    };

    time_it([&] { return fedavg(models); }, "FedAvg");
    time_it([&] { return trimmed_mean(models, num_adv); }, "Trimmed Mean");
    time_it([&] { return krum(models, num_adv); }, "Krum");
    time_it([&] { return fltrust(models, server_model); }, "FLTrust");
    time_it([&] { return fedavg(clipped_models); }, "L2 Norm Defense (FedAvg on clipped models)");

    return 0;
}
