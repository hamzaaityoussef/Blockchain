#include <iostream>
#include <vector>
#include <string>
#include <bitset>
#include <random>
#include <cassert>
#include <iomanip>
#include <sstream>
#include <cmath>

// --- Exemple de fonction ac_hash (à remplacer par la tienne) ---
uint32_t ac_hash(const std::string& s) {
    uint32_t hash = 0;
    for (char c : s) {
        hash = (hash * 31) + static_cast<uint8_t>(c);
    }
    return hash;
}

// --- Convertir un uint32_t en bits ---
std::vector<int> hash_to_bits(uint32_t hash) {
    std::vector<int> bits(32);
    for (int i = 0; i < 32; ++i) {
        bits[31 - i] = (hash >> i) & 1;
    }
    return bits;
}

int main() {
    const int sample_size = 4000; // 4000 hashes * 32 bits = 128000 bits > 10^5
    int ones_count = 0;

    std::mt19937 rng(42); // seed fixe pour reproductibilité
    std::uniform_int_distribution<int> dist(0, 255);

    for (int i = 0; i < sample_size; ++i) {
        // Générer un message aléatoire de 10 caractères
        std::string msg(10, ' ');
        for (int j = 0; j < 10; ++j) {
            msg[j] = static_cast<char>(dist(rng));
        }

        uint32_t hash_val = ac_hash(msg);
        auto bits = hash_to_bits(hash_val);
        for (int b : bits) ones_count += b;
    }

    int total_bits = sample_size * 32;
    double percent_ones = 100.0 * ones_count / total_bits;

    std::cout << "Bits totaux : " << total_bits << "\n";
    std::cout << "Bits à 1 : " << ones_count << "\n";
    std::cout << "Pourcentage de 1 : " << std::fixed << std::setprecision(2)
        << percent_ones << "%\n";

    if (percent_ones > 48.0 && percent_ones < 52.0)
        std::cout << "Distribution équilibrée (≈50%)\n";
    else
        std::cout << "Distribution non équilibrée\n";

    return 0;
}
