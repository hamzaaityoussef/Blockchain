#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cassert>

// Convertit une chaîne en un vecteur de bits (MSB-first par octet)
static std::vector<int> string_to_bits(const std::string& s) {
    std::vector<int> bits;
    bits.reserve(s.size() * 8);
    for (unsigned char c : s) {
        for (int i = 7; i >= 0; --i) { // MSB first
            bits.push_back((c >> i) & 1);
        }
    }
    return bits;
}

// Initialise un état de taille 256 en "foldant" les bits d'entrée : XOR des bits sur les 256 positions
static std::vector<int> init_state_from_bits(const std::vector<int>& bits, size_t state_size = 256) {
    std::vector<int> state(state_size, 0);
    for (size_t i = 0; i < bits.size(); ++i) {
        state[i % state_size] ^= (bits[i] & 1); // XOR fold pour mélanger toute l'entrée
    }
    // Pour éviter l'état tout nul quand l'entrée est vide, on encode la longueur aussi :
    uint64_t len = bits.size();
    for (size_t i = 0; i < 64 && i < state_size; ++i) {
        state[i] ^= ( (len >> i) & 1 );
    }
    return state;
}

// Évolution d'une génération (voisinage r = 1), condition aux limites cyclique (wrap-around)
static std::vector<int> evolve_once(const std::vector<int>& state, uint8_t rule8) {
    size_t n = state.size();
    std::vector<int> next(n, 0);

    for (size_t i = 0; i < n; ++i) {
        int left  = state[(i + n - 1) % n];
        int self  = state[i];
        int right = state[(i + 1) % n];
        int pattern = (left << 2) | (self << 1) | right; // 0..7

        // On utilise le bit 'pattern' de rule8 (LSB = pattern 0 = 000)
        next[i] = (rule8 >> pattern) & 1;
    }
    return next;
}

// Applique 'steps' générations
static std::vector<int> evolve_steps(std::vector<int> state, uint8_t rule8, size_t steps) {
    for (size_t t = 0; t < steps; ++t) {
        state = evolve_once(state, rule8);
    }
    return state;
}

// Convertit un état de 256 bits en chaîne hex (64 hex chars)
static std::string state_to_hex256(const std::vector<int>& state) {
    assert(state.size() == 256);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t byte_idx = 0; byte_idx < 32; ++byte_idx) {
        unsigned int byte = 0;
        for (int bit = 0; bit < 8; ++bit) {
            byte = (byte << 1) | (state[byte_idx * 8 + bit] & 1); // MSB-first in the byte
        }
        oss << std::setw(2) << (byte & 0xFF);
    }
    return oss.str();
}

// fonction hash
std::string ac_hash(const std::string& input, uint32_t rule, size_t steps) {
    // On conserve seulement les 8 LSB de rule (Wolfram rules sont 0..255)
    uint8_t rule8 = static_cast<uint8_t>(rule & 0xFF);

    // 2.2 Conversion du texte en bits
    std::vector<int> bits = string_to_bits(input);

    // Initialisation de l'état (256 cellules)
    std::vector<int> state = init_state_from_bits(bits, 256);

    // 2.3 Évolution et production d'un hash 256 bits
    std::vector<int> final_state = evolve_steps(state, rule8, steps);

    std::string hex = state_to_hex256(final_state);
    return hex; // 64 hex chars -> 256 bits
}
// test
int main() {
    std::string a = "Bonjour";
    std::string b = "bjr"; // différent 
    uint32_t rule = 30;      // Rule 30 par exemple
    size_t steps = 256;      // nombre de générations (paramètre)

    std::string ha = ac_hash(a, rule, steps);
    std::string hb = ac_hash(b, rule, steps);

    std::cout << "hash(\"" << a << "\") = " << ha << "\n";
    std::cout << "hash(\"" << b << "\") = " << hb << "\n";

    if (ha == hb) {
        std::cerr << "ERREUR : les deux hashs sont identiques \n";
        return 1;
    } else {
        std::cout << "OK : deux entrées différentes -> deux hashs différents.\n";
    }

    // Test additionnel : même entrée, même paramètres -> même hash
    assert(ac_hash(a, rule, steps) == ha);

    return 0;
}
