#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <cassert>
#include <ctime>
#include <chrono>
#include <numeric>   // for std::accumulate
#include <bit>       // for std::popcount (C++20)
#include <openssl/sha.h>

//---------------------------------
// Helper Functions
//---------------------------------
static std::vector<int> string_to_bits(const std::string& s) {
    std::vector<int> bits;
    bits.reserve(s.size() * 8);
    for (unsigned char c : s)
        for (int i = 7; i >= 0; --i)
            bits.push_back((c >> i) & 1);
    return bits;
}

static std::vector<int> init_state_from_bits(const std::vector<int>& bits, size_t state_size = 256) {
    std::vector<int> state(state_size, 0);
    for (size_t i = 0; i < bits.size(); ++i)
        state[i % state_size] ^= (bits[i] & 1);
    uint64_t len = bits.size();
    for (size_t i = 0; i < 64 && i < state_size; ++i)
        state[i] ^= ((len >> i) & 1);
    return state;
}

static std::vector<int> evolve_once(const std::vector<int>& state, uint8_t rule8) {
    size_t n = state.size();
    std::vector<int> next(n, 0);
    for (size_t i = 0; i < n; ++i) {
        int left = state[(i + n - 1) % n];
        int self = state[i];
        int right = state[(i + 1) % n];
        int pattern = (left << 2) | (self << 1) | right;
        next[i] = (rule8 >> pattern) & 1;
    }
    return next;
}

static std::vector<int> evolve_steps(std::vector<int> state, uint8_t rule8, size_t steps) {
    for (size_t t = 0; t < steps; ++t)
        state = evolve_once(state, rule8);
    return state;
}

static std::string state_to_hex256(const std::vector<int>& state) {
    assert(state.size() == 256);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t byte_idx = 0; byte_idx < 32; ++byte_idx) {
        unsigned int byte = 0;
        for (int bit = 0; bit < 8; ++bit)
            byte = (byte << 1) | (state[byte_idx * 8 + bit] & 1);
        oss << std::setw(2) << (byte & 0xFF);
    }
    return oss.str();
}

std::string ac_hash(const std::string& input, uint32_t rule, size_t steps) {
    uint8_t rule8 = static_cast<uint8_t>(rule & 0xFF);
    std::vector<int> bits = string_to_bits(input);
    std::vector<int> state = init_state_from_bits(bits, 256);
    std::vector<int> final_state = evolve_steps(state, rule8, steps);
    return state_to_hex256(final_state);
}

//---------------------------------
// SHA256 Wrapper
//---------------------------------
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, (const unsigned char*)input.data(), input.size());
    SHA256_Final(hash, &sha256_ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::setw(2) << (int)hash[i];
    return oss.str();
}

//---------------------------------
// Popcount helper (for avalanche test)
//---------------------------------
int count_bit_diff(const std::string& h1, const std::string& h2) {
    int diff = 0;
    for (size_t i = 0; i < h1.size() && i < h2.size(); ++i) {
        uint8_t b1 = std::stoi(h1.substr(i, 1), nullptr, 16);
        uint8_t b2 = std::stoi(h2.substr(i, 1), nullptr, 16);
        diff += std::popcount(static_cast<unsigned int>(b1 ^ b2));
    }
    return diff;
}

//---------------------------------
// Avalanche Effect Test
//---------------------------------
void test_avalanche() {
    std::string msg = "blockchain test message";
    double total_diff = 0;
    int n_tests = 0;
    for (int bit = 0; bit < 8; ++bit) {
        std::string modified = msg;
        modified[0] ^= (1 << bit);
        std::string h1 = ac_hash(msg, 30, 128);
        std::string h2 = ac_hash(modified, 30, 128);
        int diff_bits = count_bit_diff(h1, h2);
        total_diff += diff_bits;
        n_tests++;
    }
    double avg_diff = total_diff / (n_tests * 256.0) * 100.0;
    std::cout << "\n[Avalanche Effect Test]\n";
    std::cout << "Average % of bits flipped: " << avg_diff << "%\n";
}

//---------------------------------
// Bit Distribution Test
//---------------------------------
void test_distribution() {
    std::string concat_hashes;
    for (int i = 0; i < 100; ++i)
        concat_hashes += ac_hash("data" + std::to_string(i), 30, 128);

    int ones = 0;
    for (char c : concat_hashes) {
        uint8_t nibble = std::stoi(std::string(1, c), nullptr, 16);
        ones += std::popcount(static_cast<unsigned int>(nibble));
    }
    int total_bits = static_cast<int>(concat_hashes.size()) * 4;
    double ratio = (ones * 100.0) / total_bits;
    std::cout << "\n[Bit Distribution Test]\n";
    std::cout << "Percentage of bits set to 1: " << ratio << "%\n";
    std::cout << (std::abs(ratio - 50.0) < 5.0 ? "[OK] Balanced distribution\n" : "[WARN] Not balanced\n");
}

//---------------------------------
// Rule Comparison Test
//---------------------------------
void test_rules() {
    std::vector<int> rules = { 30, 90, 110 };
    std::string input = "rule test";
    std::cout << "\n[Rule Comparison Test]\n";
    for (int rule : rules) {
        auto start = std::chrono::high_resolution_clock::now();
        std::string h = ac_hash(input, rule, 128);
        auto end = std::chrono::high_resolution_clock::now();
        double time = std::chrono::duration<double>(end - start).count();
        std::cout << "Rule " << rule << " -> hash: " << h.substr(0, 16)
            << "...  time: " << time << "s\n";
    }
}

//---------------------------------
// Main
//---------------------------------
int main() {
    std::cout << "=== Cellular Automata Hash Tests ===\n";
    test_avalanche();
    test_distribution();
    test_rules();
    std::cout << "\nAll tests completed.\n";
    return 0;
}
