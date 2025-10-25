#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <random>
#include <cassert>
#include <cmath>
#include <sstream>   // pour std::ostringstream
#include <iomanip>   // pour std::setw et std::setfill


// --- AC_HASH FUNCTIONS (copie depuis ton exo4.cpp) ---
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
    for (size_t t = 0; t < steps; ++t) state = evolve_once(state, rule8);
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

std::vector<int> ac_hash_state(const std::string& input, uint32_t rule = 30, size_t steps = 128) {
    uint8_t rule8 = static_cast<uint8_t>(rule & 0xFF);
    std::vector<int> bits = string_to_bits(input);
    std::vector<int> state = init_state_from_bits(bits, 256);
    return evolve_steps(state, rule8, steps);
}

// --- UTILITY FUNCTIONS ---
double bit_diff_percent(const std::vector<int>& a, const std::vector<int>& b) {
    assert(a.size() == b.size());
    size_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i] != b[i]) ++diff;
    return 100.0 * diff / a.size();
}

std::string flip_one_bit(const std::string& msg, size_t bit_pos) {
    std::vector<int> bits = string_to_bits(msg);
    if (bit_pos >= bits.size()) return msg;
    bits[bit_pos] ^= 1;

    // reconvert bits to string
    std::string res;
    size_t n = bits.size();
    for (size_t i = 0; i < n; i += 8) {
        unsigned char byte = 0;
        for (size_t j = 0; j < 8 && (i + j) < n; ++j)
            byte = (byte << 1) | bits[i + j];
        res.push_back(byte);
    }
    return res;
}

// --- RANDOM MESSAGE GENERATOR ---
std::string random_message(size_t min_len = 1, size_t max_len = 64) {
    static std::mt19937 rng(42);
    std::uniform_int_distribution<int> len_dist(min_len, max_len);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    size_t ln = len_dist(rng);
    std::string msg;
    msg.reserve(ln);
    for (size_t i = 0; i < ln; ++i)
        msg.push_back(static_cast<char>(byte_dist(rng)));
    return msg;
}

// --- MAIN FUNCTION ---
int main() {
    const int TRIALS = 1000;
    const uint32_t RULE = 30;
    const size_t STEPS = 128;

    double total_percent = 0.0;

    for (int t = 0; t < TRIALS; ++t) {
        std::string msg = random_message();
        std::vector<int> bits = string_to_bits(msg);
        if (bits.empty()) continue;

        std::uniform_int_distribution<size_t> bit_dist(0, bits.size() - 1);
        size_t flip_pos = bit_dist(std::mt19937(t)); // deterministic per trial
        std::string msg2 = flip_one_bit(msg, flip_pos);

        std::vector<int> hash1 = ac_hash_state(msg, RULE, STEPS);
        std::vector<int> hash2 = ac_hash_state(msg2, RULE, STEPS);

        double pct = bit_diff_percent(hash1, hash2);
        total_percent += pct;
    }

    double avg_pct = total_percent / TRIALS;
    std::cout << "AC_HASH Avalanche test over " << TRIALS << " trials:\n";
    std::cout << "Average differing bits percent: " << std::fixed << std::setprecision(2) << avg_pct << "%\n";
}
