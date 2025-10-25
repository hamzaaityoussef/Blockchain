#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <cassert>
#include <ctime>
#include <chrono>
#include <openssl/sha.h> // comment this if you don’t have OpenSSL yet

//---------------------------------
// AC_HASH FUNCTIONS
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
std::string ac_hash(const std::string& input, uint32_t rule, size_t steps) {
    uint8_t rule8 = static_cast<uint8_t>(rule & 0xFF);
    std::vector<int> bits = string_to_bits(input);
    std::vector<int> state = init_state_from_bits(bits, 256);
    std::vector<int> final_state = evolve_steps(state, rule8, steps);
    return state_to_hex256(final_state);
}

//---------------------------------
// SHA256 WRAPPER
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
// BLOCKCHAIN STRUCTS
//---------------------------------
enum class HashMode { SHA256, AC_HASH };
struct Block {
    uint64_t index;
    std::string prev_hash;
    uint64_t timestamp;
    std::string data;
    uint64_t nonce;
    std::string hash;
};
struct AcParams { uint32_t rule = 30; size_t steps = 128; };

static std::string block_header_string(const Block& b) {
    std::ostringstream oss;
    oss << b.index << '|' << b.prev_hash << '|' << b.timestamp << '|' << b.data << '|' << b.nonce;
    return oss.str();
}
static std::string compute_block_hash(const Block& b, HashMode mode, const AcParams& acp) {
    std::string header = block_header_string(b);
    return (mode == HashMode::SHA256) ? sha256(header) : ac_hash(header, acp.rule, acp.steps);
}
static bool meets_difficulty(const std::string& hexhash, unsigned difficulty) {
    for (unsigned i = 0; i < difficulty; ++i)
        if (i >= hexhash.size() || hexhash[i] != '0') return false;
    return true;
}

static std::pair<uint64_t, double> mine_block(Block& block, HashMode mode, const AcParams& acp, unsigned difficulty) {
    using clock = std::chrono::high_resolution_clock;
    auto start = clock::now();
    uint64_t iterations = 0;
    while (true) {
        block.timestamp = std::time(nullptr);
        std::string h = compute_block_hash(block, mode, acp);
        if (meets_difficulty(h, difficulty)) {
            block.hash = h;
            break;
        }
        ++block.nonce;
        ++iterations;
    }
    auto end = clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    return { iterations, elapsed };
}

//---------------------------------
// COMPARISON EXPERIMENT
//---------------------------------
int main() {
    const unsigned DIFFICULTY = 2;
    const int N_BLOCKS = 10;

    AcParams acp{ 30, 128 }; // rule 30, 128 steps

    double total_time_sha = 0, total_time_ac = 0;
    double total_iter_sha = 0, total_iter_ac = 0;

    std::string prev = "0";

    std::cout << "=== Mining " << N_BLOCKS << " blocks (difficulty " << DIFFICULTY << ") ===\n\n";

    // --- SHA256 ---
    std::cout << "[SHA256]\n";
    for (int i = 0; i < N_BLOCKS; ++i) {
        Block b{ i, prev, (uint64_t)std::time(nullptr), "data", 0, "" };
        auto [iters, t] = mine_block(b, HashMode::SHA256, acp, DIFFICULTY);
        std::cout << "Block " << i << ": time=" << t << "s, iters=" << iters << "\n";
        total_time_sha += t; total_iter_sha += iters; prev = b.hash;
    }

    // --- AC_HASH ---
    prev = "0";
    std::cout << "\n[AC_HASH]\n";
    for (int i = 0; i < N_BLOCKS; ++i) {
        Block b{ i, prev, (uint64_t)std::time(nullptr), "data", 0, "" };
        auto [iters, t] = mine_block(b, HashMode::AC_HASH, acp, DIFFICULTY);
        std::cout << "Block " << i << ": time=" << t << "s, iters=" << iters << "\n";
        total_time_ac += t; total_iter_ac += iters; prev = b.hash;
    }

    std::cout << "\n=== Averages ===\n";
    std::cout << std::setw(10) << "Mode" << std::setw(20) << "Avg Time (s)" << std::setw(25) << "Avg Iterations\n";
    std::cout << std::setw(10) << "SHA256" << std::setw(20) << total_time_sha / N_BLOCKS
        << std::setw(25) << total_iter_sha / N_BLOCKS << "\n";
    std::cout << std::setw(10) << "AC_HASH" << std::setw(20) << total_time_ac / N_BLOCKS
        << std::setw(25) << total_iter_ac / N_BLOCKS << "\n";

    return 0;
}
