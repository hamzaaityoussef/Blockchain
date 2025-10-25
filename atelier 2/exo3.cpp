// blockchain_ac_hash.cpp
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cassert>
#include <ctime>
// #include <openssl/sha.h> // pour sha256 wrapper

// -----------------------------
// --- AC_HASH (depuis précédemment)
// -----------------------------
static std::vector<int> string_to_bits(const std::string& s) {
    std::vector<int> bits;
    bits.reserve(s.size() * 8);
    for (unsigned char c : s) {
        for (int i = 7; i >= 0; --i) bits.push_back((c >> i) & 1);
    }
    return bits;
}
static std::vector<int> init_state_from_bits(const std::vector<int>& bits, size_t state_size = 256) {
    std::vector<int> state(state_size, 0);
    for (size_t i = 0; i < bits.size(); ++i) state[i % state_size] ^= (bits[i] & 1);
    uint64_t len = bits.size();
    for (size_t i = 0; i < 64 && i < state_size; ++i) state[i] ^= ((len >> i) & 1);
    return state;
}
static std::vector<int> evolve_once(const std::vector<int>& state, uint8_t rule8) {
    size_t n = state.size();
    std::vector<int> next(n, 0);
    for (size_t i = 0; i < n; ++i) {
        int left = state[(i + n - 1) % n];
        int self = state[i];
        int right = state[(i + 1) % n];
        int pattern = (left << 2) | (self << 1) | right; // 0..7
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
        for (int bit = 0; bit < 8; ++bit) {
            byte = (byte << 1) | (state[byte_idx * 8 + bit] & 1);
        }
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
// -----------------------------
// --- SHA256 wrapper (OpenSSL)
// -----------------------------
std::string sha256(const std::string& input) {
   /* unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, (const unsigned char*)input.data(), input.size());
    SHA256_Final(hash, &sha256_ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; ++i) oss << std::setw(2) << (int)hash[i];
    return oss.str();*/
    return "dummyhash";
}

// -----------------------------
// --- Blockchain minimal
// -----------------------------
enum class HashMode { SHA256, AC_HASH };

struct Block {
    uint64_t index;
    std::string prev_hash;
    uint64_t timestamp;
    std::string data;
    uint64_t nonce;
    std::string hash; // hash du bloc (hex)

    Block(uint64_t idx = 0, const std::string& prev = "", const std::string& d = "")
        : index(idx), prev_hash(prev), timestamp(std::time(nullptr)), data(d), nonce(0), hash("") {
    }
};

// paramètres du hachage AC
struct AcParams {
    uint32_t rule = 30;   // rule wolfram
    size_t steps = 256;   // générations
};

// concatène les champs pertinents pour le hachage
static std::string block_header_string(const Block& b) {
    std::ostringstream oss;
    oss << b.index << '|' << b.prev_hash << '|' << b.timestamp << '|' << b.data << '|' << b.nonce;
    return oss.str();
}

// calcule le hash selon le mode choisi
static std::string compute_block_hash(const Block& b, HashMode mode, const AcParams& acp) {
    std::string header = block_header_string(b);
    if (mode == HashMode::SHA256) {
        return sha256(header);
    }
    else {
        // AC_HASH utilise header comme entrée (deterministic)
        return ac_hash(header, acp.rule, acp.steps);
    }
}

// vérifie si hash commence par difficulty zéros hex (ex: difficulty=3 -> "000")
static bool meets_difficulty(const std::string& hexhash, unsigned difficulty) {
    for (unsigned i = 0; i < difficulty; ++i) {
        if (i >= hexhash.size()) return false;
        if (hexhash[i] != '0') return false;
    }
    return true;
}

// minage : modifie nonce pour trouver un hash valide et met à jour block.hash
static void mine_block(Block& block, HashMode mode, const AcParams& acp, unsigned difficulty, uint64_t max_iters = 10000000) {
    block.nonce = 0;
    for (uint64_t it = 0; it < max_iters; ++it) {
        block.timestamp = std::time(nullptr); // optionnel: inclure timestamp change à chaque it
        std::string h = compute_block_hash(block, mode, acp);
        if (meets_difficulty(h, difficulty)) {
            block.hash = h;
            std::cout << "Mined in " << it + 1 << " iterations. Hash=" << h << "\n";
            return;
        }
        ++block.nonce;
    }
    throw std::runtime_error("Mining failed: max iterations reached");
}

// validation : recalculer hash et vérifier égalité + difficulty + prev hash correctness optionally
static bool validate_block(const Block& block, HashMode mode, const AcParams& acp, unsigned difficulty) {
    std::string expected = compute_block_hash(block, mode, acp);
    if (expected != block.hash) {
        std::cerr << "Invalid block: hash mismatch\n";
        return false;
    }
    if (!meets_difficulty(block.hash, difficulty)) {
        std::cerr << "Invalid block: difficulty not met\n";
        return false;
    }
    return true;
}

// -----------------------------
// --- Petit test / démonstration
// -----------------------------
int main() {
    try {
        // Choix du mode (changer ici pour tester SHA256 / AC_HASH)
        HashMode mode = HashMode::AC_HASH;
        AcParams acparams;
        acparams.rule = 30;
        acparams.steps = 256;

        unsigned difficulty = 3; // nombre de '0' hex en tête (ajuste si trop difficile/rapide)

        // créer genesis
        Block genesis(0, "0", "Genesis");
        mine_block(genesis, mode, acparams, difficulty);
        assert(validate_block(genesis, mode, acparams, difficulty));
        std::cout << "Genesis valid.\n";

        // nouveau bloc
        Block b1(1, genesis.hash, "Alice->Bob:10");
        mine_block(b1, mode, acparams, difficulty);
        bool ok = validate_block(b1, mode, acparams, difficulty);
        std::cout << "Block 1 valid = " << (ok ? "TRUE" : "FALSE") << "\n";

        // vérifier que changement de donnée modifie le hash (détection de falsification)
        Block tampered = b1;
        tampered.data = "Alice->Bob:1000"; // modification frauduleuse
        bool ok2 = validate_block(tampered, mode, acparams, difficulty);
        std::cout << "Tampered block valid = " << (ok2 ? "TRUE (BAD)" : "FALSE (expected)") << "\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}