#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <openssl/sha.h>

using namespace std;

// Fonction SHA256
string sha256(const string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

// Fonction Proof of Work
string mineBlock(string previousHash, string data, int difficulty) {
    string prefix(difficulty, '0');
    int nonce = 0;
    string hash;
    auto start = chrono::high_resolution_clock::now();

    do {
        hash = sha256(previousHash + data + to_string(nonce));
        nonce++;
    } while (hash.substr(0, difficulty) != prefix);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;

    cout << "✅ Block mined!\n";
    cout << "Difficulty: " << difficulty << endl;
    cout << "Nonce: " << nonce << endl;
    cout << "Hash: " << hash << endl;
    cout << "Mining time: " << duration.count() << " seconds\n\n";

    return hash;
}

int main() {
    string previousHash = "0000abcd1234";
    string data = "Transaction: Youssef -> Alice : 50 coins";

    for (int diff = 2; diff <= 5; ++diff) {
        cout << "⛏️  Mining block with difficulty " << diff << " ...\n";
        mineBlock(previousHash, data, diff);
    }

    return 0;
}
