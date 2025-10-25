#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <map>
#include <openssl/sha.h>

using namespace std;

//  SHA256 
string sha256(const string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

//  Proof of Work 
string proofOfWork(string previousHash, string data, int difficulty) {
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

    cout << " Proof of Work validé !\n";
    cout << "Hash: " << hash << "\n";
    cout << "Temps de minage: " << duration.count() << " s\n\n";

    return hash;
}

//  Proof of Stake 
string selectValidator(map<string, int> &stakes) {
    int total = 0;
    for (auto &p : stakes) total += p.second;

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, total - 1);

    int r = dis(gen);
    for (auto &p : stakes) {
        if (r < p.second) return p.first;
        r -= p.second;
    }
    return "";
}

string proofOfStake(string previousHash, string data, map<string, int> &stakes) {
    auto start = chrono::high_resolution_clock::now();

    string validator = selectValidator(stakes);
    string blockData = previousHash + data + validator;
    string hash = sha256(blockData);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;

    cout << " Proof of Stake validé !\n";
    cout << "Validateur choisi : " << validator << "\n";
    cout << "Hash: " << hash << "\n";
    cout << "Temps de validation: " << duration.count() << " s\n\n";

    return hash;
}

//  MAIN 
int main() {
    string previousHash = "0000abcd1234";
    string data = "Transaction: Alice -> Bob : 25 coins";

    //  Proof of Work 
    cout << " TEST PROOF OF WORK \n";
    proofOfWork(previousHash, data, 4);

    //  Proof of Stake 
    cout << " TEST PROOF OF STAKE \n";
    map<string, int> stakes = {
        {"Alice", 50},
        {"Bob", 30},
        {"Charlie", 20}
    };
    proofOfStake(previousHash, data, stakes);

    return 0;
}

