#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <map>
#include <random>
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

//  Transaction 
struct Transaction {
    string sender;
    string receiver;
    double amount;
};

//  Merkle Tree 
string computeMerkleRoot(vector<Transaction> &txs) {
    if (txs.empty()) return "";
    vector<string> hashes;
    for (auto &t : txs)
        hashes.push_back(sha256(t.sender + t.receiver + to_string(t.amount)));

    while (hashes.size() > 1) {
        vector<string> newLevel;
        for (size_t i = 0; i < hashes.size(); i += 2) {
            string left = hashes[i];
            string right = (i + 1 < hashes.size()) ? hashes[i + 1] : left;
            newLevel.push_back(sha256(left + right));
        }
        hashes = newLevel;
    }
    return hashes[0];
}

//  Proof of Work 
string mineBlock(string previousHash, string merkleRoot, int difficulty) {
    string prefix(difficulty, '0');
    int nonce = 0;
    string hash;
    auto start = chrono::high_resolution_clock::now();

    do {
        hash = sha256(previousHash + merkleRoot + to_string(nonce));
        nonce++;
    } while (hash.substr(0, difficulty) != prefix);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << " Block miné (PoW) en " << duration.count() << "s avec nonce=" << nonce << endl;
    return hash;
}

//  Proof of Stake 
string selectValidator(map<string,int> &stakes) {
    int total = 0;
    for (auto &p : stakes) total += p.second;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, total-1);
    int r = dis(gen);
    for (auto &p : stakes) {
        if (r < p.second) return p.first;
        r -= p.second;
    }
    return "";
}

string validateBlockPOS(string previousHash, string merkleRoot, map<string,int> &stakes) {
    auto start = chrono::high_resolution_clock::now();
    string validator = selectValidator(stakes);
    string hash = sha256(previousHash + merkleRoot + validator);
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << " Block validé (PoS) par " << validator << " en " << duration.count() << "s" << endl;
    return hash;
}

//  Block 
class Block {
public:
    int index;
    string previousHash;
    string hash;
    string merkleRoot;
    vector<Transaction> transactions;
    time_t timestamp;

    Block(int idx, string prev, vector<Transaction> txs)
        : index(idx), previousHash(prev), transactions(txs) {
        timestamp = time(nullptr);
        merkleRoot = computeMerkleRoot(transactions);
    }
};

//  Blockchain 
class Blockchain {
public:
    vector<Block> chain;

    Blockchain() {
        vector<Transaction> genesisTx = {{"System","Genesis",0}};
        chain.push_back(Block(0,"0",genesisTx));
        chain[0].hash = sha256("Genesis Block");
    }

    Block createBlock(vector<Transaction> txs) {
        return Block(chain.size(), chain.back().hash, txs);
    }

    void addBlockPOW(vector<Transaction> txs, int difficulty) {
        Block newBlock = createBlock(txs);
        newBlock.hash = mineBlock(newBlock.previousHash, newBlock.merkleRoot, difficulty);
        chain.push_back(newBlock);
    }

    void addBlockPOS(vector<Transaction> txs, map<string,int> &stakes) {
        Block newBlock = createBlock(txs);
        newBlock.hash = validateBlockPOS(newBlock.previousHash, newBlock.merkleRoot, stakes);
        chain.push_back(newBlock);
    }

    void showChain() {
        cout << "\n BLOCKCHAIN \n";
        for (auto &b : chain) {
            cout << "Block #" << b.index << "\n"
                 << "PrevHash: " << b.previousHash.substr(0,16) << "...\n"
                 << "Hash: " << b.hash.substr(0,16) << "...\n"
                 << "MerkleRoot: " << b.merkleRoot.substr(0,16) << "...\n"
                 << "Timestamp: " << ctime(&b.timestamp)
                 << "--\n";
        }
    }
};

//  MAIN 
int main() {
    Blockchain bc;

    // Transactions exemples
    vector<Transaction> tx1 = {{"Alice","Bob",10},{"Bob","Charlie",5}};
    vector<Transaction> tx2 = {{"Youssef","Ali",15},{"Ali","Sara",8}};
    map<string,int> stakes = {{"Alice",50},{"Bob",30},{"Charlie",20}};

    cout << "\n Ajout de blocs avec Proof of Work \n";
    bc.addBlockPOW(tx1, 4);

    cout << "\n Ajout de blocs avec Proof of Stake \n";
    bc.addBlockPOS(tx2, stakes);

    bc.showChain();
    return 0;
}

