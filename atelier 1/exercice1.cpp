#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h> 

using namespace std;

// Fonction de hashage SHA256
string sha256(const string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

// Calcul du Merkle Root
string merkleRoot(vector<string> transactions) {
    if (transactions.empty()) return "";

    while (transactions.size() > 1) {
        vector<string> newLevel;
        for (size_t i = 0; i < transactions.size(); i += 2) {
            string left = transactions[i];
            string right = (i + 1 < transactions.size()) ? transactions[i + 1] : left;
            newLevel.push_back(sha256(left + right));
        }
        transactions = newLevel;
    }
    return transactions[0];
}

int main() {
    vector<string> txs = {"A->B:10", "B->C:20", "C->D:30", "D->E:40"};
    cout << "Merkle Root: " << merkleRoot(txs) << endl;
    return 0;
}
