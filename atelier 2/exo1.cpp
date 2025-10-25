#include <iostream>
#include <vector>
#include <bitset>

using namespace std;

// Taille de l'automate
const int N = 31;

// Inistialisation
vector<int> init_state(const vector<int>& init_bits) {
    vector<int> state(N, 0);
    int offset = (N - init_bits.size()) / 2;
    for (size_t i = 0; i < init_bits.size(); ++i) {
        state[offset + i] = init_bits[i];
    }
    return state;
}

// afficher l etat
void print_state(const vector<int>& state) {
    for (int bit : state) {
        cout << (bit ? '#' : ' ');

    }
    cout << endl;
}

// evolution selon regle
vector<int> evolve(const vector<int>& state, int rule_number) {
    vector<int> new_state(state.size(), 0);

    // Convertir la règle en binaire sur 8 bits
    bitset<8> rule(rule_number);

    for (size_t i = 0; i < state.size(); ++i) {
        int left  = (i == 0) ? 0 : state[i - 1];
        int self  = state[i];
        int right = (i == state.size() - 1) ? 0 : state[i + 1];

        // Mot de 3 bits (voisin gauche, centre, voisin droit)
        int pattern = (left << 2) | (self << 1) | right;

        // Le bit correspondant dans la règle
        new_state[i] = rule[pattern];
    }

    return new_state;
}

// programme principal
int main() {
    // Exemple : une seule cellule active au centre
    vector<int> init = {1};

    // Choisir la règle : 30, 90 ou 110
    int rule_number = 30;

    vector<int> state = init_state(init);

    cout << "Automate cellulaire 1D (Rule " << rule_number << ")\n";
    print_state(state);

    // Faire évoluer pendant quelques étapes
    for (int t = 0; t < 15; ++t) {
        state = evolve(state, rule_number);
        print_state(state);
    }

    return 0;
}