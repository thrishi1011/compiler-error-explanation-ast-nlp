#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>
using namespace std;

void searchPrefixMatches(const vector<string>& words, const string& query) {
    unordered_set<string> seen;
    for (const auto& w : words) {
        if (w.empty()) continue;
        if (seen.find(w) != seen.end()) {
            cout << "Duplicate word detected: " << w << endl;
        } else {
            seen.insert(w);
        }
    }
}

int main() {
    vector<string> dict = {"apple", "banana", "apple", "cherry"};
    searchPrefixMatches(dict, "app");
    return 0;
}