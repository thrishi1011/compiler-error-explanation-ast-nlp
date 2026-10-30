#include <iostream>
#include <vector>
#include <string>

using namespace std;

// COMPLEX DSA PROBLEM: Subarray Duplicate Detection & Exponential Subset Search
// Bottlenecks present:
// 1. Pass-by-value of large vector<string> (causes costly deep copies)
// 2. O(n^2) nested loop duplicate search instead of O(1) unordered_set
// 3. O(2^n) unmemoized recursive subset sum search
// 4. std::endl buffer flushes inside loop

bool recursiveSubsetSum(int idx, int currentSum, int target, vector<int> nums) {
    if (currentSum == target) return true;
    if (idx >= (int)nums.size() || currentSum > target) return false;
    
    // O(2^n) branching without caching/memoization
    bool include = recursiveSubsetSum(idx + 1, currentSum + nums[idx], target, nums);
    bool exclude = recursiveSubsetSum(idx + 1, currentSum, target, nums);
    return include || exclude;
}

void findDuplicateKeywords(vector<string> keywords) {
    cout << "Scanning for duplicate keywords..." << endl;
    for (int i = 0; i < (int)keywords.size(); i++) {
        for (int j = i + 1; j < (int)keywords.size(); j++) {
            if (keywords[i] == keywords[j]) {
                cout << "Duplicate keyword found: " << keywords[i] << endl;
            }
        }
    }
}

int main() {
    cout << "=== COMPLEX DSA OPTIMIZATION DEMO ===" << endl;
    
    vector<string> wordList = {
        "compiler", "optimizer", "ast", "nlp", "compiler",
        "security", "tokens", "parser", "ast", "execution"
    };
    
    findDuplicateKeywords(wordList);
    
    vector<int> numbers = {3, 34, 4, 12, 5, 2};
    int target = 9;
    
    cout << "Searching subset sum target " << target << "..." << endl;
    if (recursiveSubsetSum(0, 0, target, numbers)) {
        cout << "Found subset with target sum " << target << endl;
    } else {
        cout << "No subset sum found." << endl;
    }
    
    cout << "Completed successfully!" << endl;
    return 0;
}
