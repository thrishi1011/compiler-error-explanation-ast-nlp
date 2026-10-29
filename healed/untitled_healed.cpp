#include <iostream>
#include <vector>

bool hasDuplicates(std::vector<int> list) {
    // Nested loop comparing every pair: O(n^2)
    for (size_t i = 0; i < list.size(); i++) {
        for (size_t j = i + 1; j < list.size(); j++) {
            if (list[i] == list[j]) {
                return true;
            }
        }
    }
    return false;
}

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5, 2};
    if (hasDuplicates(numbers)) {
        std::cout << "Duplicates found!" << std::endl;
    }
    return 0;
}