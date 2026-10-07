#include <iostream>
#include <vector>
#include <algorithm>
int main() {
    std::vector<int> sorted_arr = {10, 20, 30, 40, 50};
    bool found = std::binary_search(sorted_arr.begin(), sorted_arr.end(), 30);
    std::cout << "Found: " << (found ? "yes" : "no") << "\n";
    return 0;
}
