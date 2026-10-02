#include <iostream>
#include <vector>
#include <algorithm>
bool descending(int a, int b) {
    return a > b;
}
int main() {
    std::vector<int> nums = {3, 1, 4, 1, 5};
    std::sort(nums.begin(), nums.end(), descending);
    for (int x : nums) std::cout << x << " ";
    std::cout << "\n";
    return 0;
}
