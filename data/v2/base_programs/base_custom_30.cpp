#include <iostream>
#include <vector>
#include <algorithm>
int main() {
    std::vector<int> v = {1, 2, 3, 4, 5};
    int factor = 10;
    std::for_each(v.begin(), v.end(), [factor](int n) {
        std::cout << (n * factor) << " ";
    });
    std::cout << "\n";
    return 0;
}
