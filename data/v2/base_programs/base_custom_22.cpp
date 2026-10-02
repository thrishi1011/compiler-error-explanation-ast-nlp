#include <iostream>
#include <array>
int main() {
    std::array<int, 4> arr = {1, 2, 3, 4};
    int sum = 0;
    for (size_t i = 0; i < arr.size(); i++) {
        sum += arr[i];
    }
    std::cout << "Sum: " << sum << "\n";
    return 0;
}
