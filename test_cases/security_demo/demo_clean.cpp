#include <iostream>
#include <vector>

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    int sum = 0;
    for (const auto& n : numbers) {
        sum += n;
    }
    std::cout << "Sum: " << sum << '\n';
    return 0;
}
