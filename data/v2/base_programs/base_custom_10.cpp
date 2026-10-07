#include <iostream>
namespace math_utils {
    namespace algebra {
        int square(int x) { return x * x; }
        int cube(int x) { return x * x * x; }
    }
}
int main() {
    using namespace math_utils::algebra;
    std::cout << "Square: " << square(5) << "\n";
    std::cout << "Cube: " << cube(3) << "\n";
    return 0;
}
