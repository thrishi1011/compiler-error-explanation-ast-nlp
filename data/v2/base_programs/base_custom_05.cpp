#include <iostream>
template <typename T, typename U>
auto add_values(T a, U b) -> decltype(a + b) {
    return a + b;
}
int main() {
    std::cout << add_values(10, 2.5) << "\n";
    std::cout << add_values(3.14, 2) << "\n";
    return 0;
}
