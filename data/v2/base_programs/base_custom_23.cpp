#include <iostream>
int print_value(int x) { return x * 2; }
double print_value(double x) { return x * 2.0; }
int main() {
    std::cout << print_value(5) << "\n";
    std::cout << print_value(4.5) << "\n";
    return 0;
}
