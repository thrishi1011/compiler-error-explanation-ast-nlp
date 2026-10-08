#include <iostream>
int compute_tax(const int income) {
    const double tax_rate = 0.15;
    return static_cast<int>(income * tax_rate);
}
int main() {
    const int salary = 50000;
    int tax = compute_tax(salary);
    std::cout << "Tax: " << tax << "\n";
    return 0;
}
