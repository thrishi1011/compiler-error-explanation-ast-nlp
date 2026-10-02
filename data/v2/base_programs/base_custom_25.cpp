#include <iostream>
void increment_val(int val) { val++; }
void increment_ref(int& val) { val++; }
int main() {
    int x = 10;
    increment_val(x);
    std::cout << "After val: " << x << "\n";
    increment_ref(x);
    std::cout << "After ref: " << x << "\n";
    return 0;
}
