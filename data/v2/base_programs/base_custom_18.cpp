#include <iostream>
int main() {
    int val1 = 10;
    int val2 = 20;
    const int* ptr_to_const = &val1;
    ptr_to_const = &val2;
    int* const const_ptr = &val1;
    *const_ptr = 30;
    std::cout << *ptr_to_const << " " << *const_ptr << "\n";
    return 0;
}
