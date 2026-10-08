#include <iostream>
int main() {
    int* ptr = new int(42);
    std::cout << "Value: " << *ptr << "\n";
    delete ptr;
    ptr = nullptr;
    return 0;
}
