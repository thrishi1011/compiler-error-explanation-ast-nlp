#include <iostream>
int multiply(int a, int b);
void greet(const char* name);

int main() {
    greet("User");
    std::cout << "Product: " << multiply(4, 5) << "\n";
    return 0;
}

int multiply(int a, int b) {
    return a * b;
}

void greet(const char* name) {
    std::cout << "Hello, " << name << "\n";
}
