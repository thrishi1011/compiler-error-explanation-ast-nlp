#include <iostream>
void print_banner(const char* title) {
    std::cout << "=== " << title << " ===\n";
}
int main() {
    print_banner("Test");
    return 0;
}
