#include <iostream>
int main() {
    unsigned int flags = 0x05;
    unsigned int mask = 0x01;
    bool is_set = (flags & mask) != 0;
    std::cout << "Set: " << (is_set ? "yes" : "no") << "\n";
    return 0;
}
