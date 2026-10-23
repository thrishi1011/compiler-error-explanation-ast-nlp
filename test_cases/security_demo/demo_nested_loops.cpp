#include <iostream>
#include <string>

void compute(std::string banner) {
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 10; ++j) {
            for (int k = 0; k < 10; ++k) {
                std::cout << banner << std::endl;
            }
        }
    }
}

int main() {
    compute("computing");
    return 0;
}
