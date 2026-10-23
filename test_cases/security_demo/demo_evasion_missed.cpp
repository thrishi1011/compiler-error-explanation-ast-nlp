#include <cstdlib>

void test() {
    auto f = &::system;
}

int main() {
    test();
    return 0;
}
