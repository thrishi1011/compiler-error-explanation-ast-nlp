#include <cstdio>

void free_twice() {
    int* ptr = new int(100);
    delete ptr;
    delete ptr;
}

int main() {
    free_twice();
    return 0;
}
