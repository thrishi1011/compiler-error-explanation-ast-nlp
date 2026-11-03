#include <iostream>
using namespace std;

void foo(int x) { (void)x; }

int main() {
    foo(1);
    return 0;
}