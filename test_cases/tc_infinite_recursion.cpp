// Test: Infinite recursion / stack overflow (runtime)
// Expected: compiles OK, but crashes with segfault at runtime

#include <iostream>
using namespace std;

int factorial(int n) {
    return n * factorial(n - 1);   // Missing base case: infinite recursion
}

int main() {
    cout << factorial(5) << endl;
    return 0;
}
