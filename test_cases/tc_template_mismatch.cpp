// Test: Template type error
// Expected: error: no matching function for call / template deduction failure

#include <iostream>
#include <vector>
using namespace std;

template <typename T>
T add(T a, T b) {
    return a + b;
}

int main() {
    cout << add(3, 4) << endl;          // OK: both int
    cout << add(3.14, 2.71) << endl;    // OK: both double
    cout << add(3, 2.71) << endl;       // ERROR: mixing int and double
    return 0;
}
