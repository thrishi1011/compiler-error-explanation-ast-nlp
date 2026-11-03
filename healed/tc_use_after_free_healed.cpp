// Test: Dangling pointer / use after free (security)
// Expected: compiles OK, security analyzer should flag this

#include <iostream>
using namespace std;

int main() {
    int* p = new int(99);
    cout << *p << endl;
    cout << *p << endl;        // ERROR: use after free — undefined behavior
    delete p;                  // p is freed here
    p = nullptr;           // Should come BEFORE the second cout
    return 0;
}