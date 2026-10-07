// Test: Missing return statement in non-void function
// Expected: warning: control reaches end of non-void function

#include <iostream>
using namespace std;

int absolute(int n) {
    if (n >= 0) {
        return n;
    }
    // Missing: return -n; for the negative case
}

int main() {
    cout << absolute(5) << endl;
    cout << absolute(-3) << endl;  // undefined behavior
    return 0;
}
