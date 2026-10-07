// Test: Variable shadowing and scope confusion
// Expected: warning or confusing output due to variable shadowing

#include <iostream>
using namespace std;

int x = 100;   // global x

void doSomething() {
    int x = 200;          // shadows global x
    cout << "Inside doSomething: x = " << x << endl;  // prints 200
}

int main() {
    cout << "Global x = " << x << endl;    // 100
    {
        int x = 300;                        // shadows global x in this block
        cout << "Block x = " << x << endl; // 300
    }
    cout << "Global x again = " << x << endl;  // 100 (block x gone)
    doSomething();
    int x = 400;          // ERROR: redeclaration of x in same scope as global
    return 0;
}
