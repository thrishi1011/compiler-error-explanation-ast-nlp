// Test: Variable shadowing and scope confusion
// Expected: warning or confusing output due to variable shadowing

#include <iostream>
using namespace std;

int x = 100;   // global x

void doSomething() {
    int x_local = 200;          // shadows global x
    cout << "Inside doSomething: x_local = " << x_local << endl;  // prints 200
}

int main() {
    cout << "Global x = " << x << endl;    // 100
    {
        int local_x = 300;                        // shadows global x in this block
        cout << "Block local_x = " << local_x << endl; // 300
    }
    cout << "Global x again = " << x << endl;  // 100 (block x gone)
    doSomething();
    int x_22 = 400;          // ERROR: redeclaration of x in same scope as global
    (void)x_22;
    return 0;
}
