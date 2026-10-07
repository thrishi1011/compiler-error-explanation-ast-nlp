// Test: Integer overflow
// Expected: compiles OK; runtime behavior is undefined / wraps around

#include <iostream>
#include <climits>
using namespace std;

int main() {
    int x = INT_MAX;                     // 2,147,483,647
    cout << "Max int: " << x << endl;
    x = x + 1;                          // OVERFLOW: wraps to negative
    cout << "After +1: " << x << endl;  // Prints -2147483648 on most systems
    
    unsigned int u = 0;
    u = u - 1;                          // UNDERFLOW: wraps to UINT_MAX
    cout << "Unsigned underflow: " << u << endl;
    return 0;
}
