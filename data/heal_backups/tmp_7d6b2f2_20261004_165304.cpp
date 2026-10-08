// Test: Pure auto-heal candidates (missing semicolons only)
// All errors in this file are things the auto-healer CAN fix

#include <iostream>
using namespace std;

int main() {
    int a = 10       // missing semicolon — line 8
    int b = 20       // missing semicolon — line 9
    int c = a + b    // missing semicolon — line 10
    cout << "Sum: " << c << endl
    return 0
}
