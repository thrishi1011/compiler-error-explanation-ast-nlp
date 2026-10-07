// Test: Multiple errors in one file
// Tests: missing semicolon + undeclared variable + wrong return type

#include <iostream>
using namespace std;

int sum(int a, int b) {
    return a + b
}

int main() {
    int result = sum(10, 20)
    cout << result << endl;
    cout << z << endl;         // z was never declared
    return "done";             // returning string from int function
}
