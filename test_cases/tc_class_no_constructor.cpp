// Test: Class with no matching constructor
// Expected: error: no matching function for call to 'Dog::Dog(int)'

#include <iostream>
using namespace std;

class Dog {
public:
    string name;
    Dog(string n) { name = n; }
};

int main() {
    Dog d(42);          // ERROR: passing int, constructor expects string
    cout << d.name << endl;
    return 0;
}
