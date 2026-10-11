// Test: Class with no matching constructor
// Expected: error: no matching function for call to 'Dog::Dog(int)'

#include <iostream>
#include <string>
using namespace std;

class Dog {
public:
    string name;
    Dog(string n) { name = n; }
};

int main() {
    Dog d;          // ERROR: passing int, constructor expects string
    cout << d.name << endl;
    return 0;
}
