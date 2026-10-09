#include <iostream>
using namespace std;

void print(int x);

int main() {
    print("mismatched_type");
    return 0;
}

void print(int x) {
    cout << x << endl;
}
