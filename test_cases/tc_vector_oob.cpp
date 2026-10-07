// Test: Vector out-of-bounds access
// Expected: compiles OK; crashes at runtime with index out of bounds

#include <iostream>
#include <vector>
using namespace std;

int main() {
    vector<int> nums = {10, 20, 30};

    // Safe access
    cout << "Element 0: " << nums[0] << endl;

    // OUT OF BOUNDS — vector has 3 elements, index 5 is invalid
    cout << "Element 5: " << nums[5] << endl;   // undefined behavior
    cout << "Element at(): " << nums.at(5) << endl;  // throws std::out_of_range

    return 0;
}
