#include <iostream>
#include <set>
int main() {
    std::set<int> unique_vals;
    unique_vals.insert(10);
    unique_vals.insert(20);
    unique_vals.insert(10);
    std::cout << "Size: " << unique_vals.size() << "\n";
    return 0;
}
