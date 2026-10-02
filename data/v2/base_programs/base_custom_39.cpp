#include <iostream>
int* get_first_element(int* arr) {
    return arr;
}
int main() {
    int nums[] = {7, 8, 9};
    int* p = get_first_element(nums);
    std::cout << "First: " << *p << "\n";
    return 0;
}
