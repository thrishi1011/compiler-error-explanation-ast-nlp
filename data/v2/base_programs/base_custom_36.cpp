#include <iostream>
int main() {
    int arr[] = {10, 20, 30, 40};
    int* p = arr;
    std::cout << *p << " ";
    p++;
    std::cout << *p << " ";
    p += 2;
    std::cout << *p << "\n";
    return 0;
}
