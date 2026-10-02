#include <iostream>
#include <deque>
int main() {
    std::deque<int> dq;
    dq.push_back(10);
    dq.push_front(5);
    for (int val : dq) {
        std::cout << val << " ";
    }
    std::cout << "\n";
    return 0;
}
