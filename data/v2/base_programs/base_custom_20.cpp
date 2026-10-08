#include <iostream>
#include <queue>
int main() {
    std::queue<int> q;
    q.push(1);
    q.push(2);
    while (!q.empty()) {
        std::cout << q.front() << " ";
        q.pop();
    }
    std::cout << "\n";
    return 0;
}
