#include <iostream>
struct Node {
    int data;
    Node* next;
    Node(int d) : data(d), next(nullptr) {}
};
int main() {
    Node n1(10);
    Node n2(20);
    n1.next = &n2;
    std::cout << n1.data << " -> " << n1.next->data << "\n";
    return 0;
}
