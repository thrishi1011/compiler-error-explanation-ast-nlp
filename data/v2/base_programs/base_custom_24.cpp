#include <iostream>
class Box {
private:
    int length;
public:
    Box(int l) : length(l) {}
    friend void printLength(const Box& b);
};
void printLength(const Box& b) {
    std::cout << "Length: " << b.length << "\n";
}
int main() {
    Box box(15);
    printLength(box);
    return 0;
}
