#include <iostream>
#include <vector>
template <typename T>
class SimpleStack {
private:
    std::vector<T> elements;
public:
    void push(const T& val) { elements.push_back(val); }
    T pop() {
        T top = elements.back();
        elements.pop_back();
        return top;
    }
    bool empty() const { return elements.empty(); }
};
int main() {
    SimpleStack<int> s;
    s.push(10);
    s.push(20);
    while (!s.empty()) {
        std::cout << s.pop() << " ";
    }
    std::cout << "\n";
    return 0;
}
