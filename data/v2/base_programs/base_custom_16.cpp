#include <iostream>
class Counter {
private:
    static int instances;
public:
    Counter() { instances++; }
    ~Counter() { instances--; }
    static int getInstances() { return instances; }
};
int Counter::instances = 0;
int main() {
    Counter c1;
    Counter c2;
    std::cout << "Active: " << Counter::getInstances() << "\n";
    return 0;
}
