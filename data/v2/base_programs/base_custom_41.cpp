#include <iostream>
#include <string>
class Person {
private:
    std::string name;
public:
    Person(const std::string& n) : name(n) {}
    const std::string& getName() const { return name; }
};
int main() {
    Person p("Bob");
    std::cout << p.getName() << "\n";
    return 0;
}
