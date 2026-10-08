#include <iostream>
#include <map>
#include <string>
int main() {
    std::map<std::string, int> ages;
    ages["Alice"] = 25;
    ages["Bob"] = 30;
    auto it = ages.find("Alice");
    if (it != ages.end()) {
        std::cout << it->first << ": " << it->second << "\n";
    }
    return 0;
}
