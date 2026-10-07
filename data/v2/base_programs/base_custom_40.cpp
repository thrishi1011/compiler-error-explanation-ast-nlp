#include <iostream>
#include <utility>
#include <string>
int main() {
    std::pair<std::string, int> entry("Score", 95);
    std::cout << entry.first << ": " << entry.second << "\n";
    return 0;
}
