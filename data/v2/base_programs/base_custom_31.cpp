#include <iostream>
#include <string>
#include <algorithm>
int main() {
    std::string s = "compiler";
    std::reverse(s.begin(), s.end());
    std::cout << "Reversed: " << s << "\n";
    return 0;
}
