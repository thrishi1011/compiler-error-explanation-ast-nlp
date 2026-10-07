#include <iostream>
#include <string>
#include <sstream>
int main() {
    std::string text = "100 200 300";
    std::istringstream iss(text);
    int a = 0, b = 0, c = 0;
    iss >> a >> b >> c;
    std::cout << "Sum: " << (a + b + c) << "\n";
    return 0;
}
