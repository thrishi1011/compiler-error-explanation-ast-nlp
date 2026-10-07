#include <iostream>
enum class Color { Red, Green, Blue };
const char* color_name(Color c) {
    switch (c) {
        case Color::Red: return "Red";
        case Color::Green: return "Green";
        case Color::Blue: return "Blue";
    }
    return "Unknown";
}
int main() {
    Color c = Color::Green;
    std::cout << color_name(c) << "\n";
    return 0;
}
