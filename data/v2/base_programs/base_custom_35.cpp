#include <iostream>
enum Direction { North, South, East, West };
int main() {
    Direction dir = East;
    if (dir == East) {
        std::cout << "Heading East\n";
    }
    return 0;
}
