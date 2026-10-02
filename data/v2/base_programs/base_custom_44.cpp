#include <iostream>
int main() {
    int counter = 0;
    do {
        counter++;
    } while (counter < 3);
    std::cout << "Counter: " << counter << "\n";
    return 0;
}
