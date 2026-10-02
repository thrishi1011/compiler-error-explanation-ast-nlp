#include <iostream>
class Vector2D {
public:
    double x;
    double y;
    Vector2D() : x(0.0), y(0.0) {}
    Vector2D(double x_val, double y_val) : x(x_val), y(y_val) {}
};
int main() {
    Vector2D v1;
    Vector2D v2(3.0, 4.0);
    std::cout << v1.x << " " << v2.y << "\n";
    return 0;
}
