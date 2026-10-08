#include <iostream>
struct Point {
    int x;
    int y;
    Point(int x_val, int y_val) : x(x_val), y(y_val) {}
    int manhattan_dist(const Point& other) const {
        int dx = x > other.x ? x - other.x : other.x - x;
        int dy = y > other.y ? y - other.y : other.y - y;
        return dx + dy;
    }
};
int main() {
    Point p1(0, 0);
    Point p2(3, 4);
    std::cout << "Distance: " << p1.manhattan_dist(p2) << "\n";
    return 0;
}
