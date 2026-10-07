#include <iostream>
class Shape {
protected:
    int width;
    int height;
public:
    Shape(int w, int h) : width(w), height(h) {}
    virtual int area() const { return width * height; }
    virtual ~Shape() {}
};
class Rectangle : public Shape {
public:
    Rectangle(int w, int h) : Shape(w, h) {}
    int area() const override { return width * height; }
};
int main() {
    Rectangle rect(10, 20);
    std::cout << "Area: " << rect.area() << "\n";
    return 0;
}
