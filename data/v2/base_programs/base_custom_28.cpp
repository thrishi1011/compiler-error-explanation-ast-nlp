#include <iostream>
class Complex {
public:
    double real;
    double imag;
    Complex(double r, double i) : real(r), imag(i) {}
    Complex operator+(const Complex& other) const {
        return Complex(real + other.real, imag + other.imag);
    }
};
int main() {
    Complex c1(1.0, 2.0);
    Complex c2(3.0, 4.0);
    Complex c3 = c1 + c2;
    std::cout << c3.real << " + " << c3.imag << "i\n";
    return 0;
}
