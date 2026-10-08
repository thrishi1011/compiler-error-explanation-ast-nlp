"""
build_base_programs.py
======================
Generates and collects >= 150 single-file C++ base programs that compile
with ZERO diagnostics under `g++ -std=c++17 -Wall`:
 (a) 45 custom programs specifically featuring classes, private/protected access,
     const qualifiers, separate declaration/definition, namespaces, templates,
     STL containers, and pointers.
 (b) 110 clean single-file programs from TheAlgorithms/C-Plus-Plus (MIT License).
Produces data/v2/manifest.csv.
"""

import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.join(PROJECT_ROOT, "data", "v2", "base_programs")
MANIFEST_FILE = os.path.join(PROJECT_ROOT, "data", "v2", "manifest.csv")
ALGO_DIR = os.path.join(PROJECT_ROOT, "scratch", "the_algorithms")

os.makedirs(BASE_DIR, exist_ok=True)

# ── 45 Custom Diverse C++ Programs ───────────────────────────────────────────
CUSTOM_PROGRAMS = [
    # 1. OOP with private member and public getter/setter
    ("""#include <iostream>
class Account {
private:
    int balance;
    const int account_id;
public:
    Account(int id, int bal) : balance(bal), account_id(id) {}
    int getBalance() const { return balance; }
    void setBalance(int b) { balance = b; }
    int getId() const { return account_id; }
};
int main() {
    Account acc(101, 500);
    acc.setBalance(600);
    std::cout << acc.getId() << ": " << acc.getBalance() << "\\n";
    return 0;
}
""", "OOP class with private balance and const id"),

    # 2. Protected inheritance and method override
    ("""#include <iostream>
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
    std::cout << "Area: " << rect.area() << "\\n";
    return 0;
}
""", "Protected inheritance with virtual destructor"),

    # 3. Const variable assignment protection
    ("""#include <iostream>
int compute_tax(const int income) {
    const double tax_rate = 0.15;
    return static_cast<int>(income * tax_rate);
}
int main() {
    const int salary = 50000;
    int tax = compute_tax(salary);
    std::cout << "Tax: " << tax << "\\n";
    return 0;
}
""", "Const parameter and local const variable"),

    # 4. Function declaration separate from definition
    ("""#include <iostream>
int multiply(int a, int b);
void greet(const char* name);

int main() {
    greet("User");
    std::cout << "Product: " << multiply(4, 5) << "\\n";
    return 0;
}

int multiply(int a, int b) {
    return a * b;
}

void greet(const char* name) {
    std::cout << "Hello, " << name << "\\n";
}
""", "Separate declaration and definition for functions"),

    # 5. Template function with multiple types
    ("""#include <iostream>
template <typename T, typename U>
auto add_values(T a, U b) -> decltype(a + b) {
    return a + b;
}
int main() {
    std::cout << add_values(10, 2.5) << "\\n";
    std::cout << add_values(3.14, 2) << "\\n";
    return 0;
}
""", "Template function with trailing return type"),

    # 6. STL vector and algorithm sort
    ("""#include <iostream>
#include <vector>
#include <algorithm>
int main() {
    std::vector<int> numbers = {5, 2, 8, 1, 9};
    std::sort(numbers.begin(), numbers.end());
    for (int n : numbers) {
        std::cout << n << " ";
    }
    std::cout << "\\n";
    return 0;
}
""", "STL vector and std::sort"),

    # 7. STL map lookup and insertion
    ("""#include <iostream>
#include <map>
#include <string>
int main() {
    std::map<std::string, int> ages;
    ages["Alice"] = 25;
    ages["Bob"] = 30;
    auto it = ages.find("Alice");
    if (it != ages.end()) {
        std::cout << it->first << ": " << it->second << "\\n";
    }
    return 0;
}
""", "STL map key-value operations"),

    # 8. Dynamic allocation with new and delete
    ("""#include <iostream>
int main() {
    int* ptr = new int(42);
    std::cout << "Value: " << *ptr << "\\n";
    delete ptr;
    ptr = nullptr;
    return 0;
}
""", "Pointer dynamic allocation with new and delete"),

    # 9. Scoped enum class
    ("""#include <iostream>
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
    std::cout << color_name(c) << "\\n";
    return 0;
}
""", "Scoped enum class with switch handling"),

    # 10. Namespace nesting and usage
    ("""#include <iostream>
namespace math_utils {
    namespace algebra {
        int square(int x) { return x * x; }
        int cube(int x) { return x * x * x; }
    }
}
int main() {
    using namespace math_utils::algebra;
    std::cout << "Square: " << square(5) << "\\n";
    std::cout << "Cube: " << cube(3) << "\\n";
    return 0;
}
""", "Nested namespaces and using directive"),

    # 11. Struct with constructor and member functions
    ("""#include <iostream>
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
    std::cout << "Distance: " << p1.manhattan_dist(p2) << "\\n";
    return 0;
}
""", "Struct with const reference parameters"),

    # 12. Template class (Stack implementation)
    ("""#include <iostream>
#include <vector>
template <typename T>
class SimpleStack {
private:
    std::vector<T> elements;
public:
    void push(const T& val) { elements.push_back(val); }
    T pop() {
        T top = elements.back();
        elements.pop_back();
        return top;
    }
    bool empty() const { return elements.empty(); }
};
int main() {
    SimpleStack<int> s;
    s.push(10);
    s.push(20);
    while (!s.empty()) {
        std::cout << s.pop() << " ";
    }
    std::cout << "\\n";
    return 0;
}
""", "Generic stack template class"),

    # 13. STL set operations
    ("""#include <iostream>
#include <set>
int main() {
    std::set<int> unique_vals;
    unique_vals.insert(10);
    unique_vals.insert(20);
    unique_vals.insert(10);
    std::cout << "Size: " << unique_vals.size() << "\\n";
    return 0;
}
""", "STL set uniqueness check"),

    # 14. String manipulation and stream operations
    ("""#include <iostream>
#include <string>
#include <sstream>
int main() {
    std::string text = "100 200 300";
    std::istringstream iss(text);
    int a = 0, b = 0, c = 0;
    iss >> a >> b >> c;
    std::cout << "Sum: " << (a + b + c) << "\\n";
    return 0;
}
""", "Stringstream parsing"),

    # 15. Const member function modifying mutable or returning value
    ("""#include <iostream>
class Tracker {
private:
    mutable int access_count;
    int id;
public:
    Tracker(int i) : access_count(0), id(i) {}
    int getId() const {
        access_count++;
        return id;
    }
    int getAccessCount() const { return access_count; }
};
int main() {
    const Tracker t(99);
    t.getId();
    t.getId();
    std::cout << "Count: " << t.getAccessCount() << "\\n";
    return 0;
}
""", "Const object with mutable member"),

    # 16. Static members in class
    ("""#include <iostream>
class Counter {
private:
    static int instances;
public:
    Counter() { instances++; }
    ~Counter() { instances--; }
    static int getInstances() { return instances; }
};
int Counter::instances = 0;
int main() {
    Counter c1;
    Counter c2;
    std::cout << "Active: " << Counter::getInstances() << "\\n";
    return 0;
}
""", "Class with static private member and definition"),

    # 17. Math functions from cmath
    ("""#include <iostream>
#include <cmath>
int main() {
    double x = 16.0;
    double root = std::sqrt(x);
    double power = std::pow(root, 3.0);
    std::cout << "Root: " << root << ", Power: " << power << "\\n";
    return 0;
}
""", "CMath std::sqrt and std::pow"),

    # 18. Const pointer vs pointer to const
    ("""#include <iostream>
int main() {
    int val1 = 10;
    int val2 = 20;
    const int* ptr_to_const = &val1;
    ptr_to_const = &val2;
    int* const const_ptr = &val1;
    *const_ptr = 30;
    std::cout << *ptr_to_const << " " << *const_ptr << "\\n";
    return 0;
}
""", "Const pointer and pointer-to-const semantics"),

    # 19. Binary search using algorithm
    ("""#include <iostream>
#include <vector>
#include <algorithm>
int main() {
    std::vector<int> sorted_arr = {10, 20, 30, 40, 50};
    bool found = std::binary_search(sorted_arr.begin(), sorted_arr.end(), 30);
    std::cout << "Found: " << (found ? "yes" : "no") << "\\n";
    return 0;
}
""", "std::binary_search usage"),

    # 20. Queue operations
    ("""#include <iostream>
#include <queue>
int main() {
    std::queue<int> q;
    q.push(1);
    q.push(2);
    while (!q.empty()) {
        std::cout << q.front() << " ";
        q.pop();
    }
    std::cout << "\\n";
    return 0;
}
""", "std::queue container operations"),

    # 21. Deque with push_front and push_back
    ("""#include <iostream>
#include <deque>
int main() {
    std::deque<int> dq;
    dq.push_back(10);
    dq.push_front(5);
    for (int val : dq) {
        std::cout << val << " ";
    }
    std::cout << "\\n";
    return 0;
}
""", "std::deque front and back operations"),

    # 22. Array container with size
    ("""#include <iostream>
#include <array>
int main() {
    std::array<int, 4> arr = {1, 2, 3, 4};
    int sum = 0;
    for (size_t i = 0; i < arr.size(); i++) {
        sum += arr[i];
    }
    std::cout << "Sum: " << sum << "\\n";
    return 0;
}
""", "std::array with size iteration"),

    # 23. Function overloading
    ("""#include <iostream>
int print_value(int x) { return x * 2; }
double print_value(double x) { return x * 2.0; }
int main() {
    std::cout << print_value(5) << "\\n";
    std::cout << print_value(4.5) << "\\n";
    return 0;
}
""", "Function overloading with int and double"),

    # 24. Friend function accessing private data
    ("""#include <iostream>
class Box {
private:
    int length;
public:
    Box(int l) : length(l) {}
    friend void printLength(const Box& b);
};
void printLength(const Box& b) {
    std::cout << "Length: " << b.length << "\\n";
}
int main() {
    Box box(15);
    printLength(box);
    return 0;
}
""", "Friend function accessing private member"),

    # 25. Pass by reference vs pass by value
    ("""#include <iostream>
void increment_val(int val) { val++; }
void increment_ref(int& val) { val++; }
int main() {
    int x = 10;
    increment_val(x);
    std::cout << "After val: " << x << "\\n";
    increment_ref(x);
    std::cout << "After ref: " << x << "\\n";
    return 0;
}
""", "Pass by reference and pass by value semantics"),

    # 26. Bitwise operations and masks
    ("""#include <iostream>
int main() {
    unsigned int flags = 0x05;
    unsigned int mask = 0x01;
    bool is_set = (flags & mask) != 0;
    std::cout << "Set: " << (is_set ? "yes" : "no") << "\\n";
    return 0;
}
""", "Bitwise AND and bitmask checking"),

    # 27. Multiple constructors
    ("""#include <iostream>
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
    std::cout << v1.x << " " << v2.y << "\\n";
    return 0;
}
""", "Default and parameterized constructors"),

    # 28. Operator overloading (operator+)
    ("""#include <iostream>
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
    std::cout << c3.real << " + " << c3.imag << "i\\n";
    return 0;
}
""", "Binary operator+ overloading"),

    # 29. Recursion with base case
    ("""#include <iostream>
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
int main() {
    std::cout << "5! = " << factorial(5) << "\\n";
    return 0;
}
""", "Recursive factorial function"),

    # 30. Lambda expression with capture
    ("""#include <iostream>
#include <vector>
#include <algorithm>
int main() {
    std::vector<int> v = {1, 2, 3, 4, 5};
    int factor = 10;
    std::for_each(v.begin(), v.end(), [factor](int n) {
        std::cout << (n * factor) << " ";
    });
    std::cout << "\\n";
    return 0;
}
""", "Lambda expression with capture by value"),

    # 31. String reverse with std::reverse
    ("""#include <iostream>
#include <string>
#include <algorithm>
int main() {
    std::string s = "compiler";
    std::reverse(s.begin(), s.end());
    std::cout << "Reversed: " << s << "\\n";
    return 0;
}
""", "std::reverse on std::string"),

    # 32. Custom comparator for sorting
    ("""#include <iostream>
#include <vector>
#include <algorithm>
bool descending(int a, int b) {
    return a > b;
}
int main() {
    std::vector<int> nums = {3, 1, 4, 1, 5};
    std::sort(nums.begin(), nums.end(), descending);
    for (int x : nums) std::cout << x << " ";
    std::cout << "\\n";
    return 0;
}
""", "Custom comparator function with std::sort"),

    # 33. Matrix 2D dynamic vector
    ("""#include <iostream>
#include <vector>
int main() {
    int rows = 3, cols = 3;
    std::vector<std::vector<int>> matrix(rows, std::vector<int>(cols, 1));
    std::cout << "Element: " << matrix[1][1] << "\\n";
    return 0;
}
""", "2D vector allocation and access"),

    # 34. Void function without return
    ("""#include <iostream>
void print_banner(const char* title) {
    std::cout << "=== " << title << " ===\\n";
}
int main() {
    print_banner("Test");
    return 0;
}
""", "Void function with const char* parameter"),

    # 35. Enum traditional
    ("""#include <iostream>
enum Direction { North, South, East, West };
int main() {
    Direction dir = East;
    if (dir == East) {
        std::cout << "Heading East\\n";
    }
    return 0;
}
""", "Traditional C++ enum"),

    # 36. Pointer arithmetic
    ("""#include <iostream>
int main() {
    int arr[] = {10, 20, 30, 40};
    int* p = arr;
    std::cout << *p << " ";
    p++;
    std::cout << *p << " ";
    p += 2;
    std::cout << *p << "\\n";
    return 0;
}
""", "Pointer increment and arithmetic"),

    # 37. Structure alignment and sizeof
    ("""#include <iostream>
struct DataRecord {
    int id;
    double weight;
    char code;
};
int main() {
    std::cout << "Size: " << sizeof(DataRecord) << "\\n";
    return 0;
}
""", "Struct sizeof and alignment"),

    # 38. Type alias using typedef / using
    ("""#include <iostream>
using ULong = unsigned long;
int main() {
    ULong big_num = 123456789UL;
    std::cout << "Number: " << big_num << "\\n";
    return 0;
}
""", "Type alias using C++ using statement"),

    # 39. Function returning pointer
    ("""#include <iostream>
int* get_first_element(int* arr) {
    return arr;
}
int main() {
    int nums[] = {7, 8, 9};
    int* p = get_first_element(nums);
    std::cout << "First: " << *p << "\\n";
    return 0;
}
""", "Function returning pointer to int"),

    # 40. Pair utility container
    ("""#include <iostream>
#include <utility>
#include <string>
int main() {
    std::pair<std::string, int> entry("Score", 95);
    std::cout << entry.first << ": " << entry.second << "\\n";
    return 0;
}
""", "std::pair utility header usage"),

    # 41. Const reference return
    ("""#include <iostream>
#include <string>
class Person {
private:
    std::string name;
public:
    Person(const std::string& n) : name(n) {}
    const std::string& getName() const { return name; }
};
int main() {
    Person p("Bob");
    std::cout << p.getName() << "\\n";
    return 0;
}
""", "Const reference return from member function"),

    # 42. Pure virtual function / Abstract class
    ("""#include <iostream>
class AbstractLogger {
public:
    virtual void log(const char* msg) = 0;
    virtual ~AbstractLogger() {}
};
class ConsoleLogger : public AbstractLogger {
public:
    void log(const char* msg) override {
        std::cout << "[LOG] " << msg << "\\n";
    }
};
int main() {
    ConsoleLogger logger;
    logger.log("System initialized");
    return 0;
}
""", "Abstract class with pure virtual method"),

    # 43. Multi-file simulator (headers/structures declared locally)
    ("""#include <iostream>
namespace config {
    const int MAX_USERS = 100;
    const double TIMEOUT_SEC = 30.5;
}
int main() {
    std::cout << "Max: " << config::MAX_USERS << ", Timeout: " << config::TIMEOUT_SEC << "\\n";
    return 0;
}
""", "Namespace with const configuration parameters"),

    # 44. Do-while loop
    ("""#include <iostream>
int main() {
    int counter = 0;
    do {
        counter++;
    } while (counter < 3);
    std::cout << "Counter: " << counter << "\\n";
    return 0;
}
""", "Do-while loop construct"),

    # 45. Struct with member pointer
    ("""#include <iostream>
struct Node {
    int data;
    Node* next;
    Node(int d) : data(d), next(nullptr) {}
};
int main() {
    Node n1(10);
    Node n2(20);
    n1.next = &n2;
    std::cout << n1.data << " -> " << n1.next->data << "\\n";
    return 0;
}
""", "Linked list node struct with nullptr initialization"),
]


def test_compile(filepath: str) -> bool:
    res = subprocess.run(
        ["g++", "-std=c++17", "-Wall", "-fsyntax-only", filepath],
        capture_output=True,
        text=True,
        timeout=15
    )
    return res.returncode == 0 and not res.stderr.strip()


def main():
    print("=" * 60)
    print("  COLLECTING CLEAN BASE C++ PROGRAMS (>= 150)")
    print("=" * 60)

    manifest_rows = []

    # 1. Write and test 45 custom programs
    print("  [1/2] Generating 45 custom diverse C++ programs...")
    for idx, (code, notes) in enumerate(CUSTOM_PROGRAMS, 1):
        pid = f"base_custom_{idx:02d}"
        filename = f"{pid}.cpp"
        fpath = os.path.join(BASE_DIR, filename)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(code)

        if test_compile(fpath):
            manifest_rows.append((pid, "custom_author", "MIT", fpath, notes))
        else:
            print(f"    Warning: {pid} failed compilation, skipping.")

    print(f"    Collected {len(manifest_rows)} clean custom programs.")

    # 2. Select 110 clean programs from TheAlgorithms
    print("  [2/2] Scanning TheAlgorithms/C-Plus-Plus (MIT License)...")
    algo_files = []
    if os.path.exists(ALGO_DIR):
        for root, _, files in os.walk(ALGO_DIR):
            for fn in files:
                if fn.endswith(".cpp"):
                    algo_files.append(os.path.join(root, fn))

    print(f"    Found {len(algo_files)} candidate files. Testing with -Wall...")

    algo_clean = []

    def check_file(path):
        try:
            if test_compile(path):
                return path
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        for res in executor.map(check_file, algo_files):
            if res:
                algo_clean.append(res)
                if len(algo_clean) >= 115:
                    break

    for idx, src_path in enumerate(algo_clean[:110], 1):
        pid = f"base_algo_{idx:03d}"
        filename = f"{pid}.cpp"
        dest_path = os.path.join(BASE_DIR, filename)
        shutil.copyfile(src_path, dest_path)
        rel_src = os.path.relpath(src_path, PROJECT_ROOT).replace("\\", "/")
        manifest_rows.append((pid, f"TheAlgorithms/C-Plus-Plus ({rel_src})", "MIT", dest_path, "Algorithm benchmark"))

    print(f"    Selected {min(len(algo_clean), 110)} clean programs from TheAlgorithms.")

    # 3. Write manifest
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        f.write("program_id,origin,license,filepath,notes\n")
        for pid, origin, lic, path, notes in manifest_rows:
            f.write(f'"{pid}","{origin}","{lic}","{path.replace(chr(92), "/")}","{notes}"\n')

    print(f"\n[OK] Manifest created: {MANIFEST_FILE}")
    print(f"     Total verified clean base programs: {len(manifest_rows)}")


if __name__ == "__main__":
    main()
