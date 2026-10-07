#include <iostream>
struct DataRecord {
    int id;
    double weight;
    char code;
};
int main() {
    std::cout << "Size: " << sizeof(DataRecord) << "\n";
    return 0;
}
