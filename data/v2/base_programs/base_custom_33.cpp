#include <iostream>
#include <vector>
int main() {
    int rows = 3, cols = 3;
    std::vector<std::vector<int>> matrix(rows, std::vector<int>(cols, 1));
    std::cout << "Element: " << matrix[1][1] << "\n";
    return 0;
}
