#include <iostream>
namespace config {
    const int MAX_USERS = 100;
    const double TIMEOUT_SEC = 30.5;
}
int main() {
    std::cout << "Max: " << config::MAX_USERS << ", Timeout: " << config::TIMEOUT_SEC << "\n";
    return 0;
}
