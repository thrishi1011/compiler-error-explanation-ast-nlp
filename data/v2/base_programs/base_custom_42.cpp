#include <iostream>
class AbstractLogger {
public:
    virtual void log(const char* msg) = 0;
    virtual ~AbstractLogger() {}
};
class ConsoleLogger : public AbstractLogger {
public:
    void log(const char* msg) override {
        std::cout << "[LOG] " << msg << "\n";
    }
};
int main() {
    ConsoleLogger logger;
    logger.log("System initialized");
    return 0;
}
