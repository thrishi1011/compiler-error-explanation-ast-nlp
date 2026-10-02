#include <iostream>
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
    std::cout << "Count: " << t.getAccessCount() << "\n";
    return 0;
}
