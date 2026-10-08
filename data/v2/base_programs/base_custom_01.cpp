#include <iostream>
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
    std::cout << acc.getId() << ": " << acc.getBalance() << "\n";
    return 0;
}
