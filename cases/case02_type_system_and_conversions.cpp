/**
 * ==============================================================================
 * Test Case 02: Type System, Conversions & Const-Correctness Violations
 * ==============================================================================
 * Category: Compiler Semantic Analysis & Type Diagnostic Explanation
 * Focus: Type checking, narrowing conversions, pointer incompatibility, const qualifiers.
 *
 * Diagnostic Coverage:
 *   1. Invalid conversion from 'const char*' to 'int'
 *   2. Passing incompatible pointer types without explicit cast
 *   3. Calling non-const member functions on const object references
 *   4. Brace initialization narrowing conversions (e.g., float/double into integer)
 *   5. Non-void function failing to return a value along all control paths
 *   6. Discarding 'const' qualifiers through raw pointer assignment
 *   7. Invalid downcasting and invalid static_cast operands
 * ==============================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>

class Account {
public:
    Account(int id, double initial_balance)
        : m_id(id), m_balance(initial_balance) {}

    // Non-const method mutating state
    void deposit(double amount) {
        m_balance += amount;
    }

    // Non-const getter violating const-correctness
    double get_balance() {
        return m_balance;
    }

    int get_id() const {
        return m_id;
    }

private:
    int m_id;
    double m_balance;
};

// Issue 1: Const violation - calling non-const member on const reference
void print_account_summary(const Account& acc) {
    std::cout << "Account ID: " << acc.get_id() << std::endl;
    // ERROR: passing 'const Account' as 'this' argument discards qualifiers
    std::cout << "Balance: " << acc.get_balance() << std::endl;
}

// Issue 2: Invalid type assignment between primitive & pointer/string
void type_mismatch_assignments() {
    int numeric_id = "USER_10492"; // ERROR: cannot convert 'const char*' to 'int'
    std::string text_code = 404;   // Warning/Error: conversion or ambiguous constructor
    double rate = nullptr;         // ERROR: cannot convert 'std::nullptr_t' to 'double'

    char* raw_buffer = "Read-Only String Literal"; // Deprecated conversion / error in modern C++
    *raw_buffer = 'X';
}

// Issue 3: Incompatible pointer assignments and const stripping
void pointer_compatibility_errors() {
    const int read_only_limit = 1000;
    // ERROR: invalid conversion from 'const int*' to 'int*'
    int* mutable_ptr = &read_only_limit;
    *mutable_ptr = 2000;

    double pi = 3.14159265;
    // ERROR: cannot convert 'double*' to 'int*' in assignment
    int* int_ptr = &pi;
}

// Issue 4: Narrowing conversions in list initialization (C++11/14/17 strictness)
void narrowing_conversion_tests() {
    double precise_coord = 58.99214;
    // ERROR: narrowing conversion of 'precise_coord' from 'double' to 'int'
    int truncated_x{precise_coord};

    long long huge_val = 9223372036854775807LL;
    short narrow_s{huge_val}; // ERROR: narrowing conversion
}

// Issue 5: Missing return statement in non-void function
int compute_discount(int customer_tier, double amount) {
    if (customer_tier == 1) {
        return amount * 0.10;
    } else if (customer_tier == 2) {
        return amount * 0.20;
    }
    // ERROR: control reaches end of non-void function without a return value
}

// Issue 6: Invalid static_cast between unrelated polymorphic types
struct BaseVehicle { virtual ~BaseVehicle() = default; };
struct Airplane : public BaseVehicle { void fly() {} };
struct Submarine : public BaseVehicle { void dive() {} };

void casting_violations() {
    BaseVehicle* vehicle = new Airplane();
    // ERROR: static_cast to sibling pointer that is invalid at runtime
    Submarine* sub = static_cast<Submarine*>(vehicle);
    sub->dive();
    delete vehicle;
}

int main() {
    Account acc(101, 450.75);
    print_account_summary(acc);
    type_mismatch_assignments();
    pointer_compatibility_errors();
    narrowing_conversion_tests();
    compute_discount(3, 100.0);
    casting_violations();
    return 0;
}
