/**
 * ==============================================================================
 * Test Case 08: Integer Overflows, Underflows & Arithmetic Anomalies (CWE-190)
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-190: Integer Overflow or Wraparound
 *   - MITRE CWE-191: Integer Underflow (Wrap around)
 *   - MITRE CWE-369: Divide By Zero
 *   - SEI CERT INT30-C: Ensure that unsigned integer operations do not wrap
 *   - SEI CERT INT32-C: Ensure that operations on signed integers do not result in overflow
 *   - MITRE CAPEC-128: Integer Attacks
 *   - CodeQL Pattern: cpp/integer-overflow
 *
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Recipe 'safe_int_add': replaces `a + b` with overflow-checked addition
 *   2. Detection of division or modulo by literal zero
 *   3. Dangerous signed vs unsigned comparisons leading to bypass
 * ==============================================================================
 */

#include <iostream>
#include <climits>
#include <cstdint>
#include <vector>

// Pattern 1: Signed Integer Overflow (Undefined Behavior in C/C++)
int vulnerable_signed_overflow(int base_salary, int bonus_multiplier) {
    // VULNERABILITY: If base_salary * bonus_multiplier > INT_MAX, results in signed overflow (UB)
    // CERT Rule: INT32-C / CWE-190
    int total_compensation = base_salary * bonus_multiplier;
    return total_compensation;
}

// Pattern 2: Unsigned Integer Wraparound in Memory Allocation Calculation
void* vulnerable_allocation_calculation(size_t count, size_t element_size) {
    // VULNERABILITY: count * element_size wraps around zero on 32-bit/64-bit bounds
    // Allocates a tiny buffer, but subsequent loop copies full count -> heap overflow
    // CERT Rule: INT30-C / CWE-190
    size_t total_bytes = count * element_size;
    std::cout << "Allocating: " << total_bytes << " bytes\n";
    return malloc(total_bytes);
}

// Pattern 3: Unsigned Underflow in Counter Decrement
void vulnerable_unsigned_underflow() {
    unsigned int active_connections = 0;
    // VULNERABILITY: Decrementing zero wraps to UINT_MAX (4,294,967,295)
    // CERT Rule: INT30-C / CWE-191
    active_connections--;
    std::cout << "Active connections after underflow: " << active_connections << std::endl;
}

// Pattern 4: Division & Modulo By Zero
int vulnerable_division(int numerator, int denominator) {
    // VULNERABILITY: Division by zero triggers SIGFPE hardware fault
    // CWE-369
    int result = numerator / denominator;
    int remainder = numerator % denominator;
    return result + remainder;
}

void literal_division_by_zero() {
    int x = 100;
    // Direct literal division by zero caught by compiler warning/error and static analyzer
    int y = x / 0;
    std::cout << "Result: " << y << std::endl;
}

// Pattern 5: Signed-to-Unsigned Comparison Defect
bool check_user_supplied_length(int user_len) {
    char internal_buffer[64];
    // VULNERABILITY: If user_len is negative (-1), comparing to sizeof (unsigned size_t)
    // implicitly casts user_len to huge positive value (0xFFFFFFFF > 64) OR
    // if reversed, can bypass bound checks.
    if (user_len < sizeof(internal_buffer)) {
        std::cout << "Length check accepted!\n";
        return true;
    }
    return false;
}

// Pattern 6: Compliant safe addition with overflow check
bool safe_add(int a, int b, int* result) {
    // COMPLIANT: SEI CERT INT32-C compliant check
    if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) {
        return false; // Overflow would occur
    }
    *result = a + b;
    return true;
}

int main(int argc, char** argv) {
    std::cout << "=== Running Integer Overflow & Arithmetic Suite ===\n";

    int overflowed = vulnerable_signed_overflow(INT_MAX / 2, 4);
    std::cout << "Overflowed result: " << overflowed << std::endl;

    void* buf = vulnerable_allocation_calculation(SIZE_MAX / 2, 4);
    free(buf);

    vulnerable_unsigned_underflow();
    check_user_supplied_length(-1);

    int safe_res = 0;
    if (safe_add(INT_MAX, 1, &safe_res)) {
        std::cout << "Safe add: " << safe_res << std::endl;
    } else {
        std::cout << "Safely detected overflow attempt!\n";
    }

    // Uncommenting below triggers SIGFPE:
    // literal_division_by_zero();
    // vulnerable_division(10, 0);

    return 0;
}
