/**
 * ==============================================================================
 * Test Case 10: Macro Aliasing, AST Evasion & Preprocessor Obfuscation
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-120: Buffer Copy without Checking Size of Input
 *   - MITRE CWE-676: Use of Potentially Dangerous Function
 *   - MITRE CWE-78: OS Command Injection
 *   - SEI CERT PRE31-C: Avoid dangerous preprocessor macros
 *   - SEI CERT STR31-C: Guarantee storage for strings
 *   - CodeQL Pattern: cpp/ast-macro-expansion-detection
 *
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Phase 3 AST Rule 'Macro Alias Detection':
 *      Detects dangerous functions hidden behind preprocessor macro aliases
 *      (e.g., #define READ_LINE gets, #define COPY strcpy, #define SHELL_EXEC system)
 *   2. Constant array bounds checking even when sizes are expanded from macros
 *   3. Demonstrates why AST-level semantic analysis defeats simple regex evasion
 * ==============================================================================
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

// Obfuscation Layer 1: Macro Aliases designed to evade naive keyword matching
#define READ_UNSAFE_LINE   gets
#define STR_UNCHECKED_COPY strcpy
#define RUN_SHELL_CMD      system
#define RAW_PRINT_FORMAT   printf

// Obfuscation Layer 2: Constant size macros
#define BUFFER_CAPACITY    8
#define OVERFLOW_INDEX     (BUFFER_CAPACITY + 2) // Evaluates to index 10

// Obfuscation Layer 3: Nested structures with arrays
struct SubBlock {
    int metrics[BUFFER_CAPACITY];
};

struct OuterBlock {
    SubBlock blocks[2];
};

void test_macro_aliased_gets() {
    char stack_buf[32];
    std::cout << "[*] Enter input (via macro alias):\n";
    // AST / CodeQL Rule: Catches gets() through the READ_UNSAFE_LINE macro definition!
    READ_UNSAFE_LINE(stack_buf);
    std::cout << "Read: " << stack_buf << std::endl;
}

void test_macro_aliased_strcpy() {
    char target[BUFFER_CAPACITY];
    const char* source = "Long payload that exceeds 8 bytes";
    // AST / CodeQL Rule: Catches strcpy() through the STR_UNCHECKED_COPY macro definition!
    STR_UNCHECKED_COPY(target, source);
    std::cout << "Target: " << target << std::endl;
}

void test_macro_aliased_system() {
    // AST / CodeQL Rule: Catches system() through the RUN_SHELL_CMD macro definition!
    RUN_SHELL_CMD("echo AST Macro Detection Passed");
}

void test_macro_array_bounds() {
    int lookup_table[BUFFER_CAPACITY];
    for (int i = 0; i < BUFFER_CAPACITY; ++i) {
        lookup_table[i] = i * 2;
    }

    // AST Rule: Subscript [10] exceeds declared size [8] (BUFFER_CAPACITY)
    lookup_table[10] = 555;
    std::cout << "Lookup: " << lookup_table[10] << std::endl;
}

void test_nested_struct_bounds() {
    OuterBlock outer;
    // AST Rule: Array 'blocks' has size 2, index [5] is out of bounds
    // Array 'metrics' has size 8, index [12] is out of bounds
    outer.blocks[0].metrics[12] = 42;
    std::cout << "Value: " << outer.blocks[0].metrics[12] << std::endl;
}

int main(int argc, char** argv) {
    std::cout << "=== Running AST & Macro Evasion Benchmark ===\n";
    test_macro_aliased_gets();
    test_macro_aliased_strcpy();
    test_macro_aliased_system();
    test_macro_array_bounds();
    test_nested_struct_bounds();
    return 0;
}
