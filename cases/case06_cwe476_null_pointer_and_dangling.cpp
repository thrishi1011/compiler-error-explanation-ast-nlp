/**
 * ==============================================================================
 * Test Case 06: NULL Pointer Dereference & Object Lifetime (CWE-476, CERT EXP34-C)
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-476: NULL Pointer Dereference
 *   - SEI CERT EXP34-C: Do not dereference null pointers
 *   - SEI CERT DCL30-C: Do not return references/pointers to automatic storage duration objects
 *   - MITRE CAPEC-129: Pointer Manipulation
 *   - CodeQL Pattern: cpp/dereferenced-value-may-be-null
 *
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Recipe 'add_null_check': injects `if (!ptr) return;` guard
 *   2. Detection of local variable address returned across function boundary
 *   3. Dereference without null assertion
 * ==============================================================================
 */

#include <iostream>
#include <string>
#include <cstdlib>

struct SessionContext {
    int session_id;
    char token[32];
    bool is_authenticated;

    void refresh() {
        std::cout << "Refreshing session: " << session_id << std::endl;
    }
};

// Pattern 1: Direct NULL pointer dereference
void vulnerable_direct_null_deref() {
    int* bad_ptr = nullptr;
    // VULNERABILITY: Dereferencing nullptr causes immediate segmentation fault (CRASH)
    // CERT Rule: EXP34-C / CWE-476
    *bad_ptr = 999;
    std::cout << "Value: " << *bad_ptr << std::endl;
}

// Pattern 2: Returning address of automatic stack variable (Dangling Pointer)
int* vulnerable_return_stack_address() {
    int local_counter = 42;
    // VULNERABILITY: local_counter lives on stack frame and is deallocated upon return
    // CERT Rule: DCL30-C / CWE-476
    return &local_counter; 
}

// Pattern 3: Lookups returning nullptr on missing key without check in caller
SessionContext* find_session_by_token(const char* token) {
    if (token == nullptr || strcmp(token, "VALID") != 0) {
        return nullptr; // Session not found
    }
    static SessionContext valid_session = {101, "VALID", true};
    return &valid_session;
}

void process_unverified_session(const char* client_token) {
    SessionContext* session = find_session_by_token(client_token);
    // VULNERABILITY: If session == nullptr, accessing session->session_id causes crash
    // CERT Rule: EXP34-C / CWE-476
    std::cout << "User Session ID: " << session->session_id << std::endl;
    session->refresh();
}

// Pattern 4: Unchecked pointer dereference in utility helper
int compute_length_unsafe(const char* str) {
    // VULNERABILITY: Dereferences str[0] directly without checking if str is null
    // CERT Rule: EXP34-C / CWE-476
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Pattern 5: Compliant safe dereference with defensive check
int compute_length_safe(const char* str) {
    // COMPLIANT: Explicit null guard
    if (str == nullptr) {
        return 0;
    }
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

int main(int argc, char** argv) {
    std::cout << "=== Running CWE-476 NULL Pointer Dereference Suite ===\n";

    int* dangling = vulnerable_return_stack_address();
    std::cout << "Dangling pointer read: " << *dangling << std::endl;

    process_unverified_session("INVALID_TOKEN");
    compute_length_unsafe(nullptr);
    compute_length_safe(nullptr);
    vulnerable_direct_null_deref();

    return 0;
}
