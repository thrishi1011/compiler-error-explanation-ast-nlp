/**
 * ==============================================================================
 * Test Case 05: Uncontrolled Format String Vulnerabilities (CWE-134)
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-134: Use of Externally-Controlled Format String
 *   - SEI CERT FIO30-C: Exclude user input from format strings
 *   - MITRE CAPEC-135: Format String Injection
 *   - CodeQL Pattern: cpp/non-constant-format
 *
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Recipe 'replace_printf_format': rewrites printf(var) -> printf("%s", var)
 *   2. Scanner detection on non-literal format strings in printf / fprintf / syslog
 *   3. AI Explainer: Highlights arbitrary read/write memory exploitation (%x, %s, %n)
 * ==============================================================================
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

// Pattern 1: Direct printf with untrusted variable
void vulnerable_direct_printf(const char* untrusted_input) {
    // VULNERABILITY: If untrusted_input contains "%x %x %x %n", it exposes stack memory
    // or writes arbitrary bytes to arbitrary memory addresses.
    // CERT Rule: FIO30-C / CWE-134
    printf(untrusted_input);
    printf("\n");
}

// Pattern 2: fprintf to standard error stream with user message
void vulnerable_fprintf_error_log(FILE* log_stream, const char* client_err_msg) {
    // VULNERABILITY: Direct pass to fprintf format string argument
    // CERT Rule: FIO30-C / CWE-134
    fprintf(log_stream, client_err_msg);
    fprintf(log_stream, "\n");
}

// Pattern 3: Custom logging abstraction with format string defect
class ServerLogger {
public:
    static void log_info(const char* message) {
        // VULNERABILITY: Non-constant format string parameter
        printf(message);
    }

    static void log_warning(const char* message) {
        // VULNERABILITY: Non-constant format string parameter
        fprintf(stderr, message);
    }
};

// Pattern 4: Intermediate sprintf formatting into heap buffer
void vulnerable_sprintf_passthrough(const char* user_tag) {
    char intermediate[256];
    // Copy into intermediate buffer
    strncpy(intermediate, user_tag, sizeof(intermediate) - 1);
    intermediate[sizeof(intermediate) - 1] = '\0';

    // VULNERABILITY: Printed directly as format specifier
    printf(intermediate);
}

// Pattern 5: Compliant implementation for baseline comparison
void compliant_safe_logger(const char* user_input) {
    // COMPLIANT: Explicit "%s" format specifier prevents interpretation of '%' characters
    printf("%s\n", user_input);
    fprintf(stderr, "%s\n", user_input);
}

int main(int argc, char** argv) {
    printf("=== Running CWE-134 Format String Test Suite ===\n");
    const char* attack_payload = "User: Admin | Leak Stack: %08x %08x %08x %s";

    vulnerable_direct_printf(attack_payload);
    vulnerable_fprintf_error_log(stderr, attack_payload);
    ServerLogger::log_info(attack_payload);
    ServerLogger::log_warning(attack_payload);
    vulnerable_sprintf_passthrough(attack_payload);
    compliant_safe_logger(attack_payload);

    return 0;
}
