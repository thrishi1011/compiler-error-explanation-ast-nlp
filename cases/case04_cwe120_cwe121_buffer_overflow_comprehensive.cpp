/**
 * ==============================================================================
 * Test Case 04: Buffer Overflow Vulnerabilities (CWE-120, CWE-121, CWE-676)
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
 *   - MITRE CWE-121: Stack-based Buffer Overflow
 *   - MITRE CWE-676: Use of Potentially Dangerous Function
 *   - SEI CERT ARR30-C: Do not form or use out-of-bounds pointers or array subscripts
 *   - SEI CERT STR31-C: Guarantee that storage for strings has sufficient space
 *   - MITRE CAPEC-100: Overflow Buffers
 *   - CodeQL Patterns: cpp/overflow-buffer, cpp/very-likely-overrunning-write
 * 
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Recipe 'replace_gets': replaces gets() with fgets()
 *   2. Recipe 'replace_strcpy': replaces strcpy() with strncpy()
 *   3. Recipe 'replace_strcat': replaces strcat() with strncat()
 *   4. Recipe 'replace_sprintf': replaces sprintf() with snprintf()
 *   5. AST Rule: Constant array subscript out-of-bounds detection
 * ==============================================================================
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>

#define STACK_BUF_SIZE 16
#define SOURCE_TEXT "This string is deliberately far longer than sixteen bytes and will overflow stack memory!"

// Pattern 1: Inherent CWE-676 / CWE-120 via gets()
void vulnerable_gets_reader() {
    char user_buffer[STACK_BUF_SIZE];
    printf("[*] Enter text: ");
    // VULNERABILITY: gets() does not check boundary constraints
    // CERT Rule: STR31-C / CWE-120
    gets(user_buffer); 
    printf("Read user input: %s\n", user_buffer);
}

// Pattern 2: Stack buffer overflow via bounded array and unbounded strcpy()
void vulnerable_strcpy_copy() {
    char destination[STACK_BUF_SIZE];
    const char* malicious_source = SOURCE_TEXT;

    // VULNERABILITY: strcpy does not bound destination copy length
    // CERT Rule: STR31-C / CWE-120
    strcpy(destination, malicious_source);
    printf("Copied buffer: %s\n", destination);
}

// Pattern 3: Cumulative buffer overflow via unchecked strcat()
void vulnerable_strcat_append() {
    char greeting[20];
    strcpy(greeting, "Hello, ");
    // VULNERABILITY: appending string exceeds remaining buffer capacity (20 - 7 = 13 bytes left)
    // CERT Rule: STR31-C / CWE-120
    strcat(greeting, "Honorable Administrator of Enterprise Systems!");
    printf("Greeting: %s\n", greeting);
}

// Pattern 4: Stack buffer overflow via unbounded sprintf()
void vulnerable_sprintf_formatter(int user_id, const char* session_token) {
    char header_buffer[32];
    // VULNERABILITY: sprintf lacks output bounds checking
    // CERT Rule: STR31-C / CWE-120
    sprintf(header_buffer, "X-Auth-Token: %s; UserID=%d; ExtraData=ExtendedMetadata", session_token, user_id);
    printf("Header: %s\n", header_buffer);
}

// Pattern 5: AST / CodeQL Static Out-of-bounds Array Subscript
void static_array_bounds_overflow() {
    int table[10];
    for (int i = 0; i < 10; ++i) {
        table[i] = i * 10;
    }

    // VULNERABILITY: Index [10] and [15] are strictly out of bounds for array of size 10 [0..9]
    // CERT Rule: ARR30-C / CWE-120 / CWE-121
    table[10] = 999;
    table[15] = 1234;
    printf("Table[10] = %d\n", table[10]);
}

// Pattern 6: Nested local array overruns in struct records
struct PacketFrame {
    char packet_id[8];
    char payload[16];
};

void struct_buffer_overflow() {
    PacketFrame frame;
    // Overflows 8-byte buffer, corrupting payload and frame pointers
    strcpy(frame.packet_id, "PACKET_HEADER_OVERFLOW_STRING");
    printf("Packet: %s\n", frame.packet_id);
}

int main(int argc, char** argv) {
    printf("=== Running Comprehensive Buffer Overflow Test Suite ===\n");
    vulnerable_gets_reader();
    vulnerable_strcpy_copy();
    vulnerable_strcat_append();
    vulnerable_sprintf_formatter(1337, "ABCD-EFGH-IJKL-MNOP-QRST");
    static_array_bounds_overflow();
    struct_buffer_overflow();
    return 0;
}
