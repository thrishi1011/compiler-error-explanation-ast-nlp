/**
 * ==============================================================================
 * Test Case 07: Dynamic Memory Lifecycle Violations (CWE-415, CWE-416, CWE-401)
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-415: Double Free
 *   - MITRE CWE-416: Use After Free
 *   - MITRE CWE-401: Missing Release of Memory ('Memory Leak')
 *   - SEI CERT MEM30-C: Do not access freed memory
 *   - SEI CERT MEM51-CPP: Properly deallocate dynamically allocated resources
 *   - MITRE CAPEC-129: Pointer Manipulation
 *   - CodeQL Pattern: cpp/double-free, cpp/use-after-free
 *
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Recipe 'free_to_null': sets pointer to nullptr after free()
 *   2. Recipe 'delete_to_null': sets pointer to nullptr after delete
 *   3. AST / CodeQL Rules: Detects duplicate free() on identical identifier
 *   4. AST / CodeQL Rules: Detects dereference or member access after free/delete
 * ==============================================================================
 */

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <memory>

struct DataPacket {
    int header_id;
    char payload[64];

    void process() {
        std::cout << "Processing Packet ID: " << header_id << std::endl;
    }
};

// Pattern 1: Classic Double Free on heap pointer (CWE-415)
void vulnerable_c_double_free() {
    char* dynamic_buffer = (char*)malloc(128);
    if (!dynamic_buffer) return;
    strcpy(dynamic_buffer, "Secret session authentication key");

    std::cout << "Releasing dynamic buffer...\n";
    // First free
    free(dynamic_buffer);

    // Some intermediate processing logic
    std::cout << "Performing unrelated operations...\n";

    // VULNERABILITY: Second free on already deallocated pointer
    // Corrupts heap metadata / bins, allowing arbitrary write primitives
    // CERT Rule: MEM30-C / MEM51-CPP / CWE-415
    free(dynamic_buffer);
}

// Pattern 2: Use-After-Free (CWE-416) via C-style free()
void vulnerable_c_use_after_free() {
    char* token = (char*)malloc(32);
    if (!token) return;
    strcpy(token, "AUTH_TOKEN_ACTIVE");

    free(token);

    // VULNERABILITY: Reading or writing to pointer after free()
    // Memory may have been reallocated to another subsystem
    // CERT Rule: MEM30-C / CWE-416
    std::cout << "Reading token after free: " << token << std::endl;
    token[0] = 'X';
}

// Pattern 3: C++ delete Double Free and Use-After-Free on objects
void vulnerable_cpp_double_delete() {
    DataPacket* pkt = new DataPacket{101, "Telemetry payload"};
    pkt->process();

    delete pkt;

    // VULNERABILITY: Method invocation on deleted object (CWE-416)
    pkt->process();

    // VULNERABILITY: Second delete on deleted object (CWE-415)
    delete pkt;
}

// Pattern 4: Unbounded Memory Leak (CWE-401)
void memory_leak_producer(int iterations) {
    for (int i = 0; i < iterations; ++i) {
        // VULNERABILITY: malloc without corresponding free() causes resource exhaustion
        char* leak = (char*)malloc(1024 * 64);
        memset(leak, 0x41, 1024 * 64);
    }
}

// Pattern 5: Compliant RAII Management (SEI CERT MEM51-CPP compliant)
void compliant_raii_safe() {
    // COMPLIANT: std::unique_ptr automatically destroys and deallocates upon exiting scope
    auto safe_packet = std::make_unique<DataPacket>();
    safe_packet->header_id = 202;
    strcpy(safe_packet->payload, "Compliant RAII Payload");
    safe_packet->process();

    // Raw pointer defensive reset
    char* manual_buf = (char*)malloc(64);
    if (manual_buf) {
        free(manual_buf);
        manual_buf = nullptr; // Prevents use-after-free and double-free
    }
}

int main(int argc, char** argv) {
    std::cout << "=== Running Memory Lifecycle (CWE-415 / CWE-416) Suite ===\n";
    compliant_raii_safe();
    vulnerable_c_use_after_free();
    vulnerable_c_double_free();
    vulnerable_cpp_double_delete();
    memory_leak_producer(10);
    return 0;
}
