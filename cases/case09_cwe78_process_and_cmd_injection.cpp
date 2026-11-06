/**
 * ==============================================================================
 * Test Case 09: Command Injection & Subprocess Execution (CWE-78, CERT ENV33-C)
 * ==============================================================================
 * Standards & Taxonomy Mappings:
 *   - MITRE CWE-78: Improper Neutralization of Special Elements used in an OS Command
 *   - SEI CERT ENV33-C: Do not call system() with untrusted or non-constant strings
 *   - MITRE CAPEC-88: OS Command Injection
 *   - CodeQL Pattern: cpp/command-line-injection
 *
 * Target Analyzer Checks & Automated Healer Recipes:
 *   1. Recipe 'replace_system': flags system() and recommends safe execve / subprocess API
 *   2. Detection of popen() with concatenated string arguments
 *   3. AI Explainer: Explains shell metacharacters (; & | ` $) and privilege escalation
 * ==============================================================================
 */

#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

// Pattern 1: Direct system() call with user-controlled string parameter
void vulnerable_ping_host(const std::string& user_hostname) {
    // VULNERABILITY: If user_hostname is "127.0.0.1; rm -rf /" or "localhost & calc.exe",
    // the system shell executes arbitrary injected commands with program privileges.
    // CERT Rule: ENV33-C / CWE-78 / CAPEC-88
    std::string command = "ping -c 1 " + user_hostname;
    std::cout << "[*] Executing system command: " << command << std::endl;
    system(command.c_str());
}

// Pattern 2: C-style popen pipe with sprintf-assembled command
void vulnerable_file_viewer(const char* filename) {
    char shell_cmd[256];
    // VULNERABILITY: Unvalidated filename passed into shell pipe
    // CERT Rule: ENV33-C / CWE-78
    snprintf(shell_cmd, sizeof(shell_cmd), "cat %s", filename);
    std::cout << "[*] Opening pipe: " << shell_cmd << std::endl;

    FILE* pipe = popen(shell_cmd, "r");
    if (pipe) {
        char output[128];
        while (fgets(output, sizeof(output), pipe) != nullptr) {
            std::cout << output;
        }
        pclose(pipe);
    }
}

// Pattern 3: Environment variable execution without sanitization
void vulnerable_env_command_launcher() {
    const char* user_editor = getenv("USER_EDITOR");
    if (user_editor) {
        // VULNERABILITY: User-controlled environment variable directly executed
        system(user_editor);
    }
}

// Pattern 4: Compliant parameter-validated approach
bool is_valid_alphanumeric_filename(const std::string& name) {
    if (name.empty() || name.length() > 64) return false;
    for (char ch : name) {
        if (!isalnum(ch) && ch != '.' && ch != '_' && ch != '-') {
            return false; // Reject any shell metacharacter
        }
    }
    return true;
}

void compliant_file_viewer(const std::string& safe_filename) {
    // COMPLIANT: Whitelist validation prevents metacharacter injection
    if (!is_valid_alphanumeric_filename(safe_filename)) {
        std::cerr << "[-] Error: Rejected invalid filename containing illegal characters.\n";
        return;
    }
    std::cout << "[+] Compliant execution for validated resource: " << safe_filename << std::endl;
}

int main(int argc, char** argv) {
    std::cout << "=== Running CWE-78 OS Command Injection Suite ===\n";

    // Benign simulation of malicious inputs:
    std::string malicious_host = "127.0.0.1 && echo Injected-Payload";
    vulnerable_ping_host("127.0.0.1");

    vulnerable_file_viewer("config.txt; id");
    compliant_file_viewer("config.txt");
    compliant_file_viewer("config.txt; rm -rf /");

    return 0;
}
