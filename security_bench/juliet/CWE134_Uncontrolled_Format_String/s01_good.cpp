/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Fixed format specifier
 */
#include <cstdio>

void CWE134_Uncontrolled_Format_String__good(char *userInput) {
    /* FIX: fixed format specifier */
    printf("%s\n", userInput);
}

int main() {
    char data[] = "Hello world";
    CWE134_Uncontrolled_Format_String__good(data);
    return 0;
}
