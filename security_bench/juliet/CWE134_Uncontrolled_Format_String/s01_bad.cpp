/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: Format string vulnerability
 */
#include <cstdio>

void CWE134_Uncontrolled_Format_String__bad(char *userInput) {
    /* FLAW: non-literal format string passed to printf */
    printf(userInput);
}

int main() {
    char data[] = "Hello %s %s %x";
    CWE134_Uncontrolled_Format_String__bad(data);
    return 0;
}
