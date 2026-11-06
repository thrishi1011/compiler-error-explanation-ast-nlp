/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: Stack-based buffer overflow via gets()
 */
#include <cstdio>
#include <cstdlib>

void CWE121_Stack_Based_Buffer_Overflow__gets_bad() {
    char dataBuffer[16];
    char *data = dataBuffer;
    /* FLAW: gets does not check boundary */
    gets(data);
    printf("%s\n", data);
}

int main() {
    CWE121_Stack_Based_Buffer_Overflow__gets_bad();
    return 0;
}
