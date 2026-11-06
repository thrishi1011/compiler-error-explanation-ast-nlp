/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: Stack-based buffer overflow via strcpy()
 */
#include <cstdio>
#include <cstring>

void CWE121_Stack_Based_Buffer_Overflow__strcpy_bad() {
    char data[10];
    const char *source = "This string is definitely longer than ten bytes";
    /* FLAW: unbounded copy into fixed buffer */
    strcpy(data, source);
    printf("%s\n", data);
}

int main() {
    CWE121_Stack_Based_Buffer_Overflow__strcpy_bad();
    return 0;
}
