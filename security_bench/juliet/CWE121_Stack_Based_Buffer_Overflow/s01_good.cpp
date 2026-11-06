/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Stack-based buffer protected via fgets()
 */
#include <cstdio>
#include <cstdlib>

void CWE121_Stack_Based_Buffer_Overflow__fgets_good() {
    char dataBuffer[16];
    char *data = dataBuffer;
    /* FIX: Use fgets with sizeof bounds check */
    if (fgets(data, sizeof(dataBuffer), stdin) != NULL) {
        printf("%s\n", data);
    }
}

int main() {
    CWE121_Stack_Based_Buffer_Overflow__fgets_good();
    return 0;
}
