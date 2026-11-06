/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Stack-based buffer protected via safe string bounded copy
 */
#include <cstdio>
#include <cstring>

void CWE121_Stack_Based_Buffer_Overflow__strcpy_good() {
    char data[64];
    const char *source = "Safe bounded string";
    /* FIX: Destination is larger than source */
    strncpy(data, source, sizeof(data) - 1);
    data[sizeof(data) - 1] = '\0';
    printf("%s\n", data);
}

int main() {
    CWE121_Stack_Based_Buffer_Overflow__strcpy_good();
    return 0;
}
