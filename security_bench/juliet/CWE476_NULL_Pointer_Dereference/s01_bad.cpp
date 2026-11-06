/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: NULL pointer dereference
 */
#include <cstdio>

void CWE476_NULL_Pointer_Dereference__bad() {
    int *data = NULL;
    /* FLAW: dereference without null check */
    *data = 5;
    printf("%d\n", *data);
}

int main() {
    CWE476_NULL_Pointer_Dereference__bad();
    return 0;
}
