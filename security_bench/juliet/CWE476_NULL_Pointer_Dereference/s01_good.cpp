/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Null pointer check before dereference
 */
#include <cstdio>

void CWE476_NULL_Pointer_Dereference__good() {
    int *data = NULL;
    /* FIX: check before dereference */
    if (data != NULL) {
        *data = 5;
        printf("%d\n", *data);
    } else {
        printf("Pointer was NULL, handled safely.\n");
    }
}

int main() {
    CWE476_NULL_Pointer_Dereference__good();
    return 0;
}
