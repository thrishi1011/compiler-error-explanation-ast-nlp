/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: Use After Free
 */
#include <cstdio>
#include <cstdlib>

void CWE416_Use_After_Free__bad() {
    int *data = (int *)malloc(100 * sizeof(int));
    if (data == NULL) return;
    free(data);
    /* FLAW: accessing pointer after free */
    printf("%d\n", data[0]);
}

int main() {
    CWE416_Use_After_Free__bad();
    return 0;
}
