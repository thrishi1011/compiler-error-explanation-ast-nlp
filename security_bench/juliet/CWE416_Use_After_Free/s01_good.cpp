/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Access before free or proper lifecycle
 */
#include <cstdio>
#include <cstdlib>

void CWE416_Use_After_Free__good() {
    int *data = (int *)malloc(100 * sizeof(int));
    if (data == NULL) return;
    data[0] = 42;
    /* FIX: access before free */
    printf("%d\n", data[0]);
    free(data);
    data = NULL;
}

int main() {
    CWE416_Use_After_Free__good();
    return 0;
}
