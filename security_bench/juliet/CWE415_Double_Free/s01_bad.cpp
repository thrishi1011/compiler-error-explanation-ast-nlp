/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: Double Free
 */
#include <cstdio>
#include <cstdlib>

void CWE415_Double_Free__bad() {
    int *data = (int *)malloc(100 * sizeof(int));
    if (data == NULL) return;
    free(data);
    /* FLAW: deallocating pointer twice */
    free(data);
}

int main() {
    CWE415_Double_Free__bad();
    return 0;
}
