/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Single deallocation and pointer reset
 */
#include <cstdio>
#include <cstdlib>

void CWE415_Double_Free__good() {
    int *data = (int *)malloc(100 * sizeof(int));
    if (data == NULL) return;
    /* FIX: free once and set to NULL */
    free(data);
    data = NULL;
}

int main() {
    CWE415_Double_Free__good();
    return 0;
}
