/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Good: Checked integer increment
 */
#include <cstdio>
#include <climits>

void CWE190_Integer_Overflow__good() {
    int data = INT_MAX;
    /* FIX: check before increment */
    if (data < INT_MAX) {
        data++;
        printf("%d\n", data);
    } else {
        printf("Increment guarded against overflow.\n");
    }
}

int main() {
    CWE190_Integer_Overflow__good();
    return 0;
}
