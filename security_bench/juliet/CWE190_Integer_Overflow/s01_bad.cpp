/* TEMPLATE GENERATED TESTCASE FILE (NIST SARD Juliet C/C++ Test Suite)
 * Flaw: Integer Overflow
 */
#include <cstdio>
#include <climits>

void CWE190_Integer_Overflow__bad() {
    int data = INT_MAX;
    /* FLAW: increment causes signed overflow */
    data++;
    printf("%d\n", data);
}

int main() {
    CWE190_Integer_Overflow__bad();
    return 0;
}
