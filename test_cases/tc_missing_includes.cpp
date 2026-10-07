// Test: Missing include for commonly used functions
// Expected: error: 'sort' was not declared in this scope
//           error: 'printf' was not declared in this scope

// Missing: #include <algorithm>  for sort()
// Missing: #include <cstdio>     for printf()
// Missing: #include <cstring>    for strlen()
#include <vector>
using namespace std;

int main() {
    vector<int> v = {5, 1, 4, 2, 3};
    sort(v.begin(), v.end());       // ERROR: needs #include <algorithm>
    
    printf("Sorted!\n");            // ERROR: needs #include <cstdio>
    
    const char* s = "hello";
    int len = strlen(s);            // ERROR: needs #include <cstring>
    printf("Length: %d\n", len);
    return 0;
}
