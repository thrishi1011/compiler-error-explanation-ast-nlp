#include <cstdio>
#include <cstdlib>
#include <cstring>

void leak_test() {
    char* buf = (char*)malloc(64);
    if (buf) {
        snprintf(buf, 64, "%s", "data");
        printf("%s\n", buf);
    }
    free(buf);
}

int main() {
    leak_test();
    return 0;
}
