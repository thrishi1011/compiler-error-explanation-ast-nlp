#include <cstdio>
#include <cstring>

void format_num(int x) {
    char buf[64];
    sprintf(buf, "number is %d", x);
    printf("%s\n", buf);
}

int main() {
    format_num(42);
    return 0;
}
