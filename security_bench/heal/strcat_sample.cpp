#include <cstdio>
#include <cstring>

void concat_data(const char* s) {
    char d[64] = "prefix: ";
    strcat(d, s);
    printf("%s\n", d);
}

int main() {
    concat_data("test");
    return 0;
}
