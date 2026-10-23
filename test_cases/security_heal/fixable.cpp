#include <cstdio>
#include <cstdlib>
#include <cstring>

void process_data(const char* src, const char* user_text) {
    char buf[16];
    strcpy(buf, src);

    char name[32];
    scanf("%s", name);

    printf(user_text);

    int* p = new int(42);
    delete p;
    delete p;

    int total;
    total = total + 5;

    char* tmp = (char*)malloc(64);
    if (tmp) {
        snprintf(tmp, 64, "%s", "data");
        printf("%s\n", tmp);
    }
}

int main() {
    process_data("hello", "message\n");
    return 0;
}
