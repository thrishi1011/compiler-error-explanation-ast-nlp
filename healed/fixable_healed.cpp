#include <cstdio>
#include <cstdlib>
#include <cstring>

void process_data(const char* src, const char* user_text) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%s", src);

    char name[32];
    scanf("%31s", name);

    printf("%s", user_text);

    int* p = new int(42);
    delete p;
    p = nullptr;
    delete p;

    int total = 0;
    total = total + 5;

    char* tmp = (char*)malloc(64);
    if (tmp) {
        snprintf(tmp, 64, "%s", "data");
        printf("%s\n", tmp);
    }
    free(tmp);
}

int main() {
    process_data("hello", "message\n");
    return 0;
}
