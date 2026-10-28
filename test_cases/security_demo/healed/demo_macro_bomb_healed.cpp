#define M1 "xxxx"
#define M2 M1 M1 M1 M1
#define M3 M2 M2 M2 M2
#define M4 M3 M3 M3 M3
#define M5 M4 M4 M4 M4
#define M6 M5 M5 M5 M5
#define M7 M6 M6 M6 M6
#define M8 M1

int main() {
    const char* p = M8;
    (void)p;
    return 0;
}