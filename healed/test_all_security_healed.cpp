
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
using namespace std;

// ─────────────────────────────────────────────────────────────
// CRITICAL: Buffer Overflow — gets() has no bounds checking
// ─────────────────────────────────────────────────────────────
void trigger_gets_overflow() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';
    printf("Input: %s\n", buf);
}

// ─────────────────────────────────────────────────────────────
// HIGH: Unsafe String Functions — strcpy / strcat / sprintf
// ─────────────────────────────────────────────────────────────
void trigger_unsafe_string_functions(const char* user_input) {
    char dest[64];
    snprintf(dest, sizeof(dest), "%s", user_input);
    strncat(dest, "_suffix", sizeof(dest) - strlen(dest) - 1);
    char out[128];
    snprintf(out, sizeof(out), "%s", dest);
}

// ─────────────────────────────────────────────────────────────
// HIGH: Unbounded Input — scanf with %s and no width
// ─────────────────────────────────────────────────────────────
void trigger_unbounded_scanf() {
    char username[32];
    scanf("%31s", username);
}

// ─────────────────────────────────────────────────────────────
// HIGH: Command Injection — system_fn() with shell execution
// ─────────────────────────────────────────────────────────────
void trigger_command_injection(const char* cmd) {
    // [Unsafe system call neutralized for security]
}

// ─────────────────────────────────────────────────────────────
// HIGH: Weak Randomness — rand() used near secret/token/key
// ─────────────────────────────────────────────────────────────
void trigger_weak_randomness() {
    int secret = rand();             // [HIGH] Weak Randomness — 'secret' on same line
    int token  = rand();             // [HIGH] Weak Randomness — 'token' on same line
    int key    = rand();             // [HIGH] Weak Randomness — 'key' on same line
    (void)secret; (void)token; (void)key;
}

// ─────────────────────────────────────────────────────────────
// HIGH: Double Free — deleting same pointer twice
// ─────────────────────────────────────────────────────────────
void trigger_double_free() {
    int* p = new int(42);
    delete p;                        // first free
    p = nullptr;
    delete p;                        // [HIGH] Double Free
}

// ─────────────────────────────────────────────────────────────
// HIGH: Use After Free — using pointer after delete
// ─────────────────────────────────────────────────────────────
void trigger_use_after_free() {
    int* q = new int(99);
    *q = 7;                          // [HIGH] Use After Free
    delete q;                        // freed here
}

// ─────────────────────────────────────────────────────────────
// HIGH: Integer Overflow — arithmetic on size/count/len values
// ─────────────────────────────────────────────────────────────
void trigger_integer_overflow(int count) {
    // Multiplication of count * large constant may overflow before malloc
    size_t alloc_size = static_cast<size_t>(count) * 1024;          // [HIGH] Integer Overflow
    void*  mem        = malloc(alloc_size);    // [MEDIUM] potential leak below
    (void)mem;
    // intentionally no free() → Memory Leak below
    free(mem);
}

// ─────────────────────────────────────────────────────────────
// MEDIUM: Unsafe Memory Copy — memcpy with raw int size
// ─────────────────────────────────────────────────────────────
void trigger_unsafe_memcpy(void* dst, const void* src) {
    memcpy(dst, src, 256);           // [MEDIUM] Unsafe Memory Copy (raw size)
}

// ─────────────────────────────────────────────────────────────
// MEDIUM: Unsafe Pointer Arithmetic
// ─────────────────────────────────────────────────────────────
void trigger_pointer_arithmetic(char* datap) {
    char* cursor = datap;
    cursor++;                        // [MEDIUM] Unsafe Pointer Arithmetic
    *cursor = 'X';
}

// ─────────────────────────────────────────────────────────────
// MEDIUM: Potential Memory Leak — malloc without free in scope
// ─────────────────────────────────────────────────────────────
void trigger_memory_leak() {
    char* bufp = (char*)malloc(128); // [MEDIUM] potential memory leak — no free
    bufp[0] = 'A';
    // function returns without freeing bufp
    free(bufp);
}

// ─────────────────────────────────────────────────────────────
// LOW: Disabled Safety Check — assert() in production path
//      (no #ifdef NDEBUG guard present in this file)
// ─────────────────────────────────────────────────────────────
void trigger_assert(int value) {
    assert(value > 0);               // [LOW] Disabled Safety Check
}

// ─────────────────────────────────────────────────────────────
// LOW: Unresolved Security Debt — TODO near sensitive code
// ─────────────────────────────────────────────────────────────
void trigger_security_debt() {
    char password[64];
    // TODO: add proper password hashing before release  // [LOW] Security Debt
    snprintf(password, sizeof(password), "%s", "hunter2");
}

// ─────────────────────────────────────────────────────────────
// COMPILER DIAGNOSTICS (surfaced at compile time)
// The following patterns produce compiler warnings that the
// analyzer elevates to security findings when you compile.
// ─────────────────────────────────────────────────────────────

// [LOW]    Unused Variable / Dead Code
void trigger_unused_variable() {
    int unused_flag = 1;             // set but never used
    printf("no-op\n");
    (void)unused_flag;               // suppress: remove this line to trigger
}

// [HIGH]   Uninitialized Memory — read before initialization
int trigger_uninitialized() {
    int x = 0;
    return x;                        // [HIGH] may be used uninitialized
}

// [HIGH]   Format String Vulnerability — non-literal format string
void trigger_format_string(char* user_fmt) {
    printf("%s", user_fmt);
}

// [MEDIUM] Signed/Unsigned Mismatch
void trigger_sign_mismatch(int n) {
    unsigned int u = 10;
    if (n < u) {                     // [MEDIUM] signed/unsigned comparison
        printf("less\n");
    }
}

// ─────────────────────────────────────────────────────────────
// Entry point — calls all triggers
// ─────────────────────────────────────────────────────────────
int main() {
    char dummy[256] = {0};

    trigger_gets_overflow();
    trigger_unsafe_string_functions("hello");
    trigger_unbounded_scanf();
    trigger_command_injection("ls");
    trigger_weak_randomness();
    trigger_double_free();
    trigger_use_after_free();
    trigger_integer_overflow(100);
    trigger_unsafe_memcpy(dummy, dummy);
    trigger_pointer_arithmetic(dummy);
    trigger_memory_leak();
    trigger_assert(1);
    trigger_security_debt();
    trigger_unused_variable();
    trigger_uninitialized();
    trigger_format_string(dummy);
    trigger_sign_mismatch(-1);

    return 0;
}
