#include <unistd.h>

int main(int argc, char** argv) {
    char* args[] = {(char*)"/bin/ls", nullptr};
    execvp("/bin/ls", args);
    return 0;
}
