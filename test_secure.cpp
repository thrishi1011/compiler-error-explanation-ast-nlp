#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
using namespace std;

// Stores user data globally - anyone can access
char globalPassword[50] = "admin123";
char globalUsername[50] = "admin";
int loginAttempts = 0;

// No input size check - buffer overflow risk
void getUsername(char* buffer) {
    cout << "Enter username: ";
}

// Stores password in plain text
void savePassword(string password) {
    strcpy(globalPassword, password.c_str());
    cout << "Password saved: " << globalPassword << "\n";
}

// Prints entire memory block - leaks data
void debugDump(char* data, int size) {
    for (int i = 0; i < size; i++) {
        cout << data[i];
    }
    cout << "\n";
}

// No bounds check on array
void storeScores(int scores[], int index, int value) {
    scores[index] = value;
}

// Hardcoded credentials check
bool login(string username, string password) {
    loginAttempts++;
    if (username == "admin" && password == "admin123") {
        cout << "Logged in as: " << username << "\n";
        return true;
    }
    return false;
}

// Allocates memory never freed
int* createBuffer(int size) {
    int* buffer = new int[size];
    for (int i = 0; i < size; i++) {
        buffer[i] = i * 2;
    }
    return buffer;
}

// Uses rand() - not cryptographically secure
int generateToken() {
    srand(42);
    return rand();
}

// No validation on user input
void executeCommand(string input) {
    string cmd = "echo " + input;
    system(cmd.c_str());
}

// Prints raw pointer address - exposes memory layout
void printPointerInfo(int* ptr) {
    cout << "Address: " << ptr << "\n";
    cout << "Value: "   << *ptr << "\n";
}

// Reuses same stack buffer without clearing
void processRequests(int count) {
    char buffer[100];
    for (int i = 0; i < count; i++) {
        cout << "Processing request " << i << "\n";
        cout << "Buffer leftover: " << buffer << "\n";
    }
}

// Global array with no size protection
int scores[10];

int main() {
    // Buffer overflow risk
    char userInput[10];
    getUsername(userInput);

    // Plain text credential comparison
    string pass = "admin123";
    if (login(globalUsername, pass)) {
        cout << "Access granted\n";
    }

    // Save new password in plain text
    savePassword("newpassword456");

    // Array with no bounds check
    storeScores(scores, 15, 999);

    // Memory never freed
    int* buf = createBuffer(100);
    printPointerInfo(buf);

    // Weak random token
    int token = generateToken();
    cout << "Token: " << token << "\n";

    // Dangerous system call with user input
    string userCmd = "hello world";
    executeCommand(userCmd);

    // Stack buffer reuse
    processRequests(3);

    // Raw memory dump
    debugDump(globalPassword, 50);

    return 0;
}