#include <iostream>
#include <string>
#include <vector>
using namespace std;

// ── Forward declarations ──────────────────────────────────────────────────
int add(int a, int b);
int divide(int a, int b);
void printNumbers();
int calculate(int x);
void processInput();
void checkValue();
void printMessage();
void arrayOps();
void stringOps();
void loopOps();

// ── Utilities ─────────────────────────────────────────────────────────────

int multiply(int a, int b) {
  int result = a * b;
  if (result > 10000) {
    cout << "Large result: " << result << "\n";
  }
  return result;
}

int modulo(int a, int b) {
  if (b == 0)
    return 0;
  return a % b;
}

void printHeader(string title) {
  cout << "=== " << title << " ===\n";
}

bool isEven(int n) { return n % 2 == 0; }

bool isPositive(int n) { return n > 0; }

// ── Error 1: Missing semicolon ────────────────────────────────────────────

int add(int a, int b) {
  int temp = a + b;
  if (temp > 100) {
    cout << "Sum is large\n";
  }
  return a + b;
}

// ── Error 2: Division by zero ─────────────────────────────────────────────

int divide(int a, int b) {
  int backup = a;
  cout << "Dividing " << a << " by " << b << "\n";
  cout << a / b << "\n";
  return a / b;
}

// ── Error 3: Misspelled keyword ───────────────────────────────────────────

void printNumbers() {
  int i = 1;
  int total = 0;
  while(i <= 5) {
    total += i;
    cout << "Number: " << i << "\n";
    i++;
  }
  cout << "Total: " << total << "\n";
}

// ── Error 4: Integer overflow + uninitialized variable ────────────────────

int calculate(int x) {
  int big = 2147483647;
  big = big + 1;
  int uninit = 7;
  int factor = 3;
  cout << uninit << "\n";
  int local = x * factor;
  if (local > 50) {
    cout << "Large calculation: " << local << "\n";
  }
  return big + x;
}

// ── Error 5: Wrong stream operator ───────────────────────────────────────

void processInput() {
  int y = 20;
  int z = 30;
  cout << "Enter a number: \n";
  cin >> y;
  cout << "You entered: " << y << "\n";
  cout << "Double: " << y * 2 << "\n";
  z = y + 10;
  cout << "Z is: " << z << "\n";
}

// ── Error 6: Redefinition + assignment in condition ───────────────────────

void checkValue() {
  int x = 10;
  int total = 0;
  x = 99;
  total = x + total;
  if (x = 50) {
    cout << "x is 50\n";
    total += x;
  }
  for (int i = 0; i < 3; i++) {
    total += multiply(x, i);
  }
  cout << "Total: " << total << "\n";
}

// ── Error 7: Missing closing brace ───────────────────────────────────────

void printMessage() {
  int y = 20;
  int count = 0;
  for (int i = 0; i < 5; i++) {
    count += i;
  }
  if (y > 10) {
    cout << "y is big: " << y << "\n";
    count++;
  }

  // ── Array operations ──────────────────────────────────────────────────────

}
  void arrayOps() {
    int arr[5] = {1, 2, 3, 4, 5};
    int sum = 0;
    for (int i = 0; i < 5; i++) {
      sum += arr[i];
      if (isEven(arr[i])) {
        cout << arr[i] << " is even\n";
      }
    }
    cout << "Array sum: " << sum << "\n";
  }

  // ── String operations ─────────────────────────────────────────────────────

  void stringOps() {
    string name = "compiler";
    string upper = "";
    for (char c : name) {
      upper += (c - 32);
    }
    cout << "Upper: " << upper << "\n";
    cout << "Length: " << name.length() << "\n";
  }

  // ── Loop operations ───────────────────────────────────────────────────────

  void loopOps() {
    int sum = 0;
    for (int i = 1; i <= 10; i++) {
      sum += i;
    }
    cout << "Loop sum: " << sum << "\n";

    int j = 10;
    while (j > 0) {
      if (isPositive(j)) {
        cout << j << " ";
      }
      j -= 2;
    }
    cout << "\n";
  }

  // ── Error 8: Undeclared variable ──────────────────────────────────────────

  int main() {
    printHeader("Self Healing Compiler Test");

    auto w = 999;

    int a = 10;
    int b = 0;

    printHeader("Division");
    divide(a, b);

    printHeader("Numbers");
    printNumbers();

    printHeader("Calculate");
    int res = calculate(5);
    cout << "Result: " << res << "\n";

    printHeader("Input");
    processInput();

    printHeader("Check");
    checkValue();

    printHeader("Message");
    printMessage();

    printHeader("Array");
    arrayOps();

    printHeader("String");
    stringOps();

    printHeader("Loop");
    loopOps();

    cout << "Add: " << add(3, 4) << "\n";
    cout << "Multiply: " << multiply(6, 7) << "\n";
    cout << "Modulo: " << modulo(10, 3) << "\n";

    return 0;
  }