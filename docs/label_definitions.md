# Compiler Error Category Label Definitions

This document defines the formal ground-truth boundaries for the 9 error categories used in the **Green Self-Healing Compiler** offline classifier (`src/error_classifier.py`).

---

## 1. Canonical Taxonomy & Operational Rules

| Category | Operational Definition | Typical GCC Diagnostic Patterns |
|---|---|---|
| **`syntax_error`** | Structural token or grammar parsing failures. The compiler could not form a valid parse tree. | `expected ';' before ...`, `expected '}' at end of input`, `expected ')'`, `expected primary-expression`, `stray '\...' in program`, `missing terminating " character`, `unterminated comment` |
| **`name_resolution`** | An identifier, user-defined type, or member was referenced but not found in any visible scope or namespace. (Excludes standard library symbols mapped to missing headers; see boundary rule below). | `'x' was not declared in this scope`, `'MyClass' does not name a type`, `'field' is not a member of 'Struct'`, `use of undeclared identifier` |
| **`missing_include`** | An explicit `#include` directive failed to find a file, OR an undeclared symbol is an established C++ standard library symbol whose required header is listed in `auto_healer._SYMBOL_TO_HEADER`. | `fatal error: ...: No such file or directory`, `#include expects "FILENAME" or <FILENAME>`, `'cout' was not declared in this scope` (symbol in `_SYMBOL_TO_HEADER`), `'vector' was not declared in this scope`, `did you forget to '#include <...>'?` |
| **`type_error`** | Type mismatch during assignment, initialization, arithmetic, or function invocation. Value cannot be converted or no overload matches. | `cannot convert '...' to '...'`, `invalid operands of types ... to binary ...`, `no matching function for call to ...`, `too few arguments to function ...`, `too many arguments to function ...`, `subscripted value is not an array`, `invalid use of void` |
| **`return_type_error`** | Violation of function return semantics: missing return value in non-void function, returning a value from void function, wrong return type, or improper `main()` return type. | `control reaches end of non-void function [-Wreturn-type]`, `no return statement in function returning non-void`, `return-type defaults to 'int'`, `return with a value, in function returning void`, `return with no value, in function returning '...'`, `'main' must return 'int'` |
| **`redefinition`** | An identifier, variable, struct, or function is defined more than once in the same scope or across compilation units. | `redefinition of '...'`, `redeclaration of '...' with no linkage`, `conflicting declaration '...'`, `multiple definition of '...'` |
| **`access_error`** | Access control violation (private or protected members), const-correctness violation (modifying read-only locations), or discarding cv-qualifiers. | `'...' is private within this context`, `'...' is protected within this context`, `assignment of read-only variable '...'`, `assignment of read-only location`, `passing 'const ...' as 'this' argument discards qualifiers` |
| **`linker_error`** | Link-time diagnostic where declared symbols or libraries cannot be resolved by `ld` / `collect2`. | `undefined reference to '...'`, `collect2: error: ld returned 1 exit status`, `cannot find -l...`, `symbol(s) not found for architecture ...` |
| **`other`** | Legitimate non-standard warnings or compiler messages that do not belong to the above 8 categories. **Must NOT be used as a lazy catch-all for unparsed errors.** | `[-Wsign-compare]`, `[-Wparentheses]`, `[-Wunused-variable]`, `[-Wdeprecated]`, `division by zero`, `narrowing conversion` |

---

## 2. Boundary Rule: `missing_include` vs. `name_resolution`

### The Problem
GCC 6.3 emits the exact same diagnostic text for an undeclared user variable and a missing standard library header:
* User forgot `int count;`: `'count' was not declared in this scope`
* User forgot `#include <iostream>`: `'cout' was not declared in this scope`

Without looking at the source code, the string alone is identical in structure.

### The Standardized Operational Rule
To eliminate ambiguity across mutation generation, dataset relabeling, and gold evaluation:
1. Extract the primary symbol quoted in the diagnostic (`'([a-zA-Z_][a-zA-Z0-9_:]*)'`).
2. If the symbol (or its leaf identifier after stripping namespaces) exists in `auto_healer._SYMBOL_TO_HEADER` (e.g., `cout`, `cin`, `endl`, `vector`, `string`, `map`, `sort`, `sqrt`, `max`, `min`):
   $$\text{Category} = \mathbf{missing\_include}$$
3. If the diagnostic explicitly states `No such file or directory` or contains `did you forget to '#include`:
   $$\text{Category} = \mathbf{missing\_include}$$
4. Otherwise (for all custom names, user identifiers, misspelled variables, typos):
   $$\text{Category} = \mathbf{name\_resolution}$$

This rule is applied identically during mutation generation, training set relabeling, and gold set evaluation.

---

## 3. Boundary Rule: `access_error` vs. `type_error`

* Assigning to a `const` variable (`assignment of read-only variable 'x'`) restricts write access to memory marked immutable. It is categorized strictly as **`access_error`** (consistent with access control and the 23-file benchmark `const_assignment.cpp`).
* Incompatible type casting (`invalid conversion from 'int' to 'char*'`) remains **`type_error`**.

---

## 4. `other` Category Discipline
In legacy datasets (e.g. CodeNet 67k), 38% of all rows were dumped into `other` because rule matchers failed. 
In Dataset V2:
* Real errors (e.g. `lvalue required as unary operand`, `default statement not in switch`, `implicit declaration`) are re-classified into `type_error`, `syntax_error`, or `name_resolution`.
* `other` is reserved solely for miscellaneous compiler warnings (e.g. signed/unsigned comparison warnings, parentheses precedence warnings).
