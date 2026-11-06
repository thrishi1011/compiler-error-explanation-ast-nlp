# Comprehensive Test Suite (`cases/`)

This directory contains **12 consolidated, comprehensive test cases** designed to benchmark and verify all components of the C++ Compiler Error Explanation and Security Analysis system:

1. **Compiler Diagnostics & Syntax Parsing (`compiler_runner.py`, `error_parser.py`)**
2. **AST Extraction & CodeQL Semantic Checking (`ast_extractor.py`, `ast_security_rules.py`)**
3. **MITRE CWE Weakness Taxonomy & SEI CERT C++ Rules (`security_analyzer.py`)**
4. **Automated Security Healing Engine (`security_healer.py`)**
5. **AI Explainer Prompting & NLP Enrichment (`ai_explainer.py`, `error_explainer.py`)**
6. **Guard Supervisor & Adversarial Defenses (`guard/supervisor.py`, `guard/vuln_guard.py`)**

Instead of hundreds of tiny fragmented snippets, each case file is a **lengthy, multi-function real-world source file** containing multiple interacting scenarios, edge cases, and rich annotations.

---

## Catalog of Test Cases

| Case File | Category | Key Compiler Errors / CWEs / CERT Rules | Key Verifications |
|:---|:---|:---|:---|
| [`case01_syntax_and_grammar_errors.cpp`](case01_syntax_and_grammar_errors.cpp) | Syntax & Grammar | Missing `;`, unclosed `}`, mismatched `()`, misspelled keywords (`retun`, `whle`) | Tokenization, parser error recovery, line/column tracking |
| [`case02_type_system_and_conversions.cpp`](case02_type_system_and_conversions.cpp) | Semantic & Type System | Const-correctness violations, narrowing conversions, pointer incompatibility, missing returns | Type checking diagnostics, static_cast semantics, NLP explanations |
| [`case03_undefined_symbols_and_missing_headers.cpp`](case03_undefined_symbols_and_missing_headers.cpp) | Name Resolution | Missing `<iostream>`, `<vector>`, `<string>`, `<algorithm>`, undeclared symbols | Suggestion engine for missing includes and `std::` qualifiers |
| [`case04_cwe120_cwe121_buffer_overflow_comprehensive.cpp`](case04_cwe120_cwe121_buffer_overflow_comprehensive.cpp) | Buffer Overflows | **CWE-120**, **CWE-121**, **CWE-676**, **CERT ARR30-C**, **CERT STR31-C** | `gets()`, `strcpy()`, `strcat()`, `sprintf()`, constant array overruns |
| [`case05_cwe134_format_string_attacks.cpp`](case05_cwe134_format_string_attacks.cpp) | Format String Defect | **CWE-134**, **CERT FIO30-C**, **CAPEC-135** | `printf(user_str)`, `fprintf(stderr, msg)`, `%s` auto-healing recipe |
| [`case06_cwe476_null_pointer_and_dangling.cpp`](case06_cwe476_null_pointer_and_dangling.cpp) | Pointer & Lifetimes | **CWE-476**, **CERT EXP34-C**, **CERT DCL30-C**, **CAPEC-129** | Immediate `nullptr` dereference, returning address of local stack variable |
| [`case07_cwe415_cwe416_memory_lifecycle.cpp`](case07_cwe415_cwe416_memory_lifecycle.cpp) | Memory Lifecycle | **CWE-415**, **CWE-416**, **CWE-401**, **CERT MEM30-C**, **CERT MEM51-CPP** | Double free, use-after-free, memory leaks, RAII smart pointer recommendations |
| [`case08_cwe190_integer_and_conversions.cpp`](case08_cwe190_integer_and_conversions.cpp) | Arithmetic Anomalies | **CWE-190**, **CWE-191**, **CWE-369**, **CERT INT30-C**, **CERT INT32-C** | Signed overflow (UB), unsigned wraparound, division by zero, signed/unsigned bypass |
| [`case09_cwe78_process_and_cmd_injection.cpp`](case09_cwe78_process_and_cmd_injection.cpp) | Command Injection | **CWE-78**, **CERT ENV33-C**, **CAPEC-88** | `system(cmd)` string concatenation, `popen()` piping, metacharacter validation |
| [`case10_ast_macro_evasion.cpp`](case10_ast_macro_evasion.cpp) | Preprocessor Evasion | **CWE-120**, **CWE-676**, **CWE-78**, **CERT PRE31-C** | Macro aliasing (`#define READ gets`), nested structs, AST CodeQL rules |
| [`case11_clean_and_complex_cpp17.cpp`](case11_clean_and_complex_cpp17.cpp) | Clean Baseline | **0 Errors, 0 Warnings, 0 CWEs** | False-positive benchmark; clean AST rendering of templates & lambdas |
| [`case12_host_guard_evasion_attempts.cpp`](case12_host_guard_evasion_attempts.cpp) | Adversarial Guard Defenses | **CAPEC-242**, **CAPEC-664**, **CWE-120**, **CWE-78** | Prompt injection inside comments, supervisor detection, red-team simulation |

---

## How to Test

### 1. Test Single Case via CLI
Run any case directly through `src/main.py`:
```powershell
# Analyze buffer overflows with full CWE and CERT annotations:
python src/main.py cases/case04_cwe120_cwe121_buffer_overflow_comprehensive.cpp

# Analyze format strings with verbose context:
python src/main.py -v cases/case05_cwe134_format_string_attacks.cpp

# Run adversarial simulation on guard evasion attempt:
python src/main.py --simulate-adversarial prompt_injection cases/case12_host_guard_evasion_attempts.cpp
```

### 2. Export Findings to SARIF (for VS Code / GitHub Security)
```powershell
python -c "import sys; sys.path.insert(0, 'src'); from security_analyzer import analyze, save_sarif; findings = analyze('cases/case04_cwe120_cwe121_buffer_overflow_comprehensive.cpp'); save_sarif(findings, 'case04.sarif'); print('SARIF saved with', len(findings), 'findings')"
```

### 3. Run Automated Benchmark Across All Cases
Run the automated batch test runner:
```powershell
python cases/run_all_cases.py
```
