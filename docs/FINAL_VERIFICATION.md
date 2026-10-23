# Final Project Verification & Integrity Report

> **Generated Programmatically** from `data/verification_results.json` and active test runs.

- **Overall Status**: **100% PASS** (55/55 stages passed)
- **Total Execution Time**: 369.21 seconds across all test stages
- **Command Ceiling**: All commands completed under strict bounded timeouts (<=300s, max 120s typical)

## 1. Executive Summary: The 3-Hour Hang Diagnosis & Fix

### Root Cause Analysis
During previous test executions, `tests/test_security_docs.py` ran for over 3 hours due to two distinct failure modes:
1. **MiKTeX GUI Prompt Hang**: In `tools/build_report_assets.py`, when invoking `pdflatex` without `--disable-installer` on Windows, MiKTeX spawned a modal graphical dialog requesting manual installation of LaTeX packages. In a headless environment, this blocked CLI execution indefinitely.
2. **Pipe Inheritance Deadlock in `safe_run`**: When child processes launched grandchild worker processes with inherited `stdout`/`stderr` pipes, parent reader threads waited forever for pipe EOF even after the primary child exited. Furthermore, `_kill_process_tree` exited prematurely on dead parents, leaving orphan grandchildren running.

### Applied Fixes
- **MiKTeX Installer Suppression**: Added `--disable-installer -interaction=nonstopmode -halt-on-error` to pdflatex invocations and honored `GUARD_NO_LATEX=1` in tests.
- **Bounded Process Tree Termination in `src/guard/safe_run.py`**: Reader threads in `safe_run` are joined with a bounded 2.0s wait with pipes closed. Process trees are terminated recursively via `taskkill /F /T /PID` on Windows (`os.killpg` elsewhere).
- **Independent Timeout Wrapper `tools/run_limited.py`**: Created a standalone standard-library process runner using temporary file redirection (`DEVNULL` stdin, new process group, recursive tree killing on timeout) enforcing hard execution bounds.
- **Faulthandler Guard**: Added `faulthandler.dump_traceback_later(90, exit=True)` across tests to dump call stacks if any run approaches timeout limits.

## 2. Verification Stage Results Table

| Stage | Description | Command | Timeout | Duration | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Stage 0 | Timeout wrapper self-test (<6s) | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 10s | 1.30s | **PASS** |
| Stage 1 | Environment: python & g++ versions | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 30s | 0.27s | **PASS** |
| Stage 1 | Static: py_compile on all python files | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 0.38s | **PASS** |
| Stage 3 | 3a: parse 6 stored stderr texts | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 30s | 0.41s | **PASS** |
| Stage 3 | 3b: normalize 10 diagnostic messages | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 30s | 0.42s | **PASS** |
| Stage 3 | 3c: classify on fixed list & benchmark | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 300s | 2.14s | **PASS** |
| Stage 3 | 3d: explain on 15 messages (What/Why/How) | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 2.20s | **PASS** |
| Stage 3 | 3e: second opinion & classifier fallback | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 3.19s | **PASS** |
| Stage 3 | 3f: batch explain edge cases & mocked LLM | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 3.28s | **PASS** |
| Stage 3 | 3g: cli JSON & exit codes on 8 files | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 32.89s | **PASS** |
| Stage 3 | 3h: AST extraction & tree parsing | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 30s | 0.75s | **PASS** |
| Stage 4 | 4a: auto_healer.attempt_fix on 12 samples | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 3.17s | **PASS** |
| Stage 4 | 4b: heal_engine.compile_source gate checks | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 1.52s | **PASS** |
| Stage 4 | 4c: heal_until_clean on 12 target files | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 36.59s | **PASS** |
| Stage 4 | 4d: ai_healer edge cases (mocked LLM) | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 2.06s | **PASS** |
| Stage 4 | 4e: security_healer on test cases | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 8.94s | **PASS** |
| Stage 4 | 4f: backup creation & undo restoration | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 6.76s | **PASS** |
| Stage 4 | 4g: termination with unfixable warning | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 30s | 5.25s | **PASS** |
| Stage 5 | Phase 1: family dangerous_execution | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 0.81s | **PASS** |
| Stage 5 | Phase 2: family resource_exhaustion | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 0.62s | **PASS** |
| Stage 5 | Phase 2: safe_run timeout, cap, scrub & grandchild | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 5.09s | **PASS** |
| Stage 5 | Phase 3: display_injection & endpoint_abuse | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 0.62s | **PASS** |
| Stage 5 | Phase 4: data_access, poisoning & model_tampering | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 0.94s | **PASS** |
| Stage 5 | Phase 5: prompt_injection & malicious_patch | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 0.86s | **PASS** |
| Stage 5 | Phase 7: full security benchmark suite | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 300s | 2.30s | **PASS** |
| Stage 5 | Attack log isolation check | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 0.67s | **PASS** |
| Stage 5 | Model manifest tamper check | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 0.78s | **PASS** |
| Stage 5 | Git status clean check | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 0.72s | **PASS** |
| Stage 6 | Live Web IDE endpoints on ephemeral port | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 11.72s | **PASS** |
| Stage 7 | GUI Step 1: window & sidebar navigation | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 7.91s | **PASS** |
| Stage 7 | GUI Step 2: load fixable.cpp & jump cursor | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 16.31s | **PASS** |
| Stage 7 | GUI Step 3: clean run & blocked execvp | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 8.25s | **PASS** |
| Stage 7 | GUI Step 4: offline auto-heal & undo | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 17.27s | **PASS** |
| Stage 7 | GUI Step 5: security page tabs & attack log | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 10.08s | **PASS** |
| Stage 7 | GUI Step 6: benchmark worker fast run | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 8.16s | **PASS** |
| Stage 7 | GUI Step 7: theme toggle twice | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 9.20s | **PASS** |
| Stage 8 | Offline proof: main.py -j tc01 | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 2.44s | **PASS** |
| Stage 8 | Offline proof: main.py -j tc02 | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 2.78s | **PASS** |
| Stage 8 | Offline proof: main.py -j tc03 | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 6.08s | **PASS** |
| Stage 8 | Offline proof: verify_heal engine tc01 | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 6.62s | **PASS** |
| Stage 8 | Offline proof: verify_heal engine tc02 | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 7.16s | **PASS** |
| Stage 8 | Offline proof: guard_cli --heal-security | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 2.45s | **PASS** |
| Stage 8 | Offline proof: dangerous_execution family | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 1.72s | **PASS** |
| Stage 2a | Unit test: test_guard_phase1.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 0.89s | **PASS** |
| Stage 2a | Unit test: test_guard_phase2.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 5.58s | **PASS** |
| Stage 2a | Unit test: test_guard_phase3.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 2.80s | **PASS** |
| Stage 2a | Unit test: test_guard_phase4.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 3.25s | **PASS** |
| Stage 2a | Unit test: test_guard_phase5.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 5.08s | **PASS** |
| Stage 2a | Unit test: test_guard_phase6.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 15.91s | **PASS** |
| Stage 2b | Unit test: test_guard_phase7.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 18.61s | **PASS** |
| Stage 2b | Unit test: test_guard_phase8a.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 14.52s | **PASS** |
| Stage 2b | Unit test: test_guard_phase8b.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 20.83s | **PASS** |
| Stage 2b | Unit test: test_gui_structure.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 60s | 0.55s | **PASS** |
| Stage 2b | Unit test: test_gui_clickthrough.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 25.50s | **PASS** |
| Stage 2b | Unit test: test_security_docs.py | `C:\Users\thris\AppData\Local\Microsoft\WindowsA...` | 120s | 12.61s | **PASS** |

## 3. Unit Test Results by Test File

| Test File | Tests Passed | Duration | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `test_guard_phase1.py` | 27 / 27 | 1.92s | PASS | ExecGuard, execution blocking |
| `test_guard_phase2.py` | 22 / 22 | 7.69s | PASS | ResourceGuard, safe_run tree termination |
| `test_guard_phase3.py` | 8 / 8 | 11.01s | PASS | OutputGuard, EndpointGuard, live server |
| `test_guard_phase4.py` | 16 / 16 | 10.92s | PASS | SecretsGuard, IntegrityGuard, model manifest |
| `test_guard_phase5.py` | 12 / 12 | 13.95s | PASS | PromptGuard, PatchGuard, prompt injection |
| `test_guard_phase6.py` | 26 / 26 | 45.72s | PASS | Security healing recipes, behavior gates |
| `test_guard_phase7.py` | 21 / 21 | 53.47s | PASS | Security benchmark consistency & CSV |
| `test_guard_phase8a.py` | 15 / 15 | 46.58s | PASS | Multi-file scanner, audit consistency |
| `test_guard_phase8b.py` | 24 / 24 | 42.89s | PASS | Explanations, AST fallback, quality hints |
| `test_gui_structure.py` | 4 / 4 | 1.44s | PASS | AST structure check, no nested classes |
| `test_gui_clickthrough.py` | 1 / 1 | 43.42s | PASS | Offscreen clickthrough, cards, undo |
| `test_security_docs.py` | 10 / 10 | 33.53s | PASS | Report assets, LaTeX safety, regex sanity |
| **TOTAL** | **186 / 186** | **308.54s** | **100% PASS** | Zero failures, zero hangs |

## 4. Error Explanation & Classifier Accuracy

- **Fixed List Classification (23 Cases)**: 21 / 23 (91.3% accuracy)
- **Compiled Test Cases Benchmark (`accuracy_benchmark.py`)**:
  - Regex Classifier: 7 / 23 (30.4%)
  - **ML Classifier: 17 / 23 (73.9%)** (Reference score: 14 / 23; achieved +3 gain with zero regression)
  - Combined Classifier: 12 / 23 (52.2%)
- **Explanation Completeness**: 15 / 15 sampled compiler messages generated complete, non-empty What, Why, and How guidance with verified suggestion tokens and valid confidence ratings.

## 5. Auto-Heal & Security Healing Performance

- **Offline Rules (`auto_healer.attempt_fix`)**: 12 / 12 single-error samples repaired and verified with `g++ -fsyntax-only` in under 9 seconds.
- **Full Engine (`heal_until_clean`)**:
  - Evaluated on 12 files (`tc01` through `tc09`, `tc_autoheal_semicolons.cpp`, `tc_multiple_errors.cpp`, `test_heal.cpp`).
  - Reference subset (`tc01`, `tc02`, `tc03`, `tc05`, `tc_autoheal_semicolons`, `test_heal`): **6 of 6 healed (100%)** with zero PatchGuard false blocks.
  - 11 of 12 files completely healed; `tc09_division_by_zero.cpp` flagged as `partially_healed` (0 compiler errors, 1 runtime division by zero flaw requiring manual resolution).
- **Security Healing (`security_healer.heal_security`)**:
  - `fixable.cpp`: Risk 27 -> 0 (6 vulnerabilities healed cleanly).
  - `clean.cpp`: Risk 0 -> 0 (untouched).
  - `unfixable.cpp`: Risk 17 -> 17 (untouched, correctly deferred).
  - `double_free`, `gets`, `leak`, `sprintf`, `strcat`: All healed and verified compiling.

## 6. Security Layer Benchmark Metrics vs Reference Standards

| Metric | Reference Value | Active Benchmark Result | Deviation / Notes |
| :--- | :--- | :--- | :--- |
| Standard Attacks Detected | 77 / 77 (100.0%) | 77 / 77 (100.0%) | Exact match |
| Hard Attacks Detected | 7 / 12 (58.3%) | 7 / 12 (58.3%) | Exact match (5 known evasions) |
| Overall Attack Detection (TPR) | 84 / 89 (94.4%) | 84 / 89 (94.4%) | Exact match |
| Baseline Attack Success Rate | 85.7% (n=84) | 85.7% | Exact match |
| Defended Attack Success Rate | 7.1% (n=84) | 7.1% | Exact match |
| Benign False Alerts (FPR) | 0 / 31 (0.0%) | 0 / 31 (0.0%) | Zero false alerts |
| Routing Misses | 0 | 0 | Zero routing misses across 127 cases |

## 7. Real Defects Found & Fixed

1. **`src/guard/safe_run.py`**: Grandchild processes with inherited pipes hung reader threads indefinitely when child exited. Fixed by bounding reader joins to 2.0s with pipes closed, and ensuring recursive process tree termination (`taskkill /F /T /PID`). Regression test: `test_safe_run_grandchild_timeout_descendant_termination`.
2. **`tools/build_report_assets.py`**: Invoking `pdflatex` on missing packages opened a Windows GUI modal dialog under MiKTeX. Fixed by passing `--disable-installer` and honoring `GUARD_NO_LATEX=1`.
3. **`src/error_normalizer.py`**: `build_ui_message("")` returned `"."` instead of empty string, and compound C++ types (`const char*`, `int counter`) had identifier corruption. Fixed with precise regex matching and empty string guards.
4. **`src/auto_healer.py`**: `fix_uninitialized_variable` matched stream expressions like `std::cout << x << std::endl;` as variable declarations and appended ` = {};`. Fixed by adding negative lookarounds for stream operators and `std::` namespaces.
5. **`src/heal_loop.py` & `src/gui.py`**: Auto-Heal in-place overwrite replaced with non-destructive generation into `healed/<filename>_healed.cpp`, backed by `restore_heal_backup` and undo capabilities.
6. **`src/gui.py`**: Catastrophic regular expression backtracking (ReDoS) in `_extract_cpp_call_graph` and `_extract_cpp_cfg` caused by redundant `\s` inside `[\w:<>,~*&\s]+\s+` causing GUI test execution to hang. Fixed by removing `\s` from the character class and restricting CLI argument file ingestion in `AppGUI` to C++ source extensions. Verified via `tests/test_gui_clickthrough.py`.

## 8. Known Limitations

- **Hard Obfuscation Evasion (5/12 Misses)**: Manifest hard attack cases `hard_001`, `hard_003`, `hard_012` (runtime dlopen/dlsym symbol resolution and character code calculation) and `hard_007`, `hard_008` (markdown payload smuggling in prompt hints) evade static pattern detection as documented.
- **Small Benign Sample Uncertainty**: With 31 benign evaluation samples, 0% false alerts has a Wilson 95% confidence upper bound of ~11.0%.
- **Clang Tooling Fallback**: When `clang++` is unavailable, AST extraction gracefully falls back to regex-based AST emulation (`generate_fallback_ast_text`).
