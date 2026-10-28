# Security Layer Benchmark Evaluation Report

## Manifest Totals

- **Total Manifest Cases**: 127
- **Headline Benchmark Cases**: 120 (89 attacks [77 standard, 12 hard]; 31 benign)
- **Scanner Evasion Cases (Reported Separately)**: 7 (5 hard evasion attacks, 2 benign twins)

## 1. Metric Definitions

- **Detected (attack)**: At least one finding of expected origin (`attack` or `vulnerability`) raised by an agent listed in `expected_agents`.
- **Agent Attribution**: Some detecting agent is listed in `expected_agents`.
- **Category Attribution**: Label-aligned (expected categories were corrected to each agent's canonical names, so this equals the detection rate and is not an independent result).
- **Prevented (attack)**: For `prevention: block`, the supervisor blocked the action (`verdict.blocked == True`). For `prevention: neutralize`, display injection text is neutralized (HTML tags, ANSI escapes, bidi/zero-width chars, and secrets removed). Attacks with `prevention: warn` are excluded from prevention rate and ASR denominators.
- **Alert False Positive (benign)**: Any finding of origin `attack` and severity Medium, High, or Critical raised on benign code.
- **Block False Positive (benign)**: Any benign code case that is blocked (`verdict.blocked == True`).
- **Attack Success Rate (ASR)**: Proportion of evaluated attacks not prevented: $ASR = 1 - \text{prevention rate}$.
- **Baseline Model**: Evaluates attacks against the original project baseline prior to the security guard layer:
  - `USER_SOURCE`: Evaluated against `compiler_runner._sanitize_code` patterns (blocks `system(`, `exec(`, `popen(`, `fork(`, `__asm__`, `shellcode`, and `#include <sys/...>`). Other system calls such as `execvp(...)` or resource abuse were allowed.
  - `HTTP_REQUEST`: Evaluated against original web server checks (blocks foreign `Host`, foreign `Origin`, and invalid `Content-Type` on POST; missing auth token was allowed).
  - `PATCH`: Evaluated against original `validate_ai_code` rules from `src/ai_healer.py`:
    1. Rejects if `_sanitize_code` fails.
    2. Rejects if length of fixed code is `< 0.60 * len(original)` (less than 60% of original).
    3. Rejects if `main()` was present in original and removed in fixed code.
    4. Rejects if changed lines exceed `max(int(len(original_lines) * 0.40), 10)` lines.
    *(Note: Compile validation with g++ is not simulated in the benchmark runner).*
  - `USER_HINT`, `COMPILER_OUTPUT`, `DATASET_ENTRY`, `MODEL_FILE`, display: No deterministic defense existed in the baseline (allowed).

## How to Read These Numbers

1. **Coverage vs. Generalisation**: The standard attack test cases were written after the security detectors existed. Therefore, 100% detection on the standard set measures coverage of known patterns, not unconstrained generalisation. The hard evasion set provides a much better estimate of realistic evasion resistance.
2. **Benign Set Sample Size & Uncertainty**: With 31 benign evaluation cases (33 including scanner benign cases), a recorded 0.0% false-alert rate carries a 95% Wilson confidence interval upper bound of approximately 11.0%. Zero observed false positives does not imply impossibility under broader inputs.
3. **Scope of Baseline Model**: The baseline model reflects only this repository's original code prior to introducing the security layer (`compiler_runner._sanitize_code`, original web server headers, and length/line checks from `src/ai_healer.py`); it does not model external or third-party IDE tools.
4. **Security Healing Scope**: Security healing metrics are derived from 8 prepared, compilable test samples exhibiting specific vulnerability patterns (`fixable.cpp`, `unfixable.cpp`, `clean.cpp`, and 5 canonical micro-benchmarks), not unconstrained or arbitrary legacy codebases.
5. **Calibrated Benchmark Cases**: Benchmark cases whose inputs were calibrated to match detector specifications:
   - `prompt_008`: Comment length set to 108 characters to exercise the `>= 80` character base64 decoding threshold.

## 2. Overall Summary

- **Total Headline Cases**: 120 (89 attacks, 31 benign)
- **Standard Set Attacks**: 77
- **Hard Evasion Attacks**: 12
- **ASR Evaluated Attacks**: 84 (excluding 5 warn-only attacks)
- **Precision**: 100.0% | **Recall**: 94.4% | **F1 Score**: 97.1%

| Metric | Defended Security Layer | 95% Confidence Interval |
|:---|:---:|:---:|
| **Detection Rate (TPR)** | 94.4% (84/89) | [87.5%, 97.6%] |
| **Agent Attribution** | 94.4% (84/89) | [87.5%, 97.6%] |
| **Category Attribution** | 94.4% (84/89) | [87.5%, 97.6%] |
| **Combined Attribution** | 94.4% (84/89) | [87.5%, 97.6%] |
| **Prevention Rate** | 92.9% (78/84) | [85.3%, 96.7%] |
| **False Alert Rate (FPR)** | 0.0% (0/31) | [0.0%, 11.0%] |
| **False Block Rate** | 0.0% (0/31) | [0.0%, 11.0%] |
| **Attack Success Rate (ASR)** | **7.1%** (6/84) (Baseline: **85.7%** [72/84]) | - |

## 3. Results by Threat Family

| Threat Family | Attacks (Std / Hard) | ASR Denominator | Detected | Prevented | Baseline Prevented | Baseline ASR | Defended ASR |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `dangerous_execution` | 17 (12/5) | 17 | 14 | 13 | 4 | 76.5% | **23.5%** |
| `dataset_poisoning` | 5 (5/0) | 5 | 5 | 5 | 0 | 100.0% | **0.0%** |
| `display_injection` | 6 (6/0) | 6 | 6 | 6 | 0 | 100.0% | **0.0%** |
| `endpoint_abuse` | 14 (14/0) | 14 | 14 | 14 | 6 | 57.1% | **0.0%** |
| `malicious_patch` | 12 (11/1) | 12 | 12 | 12 | 2 | 83.3% | **0.0%** |
| `model_tampering` | 3 (3/0) | 3 | 3 | 3 | 0 | 100.0% | **0.0%** |
| `prompt_injection` | 12 (8/4) | 11 | 10 | 9 | 0 | 100.0% | **18.2%** |
| `resource_exhaustion` | 7 (7/0) | 6 | 7 | 6 | 0 | 100.0% | **0.0%** |
| `scanner_evasion` | 5 (0/5) | 0 | 0 | 0 | 0 | 0.0% | **0.0%** |
| `sensitive_data_access` | 13 (11/2) | 10 | 13 | 10 | 0 | 100.0% | **0.0%** |

## 4. Attack Success Rate: Before vs After Defence

| Threat Family | ASR Denominator | Baseline ASR (Allowed) | Defended ASR | Relative Reduction |
|:---|:---:|:---:|:---:|:---:|
| `dangerous_execution` | 17 | 76.5% | 23.5% | **69.2%** |
| `dataset_poisoning` | 5 | 100.0% | 0.0% | **100.0%** |
| `display_injection` | 6 | 100.0% | 0.0% | **100.0%** |
| `endpoint_abuse` | 14 | 57.1% | 0.0% | **100.0%** |
| `malicious_patch` | 12 | 83.3% | 0.0% | **100.0%** |
| `model_tampering` | 3 | 100.0% | 0.0% | **100.0%** |
| `prompt_injection` | 11 | 100.0% | 18.2% | **81.8%** |
| `resource_exhaustion` | 6 | 100.0% | 0.0% | **100.0%** |
| `scanner_evasion` | 0 | 0.0% | 0.0% | **0.0%** |
| `sensitive_data_access` | 10 | 100.0% | 0.0% | **100.0%** |

## 5. Performance by Security Agent

| Security Agent | Target Attacks | Detected (Recall) | 95% Confidence Interval | Benign Alerts (FP) | Precision |
|:---|:---:|:---:|:---:|:---:|:---:|
| `ExecGuard` | 17 | 82.3% (14/17) | [59.0%, 93.8%] | 0 | 100.0% |
| `ResourceGuard` | 7 | 100.0% (7/7) | [64.6%, 100.0%] | 0 | 100.0% |
| `OutputGuard` | 6 | 100.0% (6/6) | [61.0%, 100.0%] | 0 | 100.0% |
| `EndpointGuard` | 14 | 100.0% (14/14) | [78.5%, 100.0%] | 0 | 100.0% |
| `SecretsGuard` | 13 | 100.0% (13/13) | [77.2%, 100.0%] | 0 | 100.0% |
| `IntegrityGuard` | 8 | 100.0% (8/8) | [67.6%, 100.0%] | 0 | 100.0% |
| `PromptGuard` | 12 | 83.3% (10/12) | [55.2%, 95.3%] | 0 | 100.0% |
| `PatchGuard` | 12 | 100.0% (12/12) | [75.8%, 100.0%] | 0 | 100.0% |
| `VulnGuard` | 5 | 0.0% (0/5) | [0.0%, 43.5%] | 0 | 100.0% |

## 6. Hard Evasion Attacks Evaluation

- **Total Hard Cases**: 12
- **Detection Rate**: 58.3% (7/12) [31.9%, 80.7%]
- **Agent Attribution**: 58.3% (7/12)
- **Category Attribution**: 58.3% (7/12) (label-aligned)
- **Prevention Rate**: 58.3% (7/12)
- **Baseline ASR**: 91.7% | **Defended ASR**: 41.7%

## Limitations of the Vulnerability Scanner (Scanner Evasion)

The `scanner_evasion` family evaluates known blind spots in static regex and AST pattern matching. These cases are excluded from headline attack detection rate and ASR because they model scanner limitations rather than active runtime attacks:

| Case ID | Pattern / Blind Spot | Expected Category | Scanner Finding | Reason for Evasion |
|:---|:---|:---|:---:|:---|
| `scan_001` | Unguarded `assert()` with `#ifdef NDEBUG` in comment | `disabled_safety_check` | Evaded (no finding) | Comment text matches `#ifdef NDEBUG` heuristic, setting debug guard flag |
| `scan_002` | `gets()` hidden behind macro alias `#define G gets` | `buffer_overflow` | Evaded (no finding) | Static regex scanner does not expand pre-processor macro aliases |
| `scan_003` | `malloc()` leak hidden by unrelated `free(other)` | `potential_memory_leak` | Evaded (no finding) | Scope-level `free_seen` flag satisfied by any free call in scope |
| `scan_004` | `strcpy()` hidden behind macro `#define STR_COPY strcpy` | `unsafe_string_function` | Evaded (no finding) | Static regex scanner does not expand macro definitions |
| `scan_005` | Double `delete` with second deletion in macro | `double_free` | Evaded (no finding) | Static deletion regex requires literal `delete` token |

## 7. Execution Latency

Execution latency evaluated across 127 cases:

- **Overall Review Time**: Mean = 8.29 ms | Median = 8.03 ms | P95 = 19.38 ms | Max = 39.14 ms

| Input Kind | Mean (ms) | Median (ms) | P95 (ms) | Max (ms) |
|:---|:---:|:---:|:---:|:---:|
| `COMPILER_OUTPUT` | 1.59 | 1.63 | 2.62 | 2.78 |
| `DATASET_ENTRY` | 3.35 | 3.10 | 5.15 | 5.72 |
| `HTTP_REQUEST` | 0.94 | 1.11 | 1.79 | 2.14 |
| `MODEL_FILE` | 7.18 | 7.21 | 12.03 | 12.54 |
| `PATCH` | 5.51 | 5.10 | 9.82 | 10.92 |
| `USER_HINT` | 2.26 | 1.24 | 5.46 | 6.13 |
| `USER_SOURCE` | 13.61 | 11.57 | 25.93 | 39.14 |

## 8. Supervisor Routing Efficiency

- **Routing Misses**: 0 (Zero routing misses across 127 evaluated cases)
- **Mean Agent Execution Ratio**: 59.1% of candidate agents triggered per input

## 9. Security Healing Evaluation

- **Total Security Findings**: 14
- **Fixed Automatically**: 11 (78.6%)
- **Actionable Suggestions**: 1
- **Skipped (Behavior-Changing)**: 2
- **Rejected / Rolled Back**: 0
- **Risk Reduction**: 71 -> 17 (76.1% reduction)

| File | Findings | Fixed | Suggested | Skipped | Rejected | Risk Before/After | Reduction | Seconds |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `fixable.cpp` | 6 | 6 | 0 | 0 | 0 | 27 -> 0 | 100.0% | 6.65s |
| `unfixable.cpp` | 3 | 0 | 1 | 2 | 0 | 17 -> 17 | 0.0% | 0.06s |
| `clean.cpp` | 0 | 0 | 0 | 0 | 0 | 0 -> 0 | 0.0% | 0.04s |
| `gets_sample.cpp` | 1 | 1 | 0 | 0 | 0 | 10 -> 0 | 100.0% | 0.74s |
| `strcat_sample.cpp` | 1 | 1 | 0 | 0 | 0 | 5 -> 0 | 100.0% | 0.61s |
| `sprintf_sample.cpp` | 1 | 1 | 0 | 0 | 0 | 5 -> 0 | 100.0% | 0.41s |
| `leak_sample.cpp` | 1 | 1 | 0 | 0 | 0 | 2 -> 0 | 100.0% | 0.51s |
| `double_free_sample.cpp` | 1 | 1 | 0 | 0 | 0 | 5 -> 0 | 100.0% | 0.68s |

## 10. Known Misses & Hard Evasions

| Case ID | Set | Threat Family | Expected Category | Reason for Miss |
|:---|:---:|:---:|:---:|:---|
| `hard_001` | `hard` | `dangerous_execution` | `process_execution` | Hard evasion: Function pointer address taken of ::system without direct call |
| `hard_003` | `hard` | `dangerous_execution` | `process_execution` | Hard evasion: popen alias through typedef function pointer |
| `hard_007` | `hard` | `prompt_injection` | `prompt_injection` | Hard evasion: Paraphrased semantic prompt injection avoiding exact keyword matches |
| `hard_008` | `hard` | `prompt_injection` | `prompt_injection` | Hard evasion: Multilingual prompt injection in French |
| `hard_012` | `hard` | `dangerous_execution` | `process_execution` | Hard evasion: Hex-escaped string literal spelling system |

## 11. Detected but Not Prevented Attacks (Prevention Failures)

Attacks where the security layer successfully detected the threat, but prevention failed (`verdict.blocked == False` for a `prevention: block` case):

| Case ID | Set | Threat Family | Finding Categories | Severities | Blocked | Purpose | Prevention | Reason Not Blocked |
|:---|:---:|:---:|:---|:---|:---:|:---:|:---:|:---|
| `exec_009` | `standard` | `dangerous_execution` | `obfuscation` | `Medium` | False | `run` | `block` | Finding category 'obfuscation' emitted with Medium severity and action 'warn'; ExecGuard does not emit a blocking action for macro token-pasting alone without a resolved dangerous syscall |

## 12. Evaluation Environment

- **Timestamp**: 2026-10-28T12:30:01Z
- **Platform**: Windows 10 (Python 3.11.9)
- **Compiler**: unavailable
- **Git Commit**: 3795cb5