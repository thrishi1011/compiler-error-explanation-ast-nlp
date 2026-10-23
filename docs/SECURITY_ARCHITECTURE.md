# Security Architecture & Implementation Documentation

This document describes the security hardening architecture, registered guard agents, enforcement gates, codebase inventory, and benchmark evaluation results for the C++ compiler error explanation platform.

> [!NOTE]
> All metrics and inventories in this document are programmatically verified from the active codebase and committed benchmark datasets (`data/security_metrics.json`).

---

## 1. Registered Security Agents

The security subsystem is managed by the `Supervisor` (`src/guard/supervisor.py`), which coordinates nine specialized agents across two distinct architectural roles:
1. **Attacks on the Tool (8 agents)**: Defend platform components against hostile payloads (`ExecGuard`, `ResourceGuard`, `OutputGuard`, `EndpointGuard`, `SecretsGuard`, `IntegrityGuard`, `PromptGuard`, `PatchGuard`).
2. **Weaknesses in User Code (1 agent)**: Identify static memory safety and programming defects in student submissions (`VulnGuard`).

| Agent | Input Kinds Handled | Emitted Categories | Role Summary |
|:---|:---|:---|:---|
| `ExecGuard` | `USER_SOURCE` | destructive_file_op, dynamic_loading, inline_assembly, network_access, obfuscation, process_execution, secret_env_access, sensitive_file_access, startup_code, unsafe_include | Monitors process spawning, system calls, and unsafe execution. |
| `VulnGuard` | `USER_SOURCE` | buffer_overflow, disabled_safety_check, division_by_zero, double_free, format_string_vulnerability, infinite_recursion, integer_overflow, integer_underflow, null_pointer_dereference, potential_memory_leak, process_execution, unbounded_input, uninitialized_variable, unresolved_security_debt, unsafe_memory_copy, unsafe_pointer_arithmetic, unsafe_string_function, use_after_free, vector_out_of_bounds, weak_randomness | Static sanitizer for memory safety, buffer overflows, and unsafe C APIs. |
| `ResourceGuard` | `USER_SOURCE` | huge_allocation, macro_expansion_bomb, oversized_input, possible_infinite_loop, special_file_include | Detects algorithmic complexity bombs and resource exhaustion. |
| `OutputGuard` | `AI_RESPONSE, COMPILER_OUTPUT, USER_SOURCE` | display_injection, hidden_unicode, spoofed_status, terminal_escape | Neutralizes display injections, ANSI escapes, and format attacks. |
| `EndpointGuard` | `HTTP_REQUEST` | bad_body, bad_content_type, bad_host, bad_json, bad_length, bad_origin, bad_token, body_too_large, cross_site_request, missing_length, unsupported_encoding | Validates HTTP headers, origins, tokens, and endpoint abuse. |
| `SecretsGuard` | `AI_RESPONSE, COMPILER_OUTPUT, DATASET_ENTRY, PATCH, USER_HINT, USER_SOURCE` | hardcoded_secret, personal_data_access, sensitive_include, tool_secret_value | Scans for API keys, tokens, credentials, and sensitive paths. |
| `IntegrityGuard` | `DATASET_ENTRY, MODEL_FILE` | dataset_bad_category, dataset_bad_message, dataset_directive_message, dataset_rate_limit, dataset_secret, dataset_store_too_large, model_hash_mismatch, model_manifest_missing, model_outside_data_dir, model_too_large | Verifies model signature, weights, and dataset integrity. |
| `PromptGuard` | `COMPILER_OUTPUT, USER_HINT, USER_SOURCE` | encoded_payload, hidden_prompt_unicode, policy_bypass_request, prompt_injection, role_marker, secret_exfiltration_request | Detects prompt injection and adversarial instructions in comments. |
| `PatchGuard` | `PATCH` | patch_comments_out_code, patch_injection_text, patch_introduces_dangerous_code, patch_marker_leak, patch_new_include, patch_removes_guard, patch_secret, patch_security_downgrade, patch_suppresses_diagnostics, patch_too_large | Audits AI-generated patches for malicious code and new includes. |

---

## 2. Enforcement Gates and Purposes

Every input payload is assigned one of the nine valid `InputKind` values (`USER_SOURCE`, `COMPILER_OUTPUT`, `AI_RESPONSE`, `USER_HINT`, `PATCH`, `HTTP_REQUEST`, `MODEL_FILE`, `DATASET_ENTRY`) and reviewed under a specific `purpose`.

Execution is controlled by deterministic gates before invoking expensive compiler, runner, or network calls:

| Purpose | What is Checked | Action on Block | Test-Verified Enforcement Points |
|:---|:---|:---|:---|
| `ai_send` | Prompt injection delimiters, instruction overrides, model steering, and credential theft. | Refuses dispatch to external AI API; returns local security block notification. | `ai_explainer.explain_errors_batch`, `ai_healer.attempt_ai_heal`, `llm_client.ask` |
| `analyze` | Source code static flaws, memory safety issues, and unsafe C APIs. | Produces advisory findings with remediation guidance; does not halt workflow. | `gui.AppGUI.run_code`, `web_server.CompilerWebHandler` |
| `compile` | Preprocessor macro bombs, include depth, path traversal in includes, and resource exhaustion. | Aborts compilation before invoking g++; returns security rejection diagnostic. | `compiler_runner.run_cpp_compiler`, `heal_engine.compile_source` |
| `dataset` | Sample corruption, invalid error categories, path traversal keys, and credential leakage. | Discards or quarantines offending log entry to prevent training set poisoning. | `dataset_logger.log_example` |
| `display` | HTML/markup injection, spoofed compilation status, ANSI escapes, and Trojan Source Unicode. | Neutralizes output via safe_text/html_text by stripping tags and escapes (non-blocking). | `guard.output_safe.safe_text`, `gui.AppGUI.run_code`, `web_server.CompilerWebHandler` |
| `model_load` | Model file integrity, SHA-256 digest validation against manifest.json, and file size limits. | Refuses to load tampered or untrusted model weights into the classifier. | `error_classifier.ErrorClassifier.load` |
| `patch` | AI-generated patch regressions, guard removal, re-introduced vulnerabilities, and new includes. | Rejects patch prior to disk write; rolls back code to original unmodified state. | `ai_healer.attempt_ai_heal` |
| `request` | Host header forgery, foreign CORS origins, oversized payloads, and missing session tokens. | Returns HTTP 400, 403, 413, or 429 response; request discarded immediately. | `web_server.CompilerWebHandler` |
| `run` | Dangerous process execution (system, exec, popen, fork), inline assembly, and shellcode. | Refuses program launch in the runner environment; returns execution blocked status. | `gui.AppGUI.run_code`, `web_server.CompilerWebHandler` |

---

## 3. Risk Scoring & Healing Architecture

- **Risk Score Calculation**: The risk score is the additive sum of severity weights (`Critical` = 10, `High` = 5, `Medium` = 2, `Low` = 1); it is an unbounded severity sum rather than a percentage scale.
- **Risk Level Thresholds**:
  - `Clean`: Score = 0
  - `Low Risk`: Score 1 to 10
  - `Moderate`: Score 11 to 30
  - `High Risk`: Score > 30
- **Security Healing API**: Vulnerability remediation is driven by `security_healer.heal_security(source_path, findings, ...)` returning a `SecurityHealResult` containing structured `Fix` decisions with `Outcome` statuses.
- **Pure Lexical Analysis**: Guard agents and healing rules rely entirely on regular-expression and lexical text analysis; there is no AST analysis in guards or healing rules.
- **Process Environment**: Programs run inside a temporary directory with a scrubbed environment, timeout limits, and capped output. This execution harness is not a sandbox with filesystem or network isolation.

---

## 4. Benchmark Results Summary

Results programmatically extracted from `data/security_metrics.json`:

- **Standard Attack Detection**: 100.0% (77/77) [95% CI: 95.2%, 100.0%]
- **Hard Evasion Detection**: 58.3% (7/12) [95% CI: 31.9%, 80.7%]
- **Overall Attack Detection**: 94.4% (84/89) [95% CI: 87.5%, 97.6%]
- **Attack Success Rate (ASR)**:
  - Baseline (Without Guards): 85.7% (72/84)
  - Defended Platform: 7.1% (6/84)
  - Relative ASR Reduction: 91.7%
- **False Alert Rate**: 0.0% (0/31) [95% CI: 0.0%, 11.0%]
- **Review Latency**:
  - Mean: 4.17 ms
  - Median: 2.65 ms
  - 95th Percentile (P95): 12.96 ms
  - Maximum: 27.16 ms

---

## 5. Security Codebase File Inventory

| File Path | Description (Module Docstring) |
|:---|:---|
| `src/guard/__init__.py` | No docstring available. |
| `src/guard/ai_budget.py` | Thread-safe rate and prompt-size budget tracker for AI model requests. |
| `src/guard/attack_log.py` | No docstring available. |
| `src/guard/base.py` | No docstring available. |
| `src/guard/benchmark.py` | Deterministic benchmark execution engine evaluating detection, attribution, |
| `src/guard/config.py` | No docstring available. |
| `src/guard/endpoint_guard.py` | EndpointGuard inspects incoming HTTP request headers and payload bodies |
| `src/guard/envscrub.py` | No docstring available. |
| `src/guard/exec_guard.py` | No docstring available. |
| `src/guard/gates.py` | No docstring available. |
| `src/guard/integrity.py` | Public API for querying ML model file integrity status. |
| `src/guard/integrity_guard.py` | IntegrityGuard agent for detecting: |
| `src/guard/lexutil.py` | No docstring available. |
| `src/guard/limiter.py` | Thread-safe concurrency and rate limiting primitives for guarding |
| `src/guard/models.py` | No docstring available. |
| `src/guard/output_guard.py` | OutputGuard detects display injection, spoofed compiler status, terminal escape |
| `src/guard/output_safe.py` | Deterministic sanitizers for text displayed in terminals, GUI widgets, |
| `src/guard/patch_guard.py` | PatchGuard agent for inspecting proposed code patches (from AI or offline rules). |
| `src/guard/pathsafe.py` | Path validation utilities to prevent unauthorized file reads, path traversal, |
| `src/guard/prompt_guard.py` | PromptGuard agent for detecting prompt injection, role hijacking, policy bypass |
| `src/guard/promptsafe.py` | Shared pure helpers for prompt injection detection, untrusted data wrapping, |
| `src/guard/redact.py` | No docstring available. |
| `src/guard/resource_guard.py` | No docstring available. |
| `src/guard/runner.py` | No docstring available. |
| `src/guard/safe_run.py` | No docstring available. |
| `src/guard/secrets.py` | Pure functions for detecting, scanning, and masking sensitive credentials, |
| `src/guard/secrets_guard.py` | SecretsGuard agent for detecting: |
| `src/guard/supervisor.py` | No docstring available. |
| `src/guard/vuln_guard.py` | No docstring available. |
| `src/security_healer.py` | No docstring available. |
| `src/security_view.py` | Pure view-model module for the security layer (Phase 8a). |
| `src/quality_hints.py` | Deterministic code quality inspection heuristics for C++ source code. |
| `security_bench/CHANGELOG.md` | Manifest Changelog: Category Label Alignments |
| `security_bench/manifest.json` | JSON configuration data (manifest.json) |
| `security_bench/README.md` | Attack Benchmark Manifest |
| `tools/build_report_assets.py` | Orchestrates report generation: |
| `tools/demo_prompt_injection.py` | demo_prompt_injection.py: Offline demonstration of prompt injection & malicious patch defenses. |
| `tools/make_security_docs.py` | Programmatically generates: |
| `tools/make_security_report_tables.py` | Generates Overleaf-ready LaTeX report assets from data/security_metrics.json: |
| `tools/plot_security_metrics.py` | Generates visualization plots for security metrics if matplotlib is installed. |
| `tools/run_security_demo.py` | Headless self-check running security reviews and quality inspections across |
| `tools/security_benchmark.py` | CLI tool executing the security benchmark, computing evaluation metrics, |
| `tools/verify_security_by_family.py` | Verifies the security layer by family using static review (never compiles or runs attacks). |

---

## 6. Test Suite Inventory

| Test Suite File | Unit Test Functions (`def test_*`) |
|:---|:---:|
| `test_guard_phase1.py` | 27 |
| `test_guard_phase2.py` | 22 |
| `test_guard_phase3.py` | 8 |
| `test_guard_phase4.py` | 16 |
| `test_guard_phase5.py` | 12 |
| `test_guard_phase6.py` | 26 |
| `test_guard_phase7.py` | 21 |
| `test_guard_phase8a.py` | 15 |
| `test_guard_phase8b.py` | 24 |
| `test_gui_clickthrough.py` | 1 |
| `test_gui_structure.py` | 4 |
| `test_llm_fallback.py` | 19 |
| `test_security_docs.py` | 12 |
| **Total Test Count** | **207** |

---

## 7. Further References

- [Security Limitations & Honest Disclosures](file:///c:/Users/thris/OneDrive/Documents/compiler%20error%20explanation%20using%20AST%20and%20NLP%20code/docs/SECURITY_LIMITATIONS.md)
- [Security Benchmark Suite README](file:///c:/Users/thris/OneDrive/Documents/compiler%20error%20explanation%20using%20AST%20and%20NLP%20code/security_bench/README.md)
