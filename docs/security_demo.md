# Five-Minute Professor Demo Script: Compiler Security Hardening

This walkthrough provides an exact, step-by-step presentation script to demonstrate and defend the security subsystem in under five minutes.

---

## Preparation
- Launch the application: `python src/main.py` (Desktop GUI) or `python src/web_server.py` (Web IDE).
- Keep `test_cases/security_demo/` open in your file explorer.

---

## Step-by-Step Demonstration

### Step 1: Clean Student Code (No False Alerts)
- **Action**: Open `test_cases/security_demo/demo_clean.cpp`, click **Compile & Explain** (or press `Ctrl+R`).
- **What to point at**: Point at the top **Security Summary Card**: Risk Level is **Clean**, Score is **0**, with zero warnings or findings.
- **Expected Result**: Compilation succeeds immediately with normal output; no security prompts or interference.
- **One-Sentence Explanation**: *"This proves our security layer introduces zero false alerts on valid, benign student code."*

### Step 2: Dangerous Process Spawning Blocked at the Run Gate
- **Action**: Open `test_cases/security_demo/demo_exec_blocked.cpp`, click **Compile**, then click **Run**.
- **What to point at**: Point at the **Security Finding Card** from `ExecGuard` (`process_execution`, action: `block`), and the prominent red **Run Blocked Banner**.
- **Expected Result**: Compilation succeeds, but binary execution is immediately halted before launch.
- **One-Sentence Explanation**: *"The Run Gate inspects dangerous syscalls like `execvp` and intercepts the process before it can ever be spawned."*

### Step 3: Sensitive File Access Blocked at the Compile Gate
- **Action**: Open `test_cases/security_demo/demo_env_include.cpp`, click **Compile**.
- **What to point at**: Point at the compile error banner showing rejection by `SecretsGuard` and `ExecGuard` (`sensitive_include`).
- **Expected Result**: Compilation is rejected before invoking `g++`; the compiler is never executed.
- **One-Sentence Explanation**: *"The Compile Gate blocks path traversal and credential reads (like `#include \".env\"`) before the preprocessor can touch them."*

### Step 4: Deterministic Automated Security Healing
- **Action**: Open `test_cases/security_demo/demo_fixable.cpp`, click **Compile**, inspect the 6 findings, then click **Auto-Heal**.
- **What to point at**: Point at the **Security Result Card** showing **Risk Before: 27 (Moderate) -> Risk After: 0 (Clean)**, and the diff replacing `gets()`, `strcpy()`, and `sprintf()` with safe bounded equivalents.
- **Expected Result**: All 6 security flaws are corrected automatically, and the healed code compiles cleanly.
- **One-Sentence Explanation**: *"Our local security healer deterministically upgrades legacy, vulnerable C APIs to bounded, safe C++ functions with 100% test-backed compilation."*

### Step 5: Display Injection Neutralization
- **Action**: Open `test_cases/security_demo/demo_display_spoof.cpp`, click **Compile**.
- **What to point at**: Point at the compiler output pane and the finding from `OutputGuard`. Note that `<span style="...">` and ANSI sequences are sanitized to plain text rather than executing or spoofing a green success card.
- **Expected Result**: Status phrases and raw tags are neutralized by `safe_text()`.
- **One-Sentence Explanation**: *"OutputGuard neutralizes diagnostic text so hostile error messages cannot spoof compiler success or inject HTML into the UI."*

### Step 6: Prompt Injection Blocked at the AI Gate
- **Action**: Open `test_cases/security_demo/demo_prompt_injection.cpp`, click **Explain with AI**.
- **What to point at**: Point at the rejection banner: **AI Request Blocked by PromptGuard (`prompt_injection`)**.
- **Expected Result**: The request is aborted locally; no prompt is sent to external LLMs (Gemini/Groq).
- **One-Sentence Explanation**: *"PromptGuard inspects outgoing requests for instruction override delimiters before untrusted text reaches third-party AI endpoints."*

### Step 7: Educational Code Quality Hints
- **Action**: Open `test_cases/security_demo/demo_nested_loops.cpp`, look at the **Code Quality** panel.
- **What to point at**: Point at the **Quality Score: 5/10 (Needs work)**, pointing out suggestions for $O(N^3)$ loop nesting, pass-by-value `std::string`, and `std::endl` flushing.
- **Expected Result**: Security level remains **Clean** (0 risk), while pedagogical hints provide actionable code improvement tips.
- **One-Sentence Explanation**: *"Quality hints separate pedagogical code style advice from active security threats."*

### Step 8: Academic Honesty & Known Blind Spots
- **Action**: Open `test_cases/security_demo/demo_evasion_missed.cpp` (`auto f = &::system;`).
- **What to point at**: Point at the Security Level showing **Clean** (missed detection).
- **Expected Result**: The tool misses this evasion because `&::system` takes the address of the function without a literal call pattern.
- **One-Sentence Explanation**: *"We explicitly document our blind spots: static regex scanning cannot detect function pointers without full dataflow analysis, which is why we test hard evasions."*

---

## Offline Verification Check
To verify that security is completely autonomous and self-contained:
1. Turn off your machine's Wi-Fi / disconnect network cables.
2. Repeat **Steps 1 through 4** (`demo_clean.cpp`, `demo_exec_blocked.cpp`, `demo_env_include.cpp`, and `demo_fixable.cpp`).
3. Notice that all guards, gates, and security healing function identically with **zero network requests**.

---

## Limitations I Will State Honestly
*(Directly aligned with `docs/SECURITY_LIMITATIONS.md`)*:
1. **Text-based detection (not AST)**: The guards and healer use regular-expression and lexical text analysis; there is no AST analysis in them.
2. **Not a sandbox**: Code runs in a temporary directory with a scrubbed environment, timeout, and output cap; there is no OS-level filesystem or network container isolation.
3. **Web session token**: Protects only against cross-site browser requests; any local user process can read the token file.
4. **Model manifest**: Verifies file digests against tampering, but cannot protect if an attacker has write permissions to modify both files.
5. **Prompt injection**: Semantic paraphrasing and non-English adversarial prompts are missed by heuristic pattern matching.
6. **AI privacy**: When AI features are explicitly triggered, diagnostic messages and code are dispatched to Gemini or Groq endpoints.
7. **Compiler dependence**: Diagnostics depend on the host compiler (`g++`); recorded version: unavailable.
8. **Benchmark creation**: Benchmark cases were written after detectors existed, measuring pattern coverage rather than generalisation.
9. **Healing sample scope**: Security healing results are evaluated on 8 prepared, compilable test samples.
