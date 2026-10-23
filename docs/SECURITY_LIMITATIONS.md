# Security Limitations and Honest Disclosures

## Architecture and Environment Limitations
- Text-based detection (not AST): Guards and the healer use regular expressions and lexical text analysis; there is no AST analysis in them.
- Not a sandbox: Programs run in a temporary directory with a scrubbed environment, timeout, and output cap; there is no filesystem or network isolation.
- Web session token: Only protects against cross-site browser requests; any local process on the machine can read it.
- Model manifest: manifest.json verifies file hashes but cannot protect against an attacker with filesystem write access to both files.
- Prompt injection: Paraphrased semantic injections and non-English instructions are missed by keyword and delimiter heuristics.
- AI privacy: Error messages and (for AI heal) user source code are sent to external Gemini or Groq APIs when AI features are enabled.
- Compiler dependence: Diagnostic output depends on compiler version (recorded g++ --version: unavailable).
- Benchmark creation: Benchmark test cases were authored after detectors existed, measuring pattern coverage rather than generalisation.
- Healing sample scope: Security healing results are evaluated on 8 prepared, compilable test samples.

## Hard-Set Misses and Blind Spots
- `hard_001`: Function pointer address taken of ::system without direct call
- `hard_003`: popen alias through typedef function pointer
- `hard_007`: Paraphrased semantic prompt injection avoiding exact keyword matches
- `hard_008`: Multilingual prompt injection in French
- `hard_012`: Hex-escaped string literal spelling system

## Detected but Not Prevented Attacks
- `exec_009`: Finding category 'obfuscation' emitted with Medium severity and action 'warn'; ExecGuard does not emit a blocking action for macro token-pasting alone without a resolved dangerous syscall

## Scanner Evasion Blind Spots
- Macro aliases (#define G gets), comments matching #ifdef NDEBUG, and scope-unrelated free() evade static regex rules.
