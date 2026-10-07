# 🌿 Green Self-Healing Compiler

A modern C++ analysis and repair platform combining compiler diagnostics, Clang AST exploration, Machine Learning error classification, automated code healing, security analysis, and energy telemetry — in one unified desktop and web workflow.

---

## Key Features

- **Compile & Analyze** — Invokes `g++ -std=c++17`, parses diagnostics into structured records, and enriches each diagnostic with human-friendly explanations, repair suggestions, and security risk ratings.
- **ML Error Classification** — Classifies compilation diagnostics using a trained scikit-learn model with regex and rule-based fallbacks for high-precision categorization.
- **Auto-Heal Loop** — Performs multi-pass iterative repairs (up to bounded attempts) with automated patch generation, AST validation, and recompilation.
- **AST Explorer** — Extracts and visualizes filtered Clang AST trees, stripping away standard library noise so developers can inspect their own syntax trees directly.
- **Security Vulnerability Analyzer** — Static detection for use-after-free, integer overflow, missing return branches, variable shadowing, and memory safety issues.
- **Energy Dashboard** — Real-time power usage, carbon intensity, and execution time telemetry powered by CodeCarbon.
- **Accuracy Benchmarking** — Built-in benchmark suite to evaluate classifier accuracy across diverse C++ error suites.
- **Desktop & Web Interfaces** — Comprehensive PyQt6 desktop application alongside a Flask-based web interface.

---

## Project Structure

```
├── src/
│   ├── main.py                     # CLI entry point
│   ├── gui.py                      # PyQt6 desktop application
│   ├── web_server.py               # Web dashboard & API
│   ├── compiler_runner.py          # g++ invocation and diagnostic capture
│   ├── error_parser.py             # Compiler diagnostic parsing
│   ├── error_explainer.py          # Diagnostic explanations & suggestions
│   ├── error_classifier.py         # ML-backed error classification
│   ├── ast_extractor.py            # Filtered Clang AST extraction
│   ├── heal_loop.py                # Multi-pass iterative healing loop
│   ├── auto_healer.py              # Rule-based and AST-guided patch generation
│   ├── diff_viewer.py              # Code diff visualization
│   ├── security_analyzer.py        # Static security flaw & vulnerability analyzer
│   ├── accuracy_benchmark.py       # Benchmark evaluation script
│   ├── second_opinion.py           # Alternative AI/heuristic analysis
│   └── common_errors.py            # Curated error knowledge base
├── data/                           # Training datasets and serialized model (.joblib)
├── test_cases/                     # Test cases covering syntax, semantics, and security
├── documentation/
│   ├── PBL_Report.md               # Detailed project report
│   ├── project_explanation.md      # Architecture and design documentation
│   └── DOCUMENTATION.md            # Technical documentation
└── requirements.txt
```

---

## Requirements

**System Requirements:**
- `g++` (GCC C++ compiler with C++17 support)
- `clang++` (for AST extraction)
- Python 3.10+

**Python Dependencies:**
```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. Command-Line Interface (CLI)

```bash
# Analyze a C++ file
python src/main.py file.cpp

# Output in JSON format with verbose context
python src/main.py file.cpp -j -v
```

### 2. Desktop GUI

```bash
python src/gui.py
```

### 3. Web Dashboard

```bash
python src/web_server.py
```

---

## Auto-Healing Workflow

```
 Source Code (.cpp) ──► g++ Compiler ──► Diagnostics Captured
                              │                     │
                              ▼                     ▼
                       Compilation OK        Error Parser
                                                    │
                                                    ▼
                                            Error Classifier
                                                    │
                                                    ▼
                                            Auto-Healer Pass
                                                    │
                                                    ▼
                                            Patch & Recompile (Loop)
```

1. **Compilation**: Invokes compiler and captures stderr diagnostic streams.
2. **Parsing & Normalization**: Strips file paths and line offsets into standard error signatures.
3. **Classification**: Evaluates AST context and diagnostic strings using trained ML models.
4. **Patch Synthesis**: Generates targeted code modifications (missing semicolons, include headers, type mismatches, etc.).
5. **Re-verification**: Compiles the patched source up to 3 iterative passes until errors resolve or terminate.

---

## License

MIT License.
