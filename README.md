# Compiler Error Explanation, AST Analysis & Code Optimization

An intelligent C++ development assistant that combines Machine Learning, Natural Language Processing, AI-powered assistance, Abstract Syntax Tree analysis, automated code repair, security analysis, and code optimization.

The project provides a desktop-based development environment where developers can compile, analyze, debug, repair, secure, and optimize C++ programs through an integrated PyQt6 graphical interface.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Application Workflow](#application-workflow)
- [Machine Learning and Error Analysis](#machine-learning-and-error-analysis)
- [Security Framework](#security-framework)
- [Testing](#testing)
- [Additional Documentation](#additional-documentation)
- [Important Notes](#important-notes)

---

## Overview

Traditional compiler diagnostics often provide technical messages without explaining the actual cause of a programming mistake or how to fix it.

This project aims to make C++ development easier by combining compiler diagnostics, Machine Learning, NLP, AI integrations, and static code analysis.

The application goes beyond displaying compiler errors. It provides:

1. Compiler error detection and classification.
2. AI-assisted explanations and suggestions.
3. Automated code repair through an iterative healing workflow.
4. Abstract Syntax Tree extraction and exploration.
5. Code optimization and complexity analysis.
6. Security vulnerability detection and protective checks.
7. Second-opinion error analysis.
8. Code quality recommendations.
9. Function call graph and control-flow analysis.
10. Execution-related energy and resource monitoring.

All major development features are accessible through a desktop graphical interface.

---

## Key Features

### 1. C++ Compilation and Error Detection

- Compile C++ programs using GCC/G++.
- Capture compiler errors and warnings.
- Parse compiler diagnostics into structured information.
- Display errors with relevant source-code context.
- Support C++17 compilation.

### 2. Machine Learning-Based Error Classification

- Classify compiler errors using a trained ML model.
- Apply TF-IDF for text feature extraction.
- Use Logistic Regression for classification.
- Provide classification results and confidence information where available.
- Include fallback classification mechanisms when the trained model is unavailable.

### 3. AI-Powered Error Explanation

- Explain compiler diagnostics in understandable language.
- Provide suggestions for fixing programming errors.
- Integrate Google Gemini and Groq.
- Combine AI assistance with existing compiler and classification information.

### 4. Automatic Code Repair

- Analyze compiler diagnostics.
- Identify errors that can potentially be repaired.
- Generate repair suggestions and patches.
- Apply repairs through an iterative auto-healing workflow.
- Recompile the code to validate repair attempts.
- Display repair information through the GUI.

### 5. Abstract Syntax Tree Analysis

- Extract AST information using Clang/Clang++.
- Analyze the structural organization of C++ code.
- Filter irrelevant AST information to make exploration easier.
- Display declarations, statements, expressions, and other relevant nodes.
- Provide an interactive AST explorer.

### 6. Code Optimization and Complexity Analysis

- Identify potential code optimization opportunities.
- Analyze algorithmic patterns.
- Estimate time and space complexity.
- Identify potential performance bottlenecks.
- Present optimization suggestions and complexity information.

### 7. Security Analysis

- Analyze source code for potential security issues.
- Detect suspicious or unsafe programming patterns.
- Use a modular security framework.
- Provide security findings with severity and contextual information.
- Apply protective checks to supported application operations.

### 8. Second-Opinion Analysis

- Provide an additional analysis of compiler errors.
- Use secondary classification and explanation mechanisms.
- Help developers compare different interpretations of errors.

### 9. Code Quality Analysis

- Identify possible code quality issues.
- Highlight improvements in readability and maintainability.
- Display contextual quality hints.

### 10. Function Call Graph and Control-Flow Analysis

- Identify functions and relationships within the source code.
- Visualize function-to-function calls.
- Analyze selected control-flow structures.
- Help developers understand code organization.

### 11. Energy and Resource Monitoring

- Integrate CodeCarbon and psutil for supported monitoring.
- Display execution-related resource information.
- Provide energy and carbon-related telemetry.
- Use supported system readings where available.

### 12. Benchmarking and Testing

- Include benchmarking functionality for supported analysis workflows.
- Provide testing utilities for compilation, healing, classification, and security.
- Maintain sample C++ programs for evaluating different scenarios.

### 13. Desktop Graphical Interface

- Built using PyQt6.
- Provides an integrated code editing and analysis environment.
- Includes compilation, execution, repair, AST exploration, security, optimization, and other analysis features.
- Supports dark and light themes.

---

## Technology Stack

| Component | Technology |
|---|---|
| Primary Language | Python |
| Source Language | C++ |
| Desktop GUI | PyQt6 |
| Machine Learning | Scikit-learn |
| NLP | TF-IDF |
| Classification | Logistic Regression |
| Compiler | GCC/G++ |
| AST Extraction | Clang/Clang++ |
| AI Integration | Google Gemini, Groq |
| Model Serialization | Joblib |
| Energy Monitoring | CodeCarbon |
| Resource Monitoring | psutil |
| Security | Modular Python security framework |

---

## System Architecture

The application consists of several interconnected components.

**1. Input Layer**

Developers load or enter C++ source code through the desktop GUI.

**2. Compilation Layer**

GCC/G++ compiles the source code and produces diagnostic messages.

**3. Diagnostic Processing Layer**

Compiler messages are parsed into structured records containing information such as error category, location, and message.

**4. Intelligence Layer**

Machine Learning classification, curated explanations, fallback mechanisms, and configured AI providers help interpret compiler diagnostics.

**5. Automatic Repair Layer**

The healing workflow attempts supported repairs and recompiles the source to check the results.

**6. Code Analysis Layer**

AST extraction, complexity analysis, optimization, call graph generation, and quality analysis provide additional information about the source code.

**7. Security Layer**

The security framework evaluates supported operations and source code for potentially unsafe patterns.

**8. Output Layer**

The GUI presents diagnostics, explanations, suggestions, repair results, security findings, and analysis information.

---

## Project Structure

The repository contains the desktop application, analysis modules, security framework, datasets, documentation, test cases, and development utilities.

```text
compiler-error-explanation-ast-nlp/
│
├── src/
│   ├── gui.py
│   ├── main.py
│   ├── compiler_runner.py
│   ├── error_parser.py
│   ├── error_explainer.py
│   ├── error_classifier.py
│   ├── second_opinion.py
│   ├── ast_extractor.py
│   ├── heal_loop.py
│   ├── auto_healer.py
│   ├── optimizer.py
│   ├── complexity_analyzer.py
│   ├── security_analyzer.py
│   ├── energy_monitor.py
│   ├── optimization_view.py
│   ├── security_view.py
│   ├── gui_new_pages.py
│   ├── accuracy_benchmark.py
│   ├── ui_components.py
│   ├── diff_viewer.py
│   └── guard/
│
├── data/
│   └── Training datasets and model artifacts
│
├── test_cases/
│   └── C++ test programs
│
├── all_test_cases/
│   └── Larger C++ test programs and repaired examples
│
├── tests/
│   └── Automated test suites
│
├── tools/
│   └── Training, verification, benchmarking and testing utilities
│
├── assets/
│   └── Application assets
│
├── .env.example
├── requirements.txt
├── DOCUMENTATION.md
├── PBL_Report.md
└── README.md
```

*Note: This is a representative structure. Some supporting files and subdirectories have been omitted for readability.*

---

## Prerequisites

Install the following software before running the project.

| Requirement | Purpose |
|---|---|
| Python 3.10+ | Run the application |
| pip | Install Python dependencies |
| Git | Clone the repository |
| GCC/G++ | Compile C++ programs |
| Clang/Clang++ | Extract Abstract Syntax Trees |

Verify the installations:

```bash
python --version
pip --version
git --version
g++ --version
clang++ --version
```

Make sure GCC/G++ and Clang/Clang++ are accessible through your system PATH.

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/thrishi1011/compiler-error-explanation-ast-nlp.git
```

### Step 2: Navigate to the Project Directory

```bash
cd compiler-error-explanation-ast-nlp
```

### Step 3: Create a Virtual Environment

**Windows:**

```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 4: Upgrade pip

```bash
python -m pip install --upgrade pip
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

The primary dependencies include:

- PyQt6
- Scikit-learn
- Joblib
- CodeCarbon
- psutil

---

## Configuration

The project supports AI-powered assistance through Google Gemini and Groq.

### Configure API Keys

1. Create a `.env` file in the project root directory.
2. Add the API keys for the providers you want to use.
3. Configure the model IDs.

**Recommended configuration:**

```env
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key

GEMINI_MODEL=gemini-2.5-flash
GROQ_MODEL=llama-3.3-70b-versatile
```

**Recommended models:**

- Gemini: `gemini-2.5-flash`
- Groq: `llama-3.3-70b-versatile`

The application uses Gemini as its primary AI provider and Groq for supported optimization and complexity-analysis workflows, as configured in the project.

Check current model availability:

- [Google Gemini Models](https://ai.google.dev/gemini-api/docs/models)
- [Groq Models](https://console.groq.com/docs/models)

**Important:**

- API keys are required for the corresponding AI-powered integrations.
- Local compilation and supported analysis features can operate without AI credentials.
- AI functionality requires internet connectivity and available provider quota.
- Never upload your `.env` file or expose API keys publicly.

---

## Running the Application

After installing dependencies and configuring the required tools, launch the desktop application.

Make sure your virtual environment is activated and your terminal is inside the project root directory.

Run:

```bash
python src/gui.py
```

**Use `src/gui.py` to launch the main PyQt6 desktop application.**

The GUI provides access to the available development and analysis features.

### Optional: Command-Line Analysis

The project also includes a CLI analysis entry point.

To analyze a C++ source file:

```bash
python src/main.py file.cpp
```

For additional output options:

```bash
python src/main.py file.cpp -j -v
```

The CLI supports structured output and additional diagnostic context through its available arguments.

---

## Application Workflow

A typical workflow is:

1. **Launch:** Start the desktop application using `python src/gui.py`.
2. **Load Code:** Open or enter a C++ source file.
3. **Compile:** Compile the source and inspect compiler diagnostics.
4. **Analyze:** Review error classifications, explanations, and suggestions.
5. **Second Opinion:** Check additional analysis where available.
6. **Repair:** Run the automatic healing workflow for supported errors.
7. **Validate:** Recompile the repaired code and inspect the results.
8. **Explore AST:** Inspect the source code's Abstract Syntax Tree.
9. **Optimize:** Review complexity and optimization suggestions.
10. **Security:** Run security analysis and inspect findings.
11. **Execute:** Run the compiled program and inspect its output.
12. **Monitor:** Review available resource and energy information.

---

## Machine Learning and Error Analysis

The project combines Machine Learning, curated error knowledge, and fallback mechanisms to interpret compiler diagnostics.

### TF-IDF Vectorization

TF-IDF converts textual compiler messages into numerical feature representations.

### Logistic Regression

The trained Logistic Regression classifier predicts compiler error categories using the extracted features.

### Error Explanation

The diagnostic processing pipeline can combine:

- Curated common-error knowledge.
- ML-based classification.
- Regex-based fallback classification.
- AI-generated explanations when configured.
- AST context where available.

The trained model is serialized using Joblib and loaded by the application when the required artifacts are present.

---

## Security Framework

The project includes a modular security framework under `src/guard/`.

The framework supports security checks around application operations and source-code handling.

Security-related capabilities include:

- Source-code security analysis.
- Input and output validation.
- Path-safety checks.
- Detection of potentially unsafe operations.
- Security findings and reporting.
- Protective checks for supported compilation and execution workflows.
- Security-related testing and verification utilities.

Security analysis is intended to help identify potential risks. It should not be considered a guarantee that every vulnerability will be detected.

---

## Testing

The repository includes automated tests, sample C++ programs, and verification utilities.

The test resources cover areas such as:

- GUI structure and interactions.
- Compiler error handling.
- Automatic healing.
- Machine Learning and AI fallback behavior.
- Security framework phases.
- Security documentation.
- Different C++ compilation scenarios.

The main test directories are:

```text
tests/
test_cases/
all_test_cases/
tools/
```

To run the Python test suite, install pytest if it is not already available:

```bash
pip install pytest
```

Then run:

```bash
python -m pytest tests/
```

Individual verification and benchmarking utilities are available under `tools/`.

---

## Additional Documentation

For more detailed technical information, refer to:

- **[DOCUMENTATION.md](DOCUMENTATION.md):** Technical documentation, application workflow, internal modules, architecture, and troubleshooting.
- **[PBL_Report.md](PBL_Report.md):** Project report and supporting project details.

---

## Important Notes

- Run the application from the repository root directory.
- Use `python src/gui.py` to launch the desktop GUI.
- GCC/G++ is required for C++ compilation.
- Clang/Clang++ is required for AST extraction.
- AI-powered functionality depends on valid API configuration.
- Some energy-monitoring capabilities depend on operating-system and hardware support.
- Ensure required trained-model artifacts and supporting data files are present.
- Some analysis and repair features are limited to the patterns and cases supported by their implementations.

---

## Author

**Thrishi**

GitHub: [@thrishi1011](https://github.com/thrishi1011)

Repository: [Compiler Error Explanation, AST Analysis & Code Optimization](https://github.com/thrishi1011/compiler-error-explanation-ast-nlp)

---
