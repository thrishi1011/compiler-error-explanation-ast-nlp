# Compiler Error Explanation, AST Analysis & Code Optimization

An intelligent C++ development assistant that combines Machine Learning, Natural Language Processing, Abstract Syntax Tree analysis, AI-powered assistance, and automated code analysis to help developers identify, understand, repair, and optimize C++ programs.

The project provides a desktop-based graphical interface where developers can compile programs, understand compiler errors, explore code structure, detect security vulnerabilities, and improve code quality.

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
- [Machine Learning Model](#machine-learning-model)
- [Important Notes](#important-notes)

---

## Overview

Traditional compiler error messages can be difficult for beginners and even experienced developers to understand, particularly when a program contains multiple errors or complex syntax issues.

This project addresses that problem by combining compiler diagnostics with Machine Learning and AI-assisted explanations.

Instead of simply displaying compiler errors, the application attempts to:

1. Identify and classify compilation errors.
2. Explain errors in understandable language.
3. Suggest possible corrections.
4. Automatically repair selected code errors.
5. Extract and visualize the Abstract Syntax Tree.
6. Analyze code complexity and optimization opportunities.
7. Detect potential security vulnerabilities.
8. Monitor execution-related resource and energy usage.

The application brings these capabilities together through a PyQt6 desktop interface.

---

## Key Features

### 1. C++ Compilation and Error Detection
- Compile C++ programs using GCC/G++.
- Capture compiler output and diagnostic messages.
- Identify compilation failures and display relevant information.
- Support C++17 compilation.

### 2. Machine Learning-Based Error Classification
- Classify compiler errors using a trained Machine Learning model.
- Use TF-IDF to convert error messages into numerical features.
- Apply Logistic Regression for error classification.
- Use classification results to support the explanation process.

### 3. AI-Powered Error Explanation
- Convert complex compiler diagnostics into understandable explanations.
- Provide suggestions for correcting programming mistakes.
- Integrate with Gemini and Groq for AI-assisted responses.
- Help developers understand why an error occurs instead of simply showing the compiler output.

### 4. Automatic Code Repair
- Analyze compilation errors and relevant source code.
- Attempt to identify and correct common programming mistakes.
- Support an iterative repair workflow.
- Allow developers to compile and check the repaired code.

### 5. Abstract Syntax Tree Analysis
- Extract the Abstract Syntax Tree using Clang.
- Represent the structural organization of C++ source code.
- Help developers understand relationships between programming constructs.
- Provide an AST exploration and visualization interface.

### 6. Code Optimization
- Analyze source code for possible improvements.
- Identify optimization opportunities.
- Generate optimized code suggestions.
- Help improve code efficiency while considering program behavior.

### 7. Complexity Analysis
- Analyze the computational complexity of code.
- Provide insights into time and space complexity.
- Help developers identify potentially inefficient sections.

### 8. Security Analysis
- Scan source code for potential security vulnerabilities.
- Identify suspicious or unsafe coding patterns.
- Provide security-related analysis through the project's security framework.

### 9. Code Quality Analysis
- Identify possible code quality issues.
- Provide suggestions for improving readability and maintainability.
- Help developers write cleaner code.

### 10. Energy and Resource Monitoring
- Monitor execution-related resource usage.
- Integrate CodeCarbon and psutil for supported monitoring capabilities.
- Provide additional insights into the resource and energy impact of program execution.

### 11. Desktop Graphical Interface
- Built using PyQt6.
- Provides access to compilation, explanations, repair, optimization, AST exploration, and security analysis.
- Includes a graphical interface for interacting with analysis results.

---

## Technology Stack

| Component | Technology |
|---|---|
| Primary Language | Python |
| Programming Language Analysis | C++ |
| Desktop GUI | PyQt6 |
| Machine Learning | Scikit-learn |
| NLP | TF-IDF |
| Classification Algorithm | Logistic Regression |
| C++ Compiler | GCC/G++ |
| AST Extraction | Clang/Clang++ |
| AI Integration | Gemini, Groq |
| Model Storage | Joblib |
| Energy Monitoring | CodeCarbon |
| System Monitoring | psutil |

---

## System Architecture

The application combines multiple components to provide an integrated C++ development assistance workflow.

**1. Input Layer**

The developer loads or enters a C++ source file through the desktop application.

**2. Compilation Layer**

GCC/G++ compiles the source code and generates compiler diagnostics when errors are encountered.

**3. Error Analysis Layer**

Compiler diagnostics are processed using the Machine Learning classifier and supporting analysis components.

**4. AI Explanation Layer**

AI integrations provide additional explanations and suggestions when configured.

**5. Automatic Repair Layer**

The repair workflow attempts to correct identified errors and validate the resulting source code.

**6. Code Analysis Layer**

The application provides AST extraction, complexity analysis, optimization, and security analysis.

**7. Output Layer**

The desktop interface presents compilation results, explanations, repair results, and analysis information.

---

## Project Structure

The project is organized into separate modules for the graphical interface, compilation, Machine Learning, AI integration, code analysis, and supporting resources.

```text
compiler-error-explanation-ast-nlp/
│
├── src/
│   ├── gui.py
│   ├── main.py
│   ├── compiler_runner.py
│   ├── llm_client.py
│   ├── heal_loop.py
│   ├── optimizer.py
│   ├── ast_extractor.py
│   ├── complexity_analyzer.py
│   ├── optimization_view.py
│   └── guard/
│
├── data/
│   ├── error_classifier.joblib
│   └── training datasets and supporting resources
│
├── requirements.txt
├── .env.example
├── README.md
└── LICENSE
```

*Note: This is a high-level representation. Individual files and supporting resources may vary as the project evolves.*

---

## Prerequisites

Before installing the project, make sure the following software is available:

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

GCC/G++ and Clang/Clang++ should be accessible through your system PATH.

---

## Installation

Follow these steps to install and configure the project on your local machine.

### Step 1: Clone the Repository

```bash
git clone https://github.com/thrishi1011/compiler-error-explanation-ast-nlp.git
```

### Step 2: Navigate to the Project Directory

```bash
cd compiler-error-explanation-ast-nlp
```

### Step 3: Create a Virtual Environment

A virtual environment keeps the project's Python dependencies separate from other Python projects.

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

### Step 5: Install Required Dependencies

Install the packages listed in `requirements.txt`.

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

The project supports AI-powered explanations through Google Gemini and Groq.

### Configure API Keys

1. Create a file named `.env` in the project root.
2. Add the API credentials for the provider you want to use.
3. Set the model IDs.

**Recommended configuration:**

```env
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key

GEMINI_MODEL=gemini-2.5-flash
GROQ_MODEL=llama-3.3-70b-versatile
```

The recommended model IDs are:

- **Gemini:** `gemini-2.5-flash`
- **Groq:** `llama-3.3-70b-versatile`

Model availability may change. Check the providers' documentation for current availability:

- [Gemini Models](https://ai.google.dev/gemini-api/docs/models)
- [Groq Models](https://console.groq.com/docs/models)

**Important:**
- API keys are required only for the corresponding AI-powered integrations.
- Core local compilation and analysis do not inherently require an AI API key.
- AI responses require internet connectivity and available provider quota.
- Never commit your `.env` file or expose your API credentials publicly.

---

## Running the Application

After completing the installation and configuration steps, launch the desktop application.

Make sure your virtual environment is activated and that your terminal is currently inside the project root directory.

Run:

```bash
python src/gui.py
```

**Use `src/gui.py` to start the graphical desktop application.**

The PyQt6 interface should open, allowing you to interact with the project's available features.

---

## Application Workflow

A typical workflow for using the application is:

1. **Open the application:** Start the desktop interface using `python src/gui.py`.
2. **Load source code:** Open an existing C++ file or enter source code.
3. **Compile:** Use the compilation functionality to compile the program.
4. **Analyze errors:** Review compiler diagnostics and available Machine Learning classifications.
5. **Understand errors:** View explanations and suggested corrections.
6. **Repair code:** Use the automatic repair functionality when appropriate.
7. **Explore AST:** Examine the Abstract Syntax Tree generated from the source code.
8. **Optimize code:** Analyze the program and review possible optimization suggestions.
9. **Check security:** Run security analysis to identify potential vulnerabilities.
10. **Review results:** Inspect the available compilation, repair, optimization, and analysis outputs.

---

## Machine Learning Model

The project uses a Machine Learning-based approach to classify compiler error messages.

### Model Pipeline

**TF-IDF Vectorization**

Converts textual compiler error messages into numerical feature representations that can be processed by a Machine Learning algorithm.

**Logistic Regression**

Uses the extracted features to predict the corresponding compiler error category.

**Trained Model**

The trained model is stored using Joblib and loaded by the application during execution.

### Training Data

The project uses compiler error datasets to support the classification process.

The model can be updated or retrained when additional training examples or improved datasets become available.

The existing trained model can be used without retraining, provided its required model files are present.

---

## Important Notes

- Run the application from the repository root directory.
- Use `python src/gui.py` to launch the desktop interface.
- GCC/G++ must be installed for C++ compilation.
- Clang/Clang++ must be installed for full AST extraction.
- AI-powered functionality depends on valid API configuration.
- Some resource and energy monitoring features depend on system support and installed packages.
- Ensure the trained Machine Learning model and required data files are present.
- If dependencies are missing, reinstall them using `pip install -r requirements.txt`.

---

## Author

**Thrishi**

GitHub: [@thrishi1011](https://github.com/thrishi1011)

Repository: [Compiler Error Explanation, AST Analysis & Code Optimization](https://github.com/thrishi1011/compiler-error-explanation-ast-nlp)

---
