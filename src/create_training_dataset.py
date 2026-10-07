"""
create_training_dataset.py
--------------------------
Builds a balanced, high-quality C/C++ compiler error training dataset by
combining:
1. Real novice C/C++ compiler errors from TEGCER (IIT Kanpur CS1 dataset:
   21,995 student runs and 212 normalized compiler error templates).
2. Curated samples from the original CodeNet corpus (deduplicated & cleaned).
3. Dedicated C++ domain patterns for linker errors, access errors, return type
   errors, and missing include directives.

Saves the balanced dataset into data/training_data.json ready for training.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import urllib.request
import zipfile
from collections import Counter
from typing import Dict, List, Set, Tuple

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_OUTPUT_FILE = os.path.join(_DATA_DIR, "training_data.json")
_BACKUP_FILE = os.path.join(_DATA_DIR, "training_data_original.json")

# Target 9 canonical categories
CATEGORIES = [
    "syntax_error",
    "name_resolution",
    "type_error",
    "missing_include",
    "linker_error",
    "redefinition",
    "access_error",
    "return_type_error",
    "other",
]

# Classification rule function for incoming raw messages
def classify_message(msg: str) -> str:
    m = msg.lower()

    # 1. Missing include (check first before name resolution)
    if any(k in m for k in [
        "file not found", "no such file or directory", "cannot open include file",
        "#include expects", "did you forget to '#include", "did you forget to '#include <",
        "was not declared in this scope; did you forget to '#include"
    ]):
        return "missing_include"

    # 2. Linker errors
    if any(k in m for k in [
        "undefined reference to", "ld returned", "linker error", "unresolved external symbol",
        "symbol(s) not found", "cannot find -l", "multiple definition of", "relocation truncated"
    ]):
        if "multiple definition of" in m:
            return "redefinition"
        return "linker_error"

    # 3. Access errors (OOP & const/read-only)
    if any(k in m for k in [
        "is private within this context", "is private", "is protected", "inaccessible",
        "cannot access", "assignment of read-only", "read-only variable", "read-only location",
        "passing 'const' as 'this' argument discards qualifiers"
    ]):
        return "access_error"

    # 4. Return type errors
    if any(k in m for k in [
        "control reaches end of non-void function", "no return statement",
        "return-type defaults to", "return with a value, in function returning void",
        "return with no value, in function returning", "void function should not return a value",
        "non-void function should return a value", "incompatible return type",
        "cannot convert", "in return"
    ]) and any(w in m for w in ["return", "non-void", "void"]):
        return "return_type_error"

    # 5. Redefinition
    if any(k in m for k in [
        "redefinition of", "conflicting types for", "already defined",
        "previous definition of", "redeclaration of"
    ]):
        return "redefinition"

    # 6. Name resolution / undeclared identifiers
    if any(k in m for k in [
        "undeclared", "not declared in this scope", "not declared",
        "unknown type name", "cannot be used as a type", "has not been declared",
        "is not a member of", "was not declared", "did you mean"
    ]):
        return "name_resolution"

    # 7. Type errors
    if any(k in m for k in [
        "cannot convert", "invalid conversion", "incompatible type", "incompatible pointer",
        "invalid operands to binary", "invalid operands", "no matching function for call",
        "too many arguments to function", "too few arguments to function",
        "subscripted value is not an array", "called object", "is not a function",
        "indirection requires pointer", "array subscript is not", "format specifies type",
        "invalid cast", "cannot be applied to", "assigning to", "initializing"
    ]):
        return "type_error"

    # 8. Syntax errors
    if any(k in m for k in [
        "expected ';'", "expected ')'", "expected '}'", "expected '{'", "expected ']' ",
        "expected expression", "expected identifier", "expected declaration", "expected unqualified-id",
        "missing terminating", "stray '\\", "stray '", "parse error", "extraneous closing brace",
        "expected before", "expected after", "before numeric constant", "before string constant",
        "expected initializer", "expected primary-expression"
    ]):
        return "syntax_error"

    return "other"


def fetch_tegcer_data() -> List[Dict]:
    """Download TEGCER error_IDs and dataset.csv messages."""
    entries = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    # 1. error_IDs.csv (canonical templates)
    print("  [1/4] Fetching TEGCER error_IDs.csv...")
    try:
        url = "https://raw.githubusercontent.com/umairzahmed/tegcer/master/data/input/error_IDs.csv"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            msg = row.get("error_message", "").strip()
            if msg:
                cat = classify_message(msg)
                entries.append({"message": msg, "category": cat, "source": "tegcer_template"})
    except Exception as e:
        print(f"    Warning: Could not fetch TEGCER error_IDs: {e}")

    # 2. dataset.zip (real student compilation outputs)
    print("  [2/4] Fetching TEGCER dataset.zip (21,995 student runs)...")
    try:
        url = "https://raw.githubusercontent.com/umairzahmed/tegcer/master/data/input/dataset.zip"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            buf = io.BytesIO(resp.read())

        err_pattern = re.compile(r":\s*(?:error|fatal error|warning):\s*(.+)$", re.MULTILINE)
        with zipfile.ZipFile(buf) as z:
            with z.open("dataset.csv") as f:
                reader = csv.DictReader(io.TextIOWrapper(f, encoding="utf-8", errors="ignore"))
                for row in reader:
                    err_raw = row.get("errorClang", "")
                    if err_raw:
                        for m in err_pattern.findall(err_raw):
                            clean_msg = m.strip()
                            # Clean out terminal codes and noise
                            clean_msg = re.sub(r"\[-W[^\]]+\]", "", clean_msg).strip()
                            if len(clean_msg) > 4:
                                cat = classify_message(clean_msg)
                                entries.append({"message": clean_msg, "category": cat, "source": "tegcer_student"})
    except Exception as e:
        print(f"    Warning: Could not fetch TEGCER dataset.zip: {e}")

    return entries


def fetch_original_data() -> List[Dict]:
    """Load high-quality clean examples from training_data_original.json."""
    print("  [3/4] Ingesting & re-filtering original dataset...")
    entries = []
    if os.path.exists(_BACKUP_FILE):
        try:
            with open(_BACKUP_FILE, "r", encoding="utf-8", errors="ignore") as f:
                raw_data = json.load(f)
            for item in raw_data:
                msg = item.get("message", "").strip()
                if not msg or len(msg) < 4:
                    continue
                # Skip non-ascii garbage
                if any(ord(c) > 127 for c in msg):
                    continue
                # Recalculate category using the rules for consistency
                orig_cat = item.get("category", "")
                rule_cat = classify_message(msg)
                # If rule finds a specific category, use it; otherwise preserve valid original category
                final_cat = rule_cat if rule_cat != "other" else orig_cat
                if final_cat in CATEGORIES:
                    entries.append({"message": msg, "category": final_cat, "source": "codenet_clean"})
        except Exception as e:
            print(f"    Warning: Could not read backup file: {e}")
    return entries


def get_curated_cpp_patterns() -> List[Dict]:
    """High-precision C++ patterns for categories underrepresented in pure C."""
    print("  [4/4] Adding C++ domain patterns (linker, access, headers, return)...")
    curated = []

    # 1. Linker error patterns across common symbols and libraries
    linker_symbols = [
        "main", "printf", "scanf", "malloc", "free", "pow", "sqrt", "sin", "cos",
        "strlen", "strcpy", "strcmp", "memcpy", "memset", "pthread_create", "pthread_join",
        "dlopen", "dlsym", "std::cout", "std::cin", "std::endl", "std::string",
        "std::vector", "std::map", "std::thread", "std::mutex", "operator new(unsigned long long)",
        "operator delete(void*)", "vtable for Base", "vtable for Derived", "vtable for Animal",
        "vtable for Shape", "typeinfo for Base", "typeinfo for Shape", "Calculator::compute()",
        "Server::start()", "Database::connect()", "Engine::run()", "Parser::parse()",
        "Vector3D::normalize()", "Matrix::multiply()", "Game::init()", "Window::create()"
    ]
    for sym in linker_symbols:
        curated.append((f"undefined reference to `{sym}'", "linker_error"))
        curated.append((f"undefined reference to '{sym}'", "linker_error"))
        curated.append((f"unresolved external symbol \"{sym}\" referenced in function", "linker_error"))

    linker_libs = ["m", "pthread", "stdc++", "dl", "ssl", "crypto", "curl", "sqlite3", "boost_system", "GL", "X11"]
    for lib in linker_libs:
        curated.append((f"cannot find -l{lib}: No such file or directory", "linker_error"))
        curated.append((f"cannot find -l{lib}", "linker_error"))

    curated.extend([
        ("collect2: error: ld returned 1 exit status", "linker_error"),
        ("collect2.exe: error: ld returned 1 exit status", "linker_error"),
        ("fatal error: ld returned 1 exit status", "linker_error"),
        ("symbol(s) not found for architecture x86_64", "linker_error"),
        ("symbol(s) not found for architecture arm64", "linker_error"),
        ("symbol(s) not found for architecture i386", "linker_error"),
        ("relocation truncated to fit: R_X86_64_PC32 against symbol `count'", "linker_error"),
        ("duplicate symbol '_main' in main.o and test.o", "linker_error"),
    ])

    # 2. Return type error patterns across functions and types
    funcs = [
        "calculate", "compute", "get_val", "is_valid", "find_min", "find_max",
        "process", "solve", "check", "run", "execute", "get_sum", "average",
        "to_string", "parse", "get_count", "eval", "convert", "search"
    ]
    types = [
        "int", "double", "float", "char", "bool", "long", "short", "unsigned int",
        "std::string", "char*", "int*", "double*", "const char*", "void*", "size_t"
    ]
    for fn in funcs:
        curated.append((f"warning: control reaches end of non-void function in '{fn}' [-Wreturn-type]", "return_type_error"))
        curated.append((f"error: void function '{fn}' should not return a value", "return_type_error"))
        curated.append((f"error: non-void function '{fn}' should return a value", "return_type_error"))
        curated.append((f"error: return-type defaults to 'int' in declaration of '{fn}'", "return_type_error"))
        curated.append((f"error: return with a value, in function '{fn}' returning void", "return_type_error"))

    for ty in types:
        curated.append((f"error: return with no value, in function returning '{ty}'", "return_type_error"))
        curated.append((f"error: cannot convert 'void' to '{ty}' in return", "return_type_error"))
        curated.append((f"error: cannot convert 'nullptr' to '{ty}' in return", "return_type_error"))

    curated.extend([
        ("warning: control reaches end of non-void function [-Wreturn-type]", "return_type_error"),
        ("error: no return statement in function returning non-void", "return_type_error"),
        ("error: return-type defaults to 'int' in declaration of function", "return_type_error"),
        ("error: return with a value, in function returning void", "return_type_error"),
        ("error: return with no value, in function returning non-void", "return_type_error"),
        ("error: void function should not return a value", "return_type_error"),
        ("error: non-void function should return a value", "return_type_error"),
        ("error: inconsistent deduction for 'auto' return type: 'int' and then 'double'", "return_type_error"),
        ("error: inconsistent deduction for 'auto' return type: 'std::string' and then 'const char*'", "return_type_error"),
        ("error: function returning an array is not allowed", "return_type_error"),
        ("error: 'main' must return 'int'", "return_type_error"),
        ("error: return type of 'main' is not 'int'", "return_type_error"),
    ])

    # 3. Access errors (OOP & const/read-only)
    members = ["secret", "password", "balance", "data", "id", "ptr", "buffer", "key", "config", "token"]
    classes = ["MyClass", "Account", "Worker", "Node", "Container", "Session", "Handler", "Base", "Security"]
    for cls in classes:
        for m in members[:3]:
            curated.append((f"error: 'int {cls}::{m}' is private within this context", "access_error"))
            curated.append((f"error: 'void {cls}::{m}()' is protected within this context", "access_error"))
            curated.append((f"error: '{m}' is a private member of '{cls}'", "access_error"))
            curated.append((f"error: '{m}' is a protected member of '{cls}'", "access_error"))

    curated.extend([
        ("error: 'class Base' is inaccessible within this context", "access_error"),
        ("error: assignment of read-only variable 'MAX_SIZE'", "access_error"),
        ("error: assignment of member 'Config::port' in read-only object", "access_error"),
        ("error: passing 'const Student' as 'this' argument discards qualifiers", "access_error"),
        ("error: cannot assign to variable 'PI' with const-qualified type 'const double'", "access_error"),
        ("error: cannot call non-const member function on const reference", "access_error"),
        ("error: assignment of read-only location", "access_error"),
        ("error: assignment of read-only member 'Node::val'", "access_error"),
        ("error: cannot modify const object", "access_error"),
    ])

    # 4. Missing include
    headers = ["iostream", "vector", "string", "cstdio", "algorithm", "cmath", "map", "set", "memory", "sstream", "queue"]
    for h in headers:
        curated.append((f"fatal error: {h}: No such file or directory", "missing_include"))
        curated.append((f"fatal error: '{h}' file not found", "missing_include"))
        curated.append((f"fatal error: <{h}>: No such file or directory", "missing_include"))

    curated.extend([
        ("error: 'std::cout' was not declared in this scope; did you forget to '#include <iostream>'?", "missing_include"),
        ("error: 'std::cin' was not declared in this scope; did you forget to '#include <iostream>'?", "missing_include"),
        ("error: 'std::vector' was not declared in this scope; did you forget to '#include <vector>'?", "missing_include"),
        ("error: 'std::string' was not declared in this scope; did you forget to '#include <string>'?", "missing_include"),
        ("error: 'std::sort' was not declared in this scope; did you forget to '#include <algorithm>'?", "missing_include"),
        ("error: 'std::sqrt' was not declared in this scope; did you forget to '#include <cmath>'?", "missing_include"),
        ("error: #include expects \"FILENAME\" or <FILENAME>", "missing_include"),
        ("error: empty filename in #include", "missing_include"),
        ("error: #include nested too deeply", "missing_include"),
    ])

    return [{"message": msg, "category": cat, "source": "curated_cpp"} for msg, cat in curated]



def build_balanced_dataset(max_per_category: int = 1200, min_per_category: int = 150) -> List[Dict]:
    """Merges all sources and produces a balanced, high-precision dataset."""
    raw_entries: List[Dict] = []

    # 1. Fetch TEGCER
    raw_entries.extend(fetch_tegcer_data())

    # 2. Original clean dataset
    raw_entries.extend(fetch_original_data())

    # 3. Curated C++ specific patterns
    raw_entries.extend(get_curated_cpp_patterns())

    print(f"\nTotal raw collected entries: {len(raw_entries)}")

    # Deduplicate by (normalized_message, category)
    by_category: Dict[str, List[Dict]] = {cat: [] for cat in CATEGORIES}
    seen_messages: Set[Tuple[str, str]] = set()

    for item in raw_entries:
        cat = item.get("category", "other")
        if cat not in by_category:
            continue
        msg = item.get("message", "").strip()
        norm_key = (re.sub(r"['\"`\d]", "", msg).lower(), cat)
        if norm_key in seen_messages:
            continue
        seen_messages.add(norm_key)

        by_category[cat].append({
            "message": msg,
            "category": cat,
            "ast_node": "",
            "explanation": "",
            "suggestion": "",
            "confidence": 1.0,
        })

    # Balance: cap each class at max_per_category
    balanced: List[Dict] = []
    print("\nCategory Distribution in New Dataset:")
    print("  " + "-" * 45)
    print(f"  {'Category':<22} {'Raw Unique':>10} {'Final Kept':>10}")
    print("  " + "-" * 45)

    for cat in CATEGORIES:
        pool = by_category[cat]
        # Prioritize curated and tegcer samples first
        pool.sort(key=lambda x: 0 if "curated" in x.get("message", "") else (1 if "error:" in x.get("message", "") else 2))
        kept = pool[:max_per_category]
        balanced.extend(kept)
        print(f"  {cat:<22} {len(pool):>10} {len(kept):>10}")

    print("  " + "-" * 45)
    print(f"  {'TOTAL':<22} {sum(len(v) for v in by_category.values()):>10} {len(balanced):>10}\n")
    return balanced


def main():
    print("=" * 60)
    print("  BUILDING ENRICHED & BALANCED TRAINING DATASET")
    print("=" * 60)

    # 1. Ensure backup
    if not os.path.exists(_BACKUP_FILE) and os.path.exists(_OUTPUT_FILE):
        import shutil
        shutil.copyfile(_OUTPUT_FILE, _BACKUP_FILE)
        print(f"Backup preserved: {_BACKUP_FILE}")

    # 2. Build balanced dataset
    dataset = build_balanced_dataset(max_per_category=1000)

    # 3. Save
    with open(_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=True)

    print(f"[OK] New dataset saved to {_OUTPUT_FILE}")
    print(f"     Total balanced samples: {len(dataset)}")
    print("     (Model is NOT trained yet as requested.)\n")


if __name__ == "__main__":
    main()
