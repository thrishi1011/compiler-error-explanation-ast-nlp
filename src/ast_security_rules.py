from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

import ast_extractor
from security_analyzer import (
    SecurityFinding,
    CWE_DEFINITIONS,
    CERT_DEFINITIONS,
    _make_finding,
)

# Dangerous functions mapped to their primary weakness
_DANGEROUS_FUNCTIONS: dict[str, dict[str, str]] = {
    "gets": {
        "vuln": "Buffer Overflow",
        "sev": "Critical",
        "desc": "Function 'gets()' does not check buffer bounds and is inherently vulnerable to stack buffer overflow.",
        "rec": "Replace 'gets()' with 'fgets()' or modern C++ 'std::getline(std::cin, str)'.",
    },
    "strcpy": {
        "vuln": "Unsafe String Function",
        "sev": "High",
        "desc": "Function 'strcpy()' does not check destination buffer boundaries before copying.",
        "rec": "Replace with 'strncpy()', 'snprintf()', or use 'std::string'.",
    },
    "strcat": {
        "vuln": "Unsafe String Function",
        "sev": "High",
        "desc": "Function 'strcat()' does not verify destination buffer space, risking buffer overflow.",
        "rec": "Replace with 'strncat()' or modern 'std::string::operator+='.",
    },
    "sprintf": {
        "vuln": "Format String Vulnerability",
        "sev": "High",
        "desc": "Function 'sprintf()' writes unbounded output to a buffer without size checks.",
        "rec": "Replace with 'snprintf()' specifying buffer capacity or use 'std::ostringstream'.",
    },
    "system": {
        "vuln": "Command Injection",
        "sev": "Critical",
        "desc": "Invoking 'system()' passes raw command strings to the shell, risking command injection.",
        "rec": "Avoid executing shell commands; use POSIX execve/fork or platform APIs without shell interpretation.",
    },
}

_ARRAY_DECL_RE = re.compile(
    r"\b(?:int|char|float|double|long|short|unsigned|uint\w*|size_t)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]"
)
_ARRAY_ACCESS_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]")
_MACRO_DEF_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)")
_FREE_OR_DELETE_RE = re.compile(r"\b(?:free\s*\(\s*([A-Za-z_]\w*)\s*\)|delete\s*(?:\[\])?\s*([A-Za-z_]\w*))\s*;")
_POINTER_DEREF_RE = re.compile(r"(?:\*\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*->)")

def _extract_macro_aliases(code: str) -> dict[str, str]:
    """Map macro aliases such as '#define G gets' -> {'G': 'gets'}."""
    aliases = {}
    for line in code.splitlines():
        m = _MACRO_DEF_RE.match(line)
        if m:
            alias, target = m.group(1), m.group(2)
            if target in _DANGEROUS_FUNCTIONS:
                aliases[alias] = target
    return aliases

def analyze_ast(source_path: str, code: Optional[str] = None) -> list[SecurityFinding]:
    """Perform structural AST and control-flow checks inspired by CodeQL C++ queries."""
    if code is None:
        if not source_path or not os.path.isfile(source_path):
            return []
        try:
            with open(source_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        except Exception:
            return []

    findings: list[SecurityFinding] = []
    lines = code.splitlines()

    # 1. Macro alias resolution (resolving regex evasion such as #define G gets)
    aliases = _extract_macro_aliases(code)

    # 2. Extract AST representation
    ast_text = ast_extractor.extract_ast(source_path, code) or ""
    if not ast_text:
        ast_text = ast_extractor.generate_fallback_ast_text(code, source_path)

    # Array declarations and sizes: name -> (size, decl_line)
    declared_arrays: dict[str, tuple[int, int]] = {}

    # Track freed variables for Use-After-Free & Double-Free: var -> free_line
    freed_vars: dict[str, int] = {}

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        # Rule 1: CodeQL cpp/dangerous-function-overflow (handling direct calls & macro aliases)
        # Check direct calls
        for fn_name, info in _DANGEROUS_FUNCTIONS.items():
            if re.search(rf"\b{re.escape(fn_name)}\s*\(", line):
                findings.append(
                    _make_finding(
                        source_path=source_path,
                        line=idx,
                        column=line.find(fn_name) + 1,
                        severity=info["sev"],  # type: ignore[arg-type]
                        vulnerability_type=info["vuln"],
                        description=f"[AST/CodeQL] {info['desc']}",
                        recommendation=info["rec"],
                        source="ast_scan",
                    )
                )

        # Check macro-aliased calls e.g., G(buf) where #define G gets
        for alias, fn_name in aliases.items():
            if re.search(rf"\b{re.escape(alias)}\s*\(", line):
                info = _DANGEROUS_FUNCTIONS[fn_name]
                findings.append(
                    _make_finding(
                        source_path=source_path,
                        line=idx,
                        column=line.find(alias) + 1,
                        severity=info["sev"],  # type: ignore[arg-type]
                        vulnerability_type=info["vuln"],
                        description=f"[AST/CodeQL] Macro alias '{alias}' expands to dangerous function '{fn_name}()'. {info['desc']}",
                        recommendation=info["rec"],
                        source="ast_scan",
                    )
                )

        # Rule 2: CodeQL cpp/out-of-bounds-array-access
        # Track array declarations
        arr_decl = _ARRAY_DECL_RE.search(line)
        if arr_decl:
            arr_name = arr_decl.group(1)
            arr_size = int(arr_decl.group(2))
            declared_arrays[arr_name] = (arr_size, idx)

        # Check array subscript access
        for access in _ARRAY_ACCESS_RE.finditer(line):
            target_name = access.group(1)
            index_val = int(access.group(2))
            if target_name in declared_arrays:
                max_size, decl_line = declared_arrays[target_name]
                if idx == decl_line:
                    continue  # Do not treat the declaration itself as a subscript access
                if index_val >= max_size:
                    findings.append(
                        _make_finding(
                            source_path=source_path,
                            line=idx,
                            column=access.start() + 1,
                            severity="Critical",
                            vulnerability_type="Buffer Overflow",
                            description=(
                                f"[AST/CodeQL] Array subscript index [{index_val}] is out of bounds for array "
                                f"'{target_name}' declared with size [{max_size}] at line {decl_line}."
                            ),
                            recommendation=(
                                f"Ensure index is strictly within range [0, {max_size - 1}], "
                                "or use std::array / std::vector with bounds-checked '.at()'."
                            ),
                            source="ast_scan",
                        )
                    )

        # Rule 3: CodeQL cpp/use-after-free and cpp/double-free
        free_match = _FREE_OR_DELETE_RE.search(line)
        if free_match:
            var_name = free_match.group(1) or free_match.group(2)
            if var_name:
                if var_name in freed_vars:
                    first_line = freed_vars[var_name]
                    findings.append(
                        _make_finding(
                            source_path=source_path,
                            line=idx,
                            column=free_match.start() + 1,
                            severity="Critical",
                            vulnerability_type="Double Free",
                            description=(
                                f"[AST/CodeQL] Variable '{var_name}' is deallocated twice without reallocation "
                                f"(previously freed at line {first_line})."
                            ),
                            recommendation="Set pointer to nullptr immediately after deallocation, or use std::unique_ptr.",
                            source="ast_scan",
                        )
                    )
                else:
                    freed_vars[var_name] = idx
        else:
            # Check if freed var is dereferenced later in same scope
            for deref in _POINTER_DEREF_RE.finditer(line):
                used_var = deref.group(1) or deref.group(2)
                if used_var in freed_vars and freed_vars[used_var] < idx:
                    findings.append(
                        _make_finding(
                            source_path=source_path,
                            line=idx,
                            column=deref.start() + 1,
                            severity="Critical",
                            vulnerability_type="Use After Free",
                            description=(
                                f"[AST/CodeQL] Dereferencing pointer '{used_var}' after it was freed at line {freed_vars[used_var]}."
                            ),
                            recommendation="Do not access memory after freeing it. Use smart pointers (std::unique_ptr) to automate lifecycle.",
                            source="ast_scan",
                        )
                    )

        # Clear scope state on closing brace
        if line == "}":
            freed_vars.clear()

    return findings
