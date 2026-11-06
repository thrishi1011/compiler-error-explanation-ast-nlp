from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Literal, Optional
import json
import re

from models import CompilerError

Severity = Literal["Critical", "High", "Medium", "Low"]

@dataclass(frozen=True)
class SecurityFinding:
    file: str
    line: int | None
    column: int | None
    severity: Severity
    vulnerability_type: str
    description: str
    recommendation: str
    source: Literal["compiler_diagnostic", "static_scan", "ast_scan"]
    cwe_id: str | None = None
    cwe_name: str | None = None
    cwe_url: str | None = None
    cert_rule: str | None = None
    cert_url: str | None = None

    def to_dict(self):
        return asdict(self)

CWE_DEFINITIONS: dict[str, dict[str, str]] = {
    "Buffer Overflow": {
        "id": "CWE-120",
        "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "url": "https://cwe.mitre.org/data/definitions/120.html",
    },
    "Unsafe String Function": {
        "id": "CWE-676",
        "name": "Use of Potentially Dangerous Function",
        "url": "https://cwe.mitre.org/data/definitions/676.html",
    },
    "Unsafe Memory Copy": {
        "id": "CWE-120",
        "name": "Buffer Copy without Checking Size of Input",
        "url": "https://cwe.mitre.org/data/definitions/120.html",
    },
    "Format String Vulnerability": {
        "id": "CWE-134",
        "name": "Use of Externally-Controlled Format String",
        "url": "https://cwe.mitre.org/data/definitions/134.html",
    },
    "Null Pointer Dereference": {
        "id": "CWE-476",
        "name": "NULL Pointer Dereference",
        "url": "https://cwe.mitre.org/data/definitions/476.html",
    },
    "Dangling Pointer": {
        "id": "CWE-562",
        "name": "Return of Stack Variable Address",
        "url": "https://cwe.mitre.org/data/definitions/562.html",
    },
    "Use After Free": {
        "id": "CWE-416",
        "name": "Use After Free",
        "url": "https://cwe.mitre.org/data/definitions/416.html",
    },
    "Double Free": {
        "id": "CWE-415",
        "name": "Double Free",
        "url": "https://cwe.mitre.org/data/definitions/415.html",
    },
    "Potential Memory Leak": {
        "id": "CWE-401",
        "name": "Missing Release of Memory after Effective Lifetime",
        "url": "https://cwe.mitre.org/data/definitions/401.html",
    },
    "Integer Overflow": {
        "id": "CWE-190",
        "name": "Integer Overflow or Wraparound",
        "url": "https://cwe.mitre.org/data/definitions/190.html",
    },
    "Integer Underflow": {
        "id": "CWE-191",
        "name": "Integer Underflow (Wrap or Wraparound)",
        "url": "https://cwe.mitre.org/data/definitions/191.html",
    },
    "Logic Error / Integer Overflow Risk": {
        "id": "CWE-190",
        "name": "Integer Overflow or Wraparound",
        "url": "https://cwe.mitre.org/data/definitions/190.html",
    },
    "Signed/Unsigned Mismatch": {
        "id": "CWE-195",
        "name": "Signed to Unsigned Conversion Error",
        "url": "https://cwe.mitre.org/data/definitions/195.html",
    },
    "Division by Zero": {
        "id": "CWE-369",
        "name": "Divide By Zero",
        "url": "https://cwe.mitre.org/data/definitions/369.html",
    },
    "Command Injection": {
        "id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
    },
    "Process Execution": {
        "id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
    },
    "Insecure Randomness": {
        "id": "CWE-338",
        "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "url": "https://cwe.mitre.org/data/definitions/338.html",
    },
    "Weak Randomness": {
        "id": "CWE-338",
        "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "url": "https://cwe.mitre.org/data/definitions/338.html",
    },
    "Uninitialized Memory": {
        "id": "CWE-457",
        "name": "Use of Uninitialized Variable",
        "url": "https://cwe.mitre.org/data/definitions/457.html",
    },
    "Uninitialized Variable": {
        "id": "CWE-457",
        "name": "Use of Uninitialized Variable",
        "url": "https://cwe.mitre.org/data/definitions/457.html",
    },
    "Unbounded Input": {
        "id": "CWE-120",
        "name": "Buffer Copy without Checking Size of Input",
        "url": "https://cwe.mitre.org/data/definitions/120.html",
    },
    "Unchecked Return Value": {
        "id": "CWE-252",
        "name": "Unchecked Return Value",
        "url": "https://cwe.mitre.org/data/definitions/252.html",
    },
    "Missing Error Handling (fopen)": {
        "id": "CWE-252",
        "name": "Unchecked Return Value",
        "url": "https://cwe.mitre.org/data/definitions/252.html",
    },
    "Infinite Recursion": {
        "id": "CWE-674",
        "name": "Uncontrolled Recursion",
        "url": "https://cwe.mitre.org/data/definitions/674.html",
    },
    "Unused Variable / Dead Code": {
        "id": "CWE-563",
        "name": "Assignment to Variable without Use ('Unused Variable')",
        "url": "https://cwe.mitre.org/data/definitions/563.html",
    },
    "Use of Deprecated API": {
        "id": "CWE-477",
        "name": "Use of Obsolete Function",
        "url": "https://cwe.mitre.org/data/definitions/477.html",
    },
    "Unsafe Pointer Arithmetic": {
        "id": "CWE-469",
        "name": "Use of Pointer Subtraction to Determine Size",
        "url": "https://cwe.mitre.org/data/definitions/469.html",
    },
    "Hardcoded Secret / Sensitive Word": {
        "id": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
    },
    "Disabled Safety Check (assert in release)": {
        "id": "CWE-670",
        "name": "Always-Incorrect Control Flow Implementation",
        "url": "https://cwe.mitre.org/data/definitions/670.html",
    },
    "Vector Out of Bounds": {
        "id": "CWE-129",
        "name": "Improper Validation of Array Index",
        "url": "https://cwe.mitre.org/data/definitions/129.html",
    },
}

CERT_DEFINITIONS: dict[str, dict[str, str]] = {
    "Buffer Overflow": {
        "rule": "ARR30-C",
        "title": "Do not form or use out-of-bounds pointers or array subscripts",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C.+Do+not+form+or+use+out-of-bounds+pointers+or+array+subscripts",
    },
    "Unsafe String Function": {
        "rule": "STR31-C",
        "title": "Guarantee that storage for strings has sufficient space for character data and the null terminator",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator",
    },
    "Unsafe Memory Copy": {
        "rule": "ARR30-C",
        "title": "Do not form or use out-of-bounds pointers or array subscripts",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C.+Do+not+form+or+use+out-of-bounds+pointers+or+array+subscripts",
    },
    "Format String Vulnerability": {
        "rule": "FIO30-C",
        "title": "Exclude user input from format strings",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings",
    },
    "Null Pointer Dereference": {
        "rule": "EXP34-C",
        "title": "Do not dereference null pointers",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/EXP34-C.+Do+not+dereference+null+pointers",
    },
    "Dangling Pointer": {
        "rule": "DCL30-C",
        "title": "Declare objects with appropriate storage durations",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/DCL30-C.+Declare+objects+with+appropriate+storage+durations",
    },
    "Use After Free": {
        "rule": "MEM50-CPP",
        "title": "Do not access freed memory",
        "url": "https://wiki.sei.cmu.edu/confluence/display/cplusplus/MEM50-CPP.+Do+not+access+freed+memory",
    },
    "Double Free": {
        "rule": "MEM51-CPP",
        "title": "Properly deallocate dynamically allocated resources",
        "url": "https://wiki.sei.cmu.edu/confluence/display/cplusplus/MEM51-CPP.+Properly+deallocate+dynamically+allocated+resources",
    },
    "Potential Memory Leak": {
        "rule": "MEM51-CPP",
        "title": "Properly deallocate dynamically allocated resources",
        "url": "https://wiki.sei.cmu.edu/confluence/display/cplusplus/MEM51-CPP.+Properly+deallocate+dynamically+allocated+resources",
    },
    "Integer Overflow": {
        "rule": "INT30-C",
        "title": "Ensure that unsigned integer operations do not wrap",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap",
    },
    "Integer Underflow": {
        "rule": "INT32-C",
        "title": "Ensure that operations on signed integers do not result in signed integer overflow",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+signed+integer+overflow",
    },
    "Logic Error / Integer Overflow Risk": {
        "rule": "INT30-C",
        "title": "Ensure that integer operations do not wrap or overflow unexpectedly",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap",
    },
    "Signed/Unsigned Mismatch": {
        "rule": "INT31-C",
        "title": "Ensure that integer conversions do not result in lost or misinterpreted data",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/INT31-C.+Ensure+that+integer+conversions+do+not+result+in+lost+or+misinterpreted+data",
    },
    "Division by Zero": {
        "rule": "INT33-C",
        "title": "Ensure that division and remainder operations do not result in divide-by-zero errors",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/INT33-C.+Ensure+that+division+and+remainder+operations+do+not+result+in+divide-by-zero+errors",
    },
    "Command Injection": {
        "rule": "ENV33-C",
        "title": "Do not call system()",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/ENV33-C.+Do+not+call+system%28%29",
    },
    "Process Execution": {
        "rule": "ENV33-C",
        "title": "Do not call system()",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/ENV33-C.+Do+not+call+system%28%29",
    },
    "Insecure Randomness": {
        "rule": "MSC50-CPP",
        "title": "Do not use std::rand() for generating pseudorandom numbers",
        "url": "https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC50-CPP.+Do+not+use+std%3A%3Arand%28%29+for+generating+pseudorandom+numbers",
    },
    "Weak Randomness": {
        "rule": "MSC50-CPP",
        "title": "Do not use std::rand() for generating pseudorandom numbers",
        "url": "https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC50-CPP.+Do+not+use+std%3A%3Arand%28%29+for+generating+pseudorandom+numbers",
    },
    "Uninitialized Memory": {
        "rule": "EXP33-C",
        "title": "Do not read uninitialized memory",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/EXP33-C.+Do+not+read+uninitialized+memory",
    },
    "Uninitialized Variable": {
        "rule": "EXP33-C",
        "title": "Do not read uninitialized memory",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/EXP33-C.+Do+not+read+uninitialized+memory",
    },
    "Unbounded Input": {
        "rule": "FIO34-C",
        "title": "Distinguish between characters read from a file and EOF or error conditions",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/FIO34-C.+Distinguish+between+characters+read+from+a+file+and+EOF+or+error+conditions",
    },
    "Unchecked Return Value": {
        "rule": "ERR33-C",
        "title": "Detect and handle standard library errors",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/ERR33-C.+Detect+and+handle+standard+library+errors",
    },
    "Missing Error Handling (fopen)": {
        "rule": "FIO42-C",
        "title": "Close files when they are no longer needed",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/FIO42-C.+Close+files+when+they+are+no+longer+needed",
    },
    "Infinite Recursion": {
        "rule": "MSC15-C",
        "title": "Do not depend on undefined behavior",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/MSC15-C.+Do+not+depend+on+undefined+behavior",
    },
    "Unused Variable / Dead Code": {
        "rule": "MSC13-C",
        "title": "Detect unused values",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/MSC13-C.+Detect+unused+values",
    },
    "Use of Deprecated API": {
        "rule": "MSC24-C",
        "title": "Do not use deprecated or obsolescent functions",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/MSC24-C.+Do+not+use+deprecated+or+obsolescent+functions",
    },
    "Unsafe Pointer Arithmetic": {
        "rule": "ARR37-C",
        "title": "Do not add or subtract an integer to a pointer to obtain an unreferenced element",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/ARR37-C.+Do+not+add+or+subtract+an+integer+to+a+pointer+to+obtain+an+unreferenced+element",
    },
    "Hardcoded Secret / Sensitive Word": {
        "rule": "MSC03-C",
        "title": "Avoid hardcoded sensitive data",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/MSC03-C.+Avoid+hardcoded+sensitive+data",
    },
    "Disabled Safety Check (assert in release)": {
        "rule": "MSC11-C",
        "title": "Incorporate diagnostic tests using assertions properly",
        "url": "https://wiki.sei.cmu.edu/confluence/display/c/MSC11-C.+Incorporate+diagnostic+tests+using+assertions+properly",
    },
    "Vector Out of Bounds": {
        "rule": "CTR50-CPP",
        "title": "Guarantee that container indices and iterators are within valid range",
        "url": "https://wiki.sei.cmu.edu/confluence/display/cplusplus/CTR50-CPP.+Guarantee+that+container+indices+and+iterators+are+within+valid+range",
    },
}

_SEVERITY_ORDER: dict[Severity, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

_SEVERITY_WEIGHT: dict[Severity, int] = {
    "Critical": 10,
    "High": 5,
    "Medium": 2,
    "Low": 1,
}

_DIAGNOSTIC_RULES = [
    (
        re.compile(r"unused variable|variable .+ set but not used", re.IGNORECASE),
        "Low",
        "Unused Variable / Dead Code",
        "An unused variable can indicate dead code, abandoned checks, or incomplete hardening logic.",
        "Remove the variable or wire it into the intended validation or control flow.",
    ),
    (
        re.compile(r"may be used uninitialized", re.IGNORECASE),
        "High",
        "Uninitialized Memory",
        "The compiler detected a value that may be read before initialization.",
        "Initialize the variable before use and avoid relying on undefined values.",
    ),
    (
        re.compile(r"format not a string literal|format string is not a string literal", re.IGNORECASE),
        "High",
        "Format String Vulnerability",
        "A non-literal format string can allow attacker-controlled format specifiers.",
        "Use a fixed format string and pass user data as separate arguments.",
    ),
    (
        re.compile(r"ignoring return value", re.IGNORECASE),
        "Medium",
        "Unchecked Return Value",
        "A function result is being discarded, which can hide failures.",
        "Check the return value and handle errors explicitly.",
    ),
    (
        re.compile(r"comparison is always (?:true|false)", re.IGNORECASE),
        "Medium",
        "Logic Error / Integer Overflow Risk",
        "The compiler believes the comparison cannot fail, which can indicate a logic bug or overflow condition.",
        "Review the expression, types, and range assumptions around the comparison.",
    ),
    (
        re.compile(r"integer overflow|overflow in expression|wraps around", re.IGNORECASE),
        "High",
        "Integer Overflow",
        "The compiler has reported an overflow-prone arithmetic expression.",
        "Check bounds before arithmetic and use checked multiplication/addition for allocation sizes.",
    ),
    (
        re.compile(r"deprecated", re.IGNORECASE),
        "Low",
        "Use of Deprecated API",
        "Deprecated APIs may be removed or behave unsafely in future toolchains.",
        "Replace the deprecated API with a supported alternative.",
    ),
    (
        re.compile(r"conversion from .* may change sign", re.IGNORECASE),
        "Medium",
        "Signed/Unsigned Mismatch",
        "Signed and unsigned types are being mixed in a way that may change values unexpectedly.",
        "Use a single signedness model or cast deliberately after checking bounds.",
    ),
    (
        re.compile(r"array subscript is above array bounds|array subscript is below array bounds", re.IGNORECASE),
        "Critical",
        "Buffer Overflow",
        "An array access is outside the valid bounds of the buffer.",
        "Check index bounds and guard all array accesses before dereferencing.",
    ),
    (
        re.compile(r"null pointer dereference", re.IGNORECASE),
        "High",
        "Null Pointer Dereference",
        "A pointer may be dereferenced without a null check.",
        "Check the pointer for null before dereferencing and fail safely.",
    ),
]

_RAW_STRING_START = re.compile(r'(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(')
_SENSITIVE_WORDS = re.compile(r"\b(key|token|password|secret)\b", re.IGNORECASE)
_SENSITIVE_FUNCTIONS = re.compile(
    r"\b(gets|strcpy|strcat|sprintf|scanf|sscanf|fscanf|system|rand|memcpy|memmove|assert|malloc|free|new|delete|fopen|tmpnam|mktemp|atoi)\s*\(?",
    re.IGNORECASE,
)
_DELETE_RE = re.compile(r"\bdelete\s*(?:\[\])?\s*([A-Za-z_]\w*)\s*;")
_RAW_POINTER_USE_RE = re.compile(r"(?:\*|->|\[)\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*(?:->|\[)")

def _empty_finding(
    file: str,
    severity: Severity,
    vulnerability_type: str,
    description: str,
    recommendation: str,
    line: int | None = None,
    column: int | None = None,
    source: Literal["compiler_diagnostic", "static_scan", "ast_scan"] = "static_scan",
    cwe_id: str | None = None,
    cwe_name: str | None = None,
    cwe_url: str | None = None,
    cert_rule: str | None = None,
    cert_url: str | None = None,
) -> SecurityFinding:
    if cwe_id is None:
        cwe_info = CWE_DEFINITIONS.get(vulnerability_type)
        if cwe_info:
            cwe_id = cwe_info["id"]
            cwe_name = cwe_info["name"]
            cwe_url = cwe_info["url"]
    if cert_rule is None:
        cert_info = CERT_DEFINITIONS.get(vulnerability_type)
        if cert_info:
            cert_rule = cert_info["rule"]
            cert_url = cert_info["url"]

    return SecurityFinding(
        file=file,
        line=line,
        column=column,
        severity=severity,
        vulnerability_type=vulnerability_type,
        description=description,
        recommendation=recommendation,
        source=source,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cwe_url=cwe_url,
        cert_rule=cert_rule,
        cert_url=cert_url,
    )

def _normalize_path(source_path: str) -> str:
    try:
        return str(Path(source_path).resolve())
    except Exception:
        return source_path

def _make_finding(
    source_path: str,
    line: int | None,
    column: int | None,
    severity: Severity,
    vulnerability_type: str,
    description: str,
    recommendation: str,
    source: Literal["compiler_diagnostic", "static_scan", "ast_scan"] = "static_scan",
    cwe_id: str | None = None,
    cwe_name: str | None = None,
    cwe_url: str | None = None,
    cert_rule: str | None = None,
    cert_url: str | None = None,
) -> SecurityFinding:
    if cwe_id is None:
        cwe_info = CWE_DEFINITIONS.get(vulnerability_type)
        if cwe_info:
            cwe_id = cwe_info["id"]
            cwe_name = cwe_info["name"]
            cwe_url = cwe_info["url"]
    if cert_rule is None:
        cert_info = CERT_DEFINITIONS.get(vulnerability_type)
        if cert_info:
            cert_rule = cert_info["rule"]
            cert_url = cert_info["url"]

    return SecurityFinding(
        file=_normalize_path(source_path),
        line=line,
        column=column,
        severity=severity,
        vulnerability_type=vulnerability_type,
        description=description,
        recommendation=recommendation,
        source=source,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cwe_url=cwe_url,
        cert_rule=cert_rule,
        cert_url=cert_url,
    )

def _strip_code(line: str, state: dict[str, object]) -> str:
    in_block_comment = bool(state.get("in_block_comment"))
    raw_delim = state.get("raw_delim")
    out: list[str] = []
    i = 0

    while i < len(line):
        if raw_delim is not None:
            raw_end = line.find(")" + str(raw_delim) + '"', i)
            if raw_end == -1:
                state["raw_delim"] = raw_delim
                return "".join(out)
            i = raw_end + len(str(raw_delim)) + 2
            raw_delim = None
            continue

        if in_block_comment:
            comment_end = line.find("*/", i)
            if comment_end == -1:
                state["in_block_comment"] = True
                return "".join(out)
            i = comment_end + 2
            in_block_comment = False
            continue

        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue

        raw_match = _RAW_STRING_START.match(line, i)
        if raw_match:
            raw_delim = raw_match.group(1)
            i = raw_match.end()
            continue

        ch = line[i]
        if ch in ("'", '"'):
            quote = ch
            i += 1
            while i < len(line):
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        out.append(ch)
        i += 1

    state["in_block_comment"] = in_block_comment
    state["raw_delim"] = raw_delim
    return "".join(out)

def _split_args(argument_blob: str) -> list[str]:
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    in_quote: str | None = None
    escape = False

    for ch in argument_blob:
        if in_quote:
            buf.append(ch)
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
            elif ch == in_quote:
                in_quote = None
            continue

        if ch in ("'", '"'):
            in_quote = ch
            buf.append(ch)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
            continue

        buf.append(ch)

    tail = "".join(buf).strip()
    if tail:
        args.append(tail)
    return args

def _string_literal_value(text: str) -> Optional[str]:
    match = re.match(r'\s*[u8uUL]*"((?:\\.|[^"\\])*)"', text)
    if not match:
        return None
    return match.group(1)

def _diagnostic_findings(error) -> list[SecurityFinding]:
    if isinstance(error, dict):
        message = (error.get("message") or "").lower()
        err_file = error.get("file") or ""
        err_line = error.get("line")
        err_col = error.get("column")
    else:
        message = (getattr(error, "message", "") or "").lower()
        err_file = getattr(error, "file", "") or ""
        err_line = getattr(error, "line", None)
        err_col = getattr(error, "column", None)
    findings: list[SecurityFinding] = []

    for pattern, severity, vuln_type, description, recommendation in _DIAGNOSTIC_RULES:
        if pattern.search(message):
            findings.append(
                _make_finding(
                    err_file,
                    err_line,
                    err_col,
                    severity,  # type: ignore[arg-type]
                    vuln_type,
                    description,
                    recommendation,
                    "compiler_diagnostic",
                )
            )

    return findings

def _looks_like_raw_integer_size(size_expr: str) -> bool:
    size_expr = size_expr.strip()
    if "sizeof" in size_expr:
        return False
    if re.search(r"\b\d+\b", size_expr):
        return True
    if any(op in size_expr for op in ("+", "-", "*", "/")):
        return True
    return False

def _scan_source_findings(source_path: str) -> list[SecurityFinding]:
    path = Path(source_path)
    if not path.exists():
        return []

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    findings: list[SecurityFinding] = []
    state: dict[str, object] = {"in_block_comment": False, "raw_delim": None}
    scope_stack: list[dict[str, object]] = [
        {"start_line": 1, "malloc_lines": [], "free_seen": False, "new_lines": [], "delete_seen": False, "fopen_lines": [], "fclose_seen": False}
    ]
    recent_sensitive_lines: list[int] = []
    freed_vars: dict[str, int] = {}
    debug_guard_present = any(
        re.search(r"#\s*(?:if|ifdef|ifndef)\s+.*NDEBUG", line, re.IGNORECASE)
        for line in lines
    )
    full_source = "".join(lines)

    def current_scope() -> dict[str, object]:
        return scope_stack[-1]

    def emit(line_no: int | None, vuln_type: str, severity: Severity, description: str, recommendation: str):
        findings.append(
            _make_finding(
                source_path,
                line_no,
                None,
                severity,
                vuln_type,
                description,
                recommendation,
                "static_scan",
            )
        )

    def emit_location(line_no: int | None, column: int | None, vuln_type: str, severity: Severity, description: str, recommendation: str):
        findings.append(
            _make_finding(
                source_path,
                line_no,
                column,
                severity,
                vuln_type,
                description,
                recommendation,
                "static_scan",
            )
        )

    max_int_vars: set[str] = set()
    unsigned_zero_vars: set[str] = set()
    zero_divisors: set[str] = set()
    uninit_vars: dict[str, int] = {}
    null_ptrs: dict[str, int] = {}
    vector_sizes: dict[str, int] = {}
    signed_vars: set[str] = set()
    unsigned_vars: set[str] = set()
    current_fn: str | None = None
    fn_has_base_case = False
    fn_recursive_lines: list[int] = []
    local_vars: set[str] = set()

    for line_no, raw_line in enumerate(lines, start=1):
        code_line = _strip_code(raw_line, state).strip()
        raw_lower = raw_line.lower()
        code_lower = code_line.lower()

        sensitive_here = bool(_SENSITIVE_FUNCTIONS.search(code_line))
        if sensitive_here:
            recent_sensitive_lines.append(line_no)
            recent_sensitive_lines = recent_sensitive_lines[-3:]

        for m_u in re.finditer(r"\b(?:unsigned(?:\s+(?:int|char|long|short))?|uint\w*|size_t)\s+([A-Za-z_]\w*)", code_line):
            unsigned_vars.add(m_u.group(1))
        for m_s in re.finditer(r"\b(?:int|long|short)\s+([A-Za-z_]\w*)", code_line):
            signed_vars.add(m_s.group(1))

        # ── 1. Infinite Recursion ─────────────────────────────────────────────
        fn_start = re.search(r"^\s*(?:int|void|bool|double|float|long|auto|char|[A-Za-z_]\w*)\s*(?:\*+|\s+)\s*([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", code_line)
        if fn_start:
            current_fn = fn_start.group(1)
            fn_has_base_case = False
            fn_recursive_lines = []
            freed_vars.clear()
            local_vars.clear()

        if current_fn:
            if re.search(r"\bif\s*\(", code_line) or (re.search(r"\breturn\b", code_line) and not re.search(rf"\b{re.escape(current_fn)}\s*\(", code_line)):
                fn_has_base_case = True
            if re.search(rf"\b{re.escape(current_fn)}\s*\(", code_line) and not fn_start:
                fn_recursive_lines.append(line_no)

            if not re.search(r"\bstatic\b", code_line):
                decl_m = re.search(r"^\s*(?:const\s+)?(?:int|char|float|double|long|short|bool|auto|[A-Za-z_]\w*)\s+(?:\*|\&)?\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=|[;{])", code_line)
                if decl_m:
                    v_name = decl_m.group(1)
                    if v_name not in ("return", "if", "for", "while", "switch", "case", "struct", "class", "namespace"):
                        local_vars.add(v_name)

            ret_ref = re.search(r"\breturn\s+&\s*([A-Za-z_]\w*)\s*;", code_line)
            if ret_ref:
                ret_var = ret_ref.group(1)
                if ret_var in local_vars:
                    emit(
                        line_no,
                        "Dangling Pointer",
                        "Critical",
                        f"Returning the address of local stack variable '{ret_var}' results in a dangling pointer when the function returns.",
                        "Allocate memory on the heap (e.g. std::make_unique), return by value, or pass an output buffer parameter.",
                    )

        if code_line == "}" and current_fn:
            if fn_recursive_lines and not fn_has_base_case:
                for r_line in fn_recursive_lines:
                    emit(
                        r_line,
                        "Infinite Recursion",
                        "Critical",
                        f"Function '{current_fn}' calls itself recursively without a terminating base case.",
                        f"Add a base case check (e.g. 'if (n <= 1) return 1;') before the recursive call.",
                    )
            current_fn = None
            fn_has_base_case = False
            fn_recursive_lines = []
            freed_vars.clear()
            local_vars.clear()

        # ── 2. Integer Overflow / Underflow ───────────────────────────────────
        int_max_init = re.search(r"\b(?<!long\s)(?:int|short)\s+([A-Za-z_]\w*)\s*=\s*(?:INT_MAX|2147483647)\b", code_line)
        if int_max_init and int_max_init.group(1) != "long":
            max_int_vars.add(int_max_init.group(1))

        for v in list(max_int_vars):
            if re.search(rf"\b{re.escape(v)}\s*(?:\+\+|\+=|\+)|(?:\+\+|\+)\s*{re.escape(v)}\b", code_line) and not int_max_init:
                emit(
                    line_no,
                    "Integer Overflow",
                    "High",
                    f"Variable '{v}' initialized near maximum capacity is incremented, leading to integer overflow.",
                    f"Use a wider integer type such as 'long long' for '{v}' or validate bounds before arithmetic.",
                )

        u_zero_init = re.search(r"\bunsigned\s+(?:int\s+)?([A-Za-z_]\w*)\s*=\s*0\b", code_line)
        if u_zero_init:
            unsigned_zero_vars.add(u_zero_init.group(1))

        for u in list(unsigned_zero_vars):
            if re.search(rf"\b{re.escape(u)}\s*(?:--|-=|-)|(?:--|-)\s*{re.escape(u)}\b", code_line) and not u_zero_init:
                if not (re.search(rf"\b{re.escape(u)}\s*>\s*0\b", code_line) or re.search(rf"if\s*\(\s*{re.escape(u)}\s*>\s*0", full_source)):
                    emit(
                        line_no,
                        "Integer Underflow",
                        "High",
                        f"Unsigned variable '{u}' initialized to 0 is decremented, causing underflow wrapping to UINT_MAX.",
                        f"Validate that '{u} > 0' before decrementing an unsigned integer.",
                    )

        # ── 3. Division by Zero ───────────────────────────────────────────────
        z_init = re.search(r"\b(?:int|double|float)\s+([A-Za-z_]\w*)\s*=\s*0\b", code_line)
        if z_init:
            zero_divisors.add(z_init.group(1))

        if re.search(r"/\s*0\b", code_line):
            emit(
                line_no,
                "Division by Zero",
                "High",
                "Literal division by zero results in undefined behavior or immediate hardware crash.",
                "Ensure divisor is non-zero before division.",
            )

        for zd in list(zero_divisors):
            if re.search(rf"/\s*{re.escape(zd)}\b", code_line) and not z_init:
                if not (
                    re.search(rf"{re.escape(zd)}\s*!=\s*0", code_line)
                    or re.search(rf"if\s*\(\s*{re.escape(zd)}\s*==\s*0\s*\)\s*{re.escape(zd)}\s*=", full_source)
                    or re.search(rf"if\s*\(\s*{re.escape(zd)}\s*!=\s*0", full_source)
                ):
                    emit(
                        line_no,
                        "Division by Zero",
                        "High",
                        f"Division by variable '{zd}' whose value is 0 causes runtime crash.",
                        f"Check 'if ({zd} != 0)' before division.",
                    )

        # ── 4. Uninitialized Variables ────────────────────────────────────────
        uninit_match = re.search(r"^\s*(?:int|float|double|char|long)\s+([A-Za-z_]\w*)\s*;\s*$", code_line)
        if uninit_match:
            u_name = uninit_match.group(1)
            if u_name not in ("main", "return"):
                uninit_vars[u_name] = line_no

        for uv, u_decl in list(uninit_vars.items()):
            if line_no > u_decl and re.search(rf"\b{re.escape(uv)}\b", code_line):
                assign_m = re.search(rf"^\s*{re.escape(uv)}\s*=\s*(.+);", code_line)
                if assign_m and not re.search(rf"\b{re.escape(uv)}\b", assign_m.group(1)):
                    del uninit_vars[uv]
                elif (
                    re.search(rf"cin\s*>>.*?\b{re.escape(uv)}\b", code_line)
                    or re.search(rf"scanf\s*\(.*&{re.escape(uv)}\b", code_line)
                    or re.search(rf"getline\s*\([^,]+,\s*{re.escape(uv)}\b", code_line)
                ):
                    del uninit_vars[uv]
                else:
                    emit(
                        line_no,
                        "Uninitialized Variable",
                        "High",
                        f"Variable '{uv}' declared at line {u_decl} is used before initialization.",
                        f"Initialize '{uv} = 0;' at declaration.",
                    )
                    del uninit_vars[uv]

        # ── 5. Null Pointer Dereference ───────────────────────────────────────
        null_match = re.search(r"\b(?:int|char|void|double|float)\s*\*\s*([A-Za-z_]\w*)\s*=\s*(?:nullptr|NULL|0)\s*;", code_line)
        if null_match:
            null_ptrs[null_match.group(1)] = line_no

        for np, n_decl in list(null_ptrs.items()):
            if line_no > n_decl and re.search(rf"\*\s*{re.escape(np)}\b|{re.escape(np)}\s*->", code_line):
                is_guarded = False
                for prev_i in range(max(0, line_no - 4), line_no):
                    prev_line = lines[prev_i] if prev_i < len(lines) else ""
                    if re.search(rf"\bif\s*\(\s*(?:{re.escape(np)}\s*!=\s*(?:nullptr|NULL|0)|(?:nullptr|NULL|0)\s*!=\s*{re.escape(np)}|{re.escape(np)})\s*\)", prev_line):
                        is_guarded = True
                        break
                if not is_guarded:
                    emit(
                        line_no,
                        "Null Pointer Dereference",
                        "Critical",
                        f"Pointer '{np}' initialized to nullptr at line {n_decl} is dereferenced.",
                        f"Allocate memory or check 'if ({np} != nullptr)' before dereferencing.",
                    )
                del null_ptrs[np]
        # ── 6. Vector Out of Bounds ───────────────────────────────────────────
        vec_init = re.search(r"\bvector\s*<[^>]+>\s*([A-Za-z_]\w*)\s*=\s*\{([^}]+)\}", code_line)
        if vec_init:
            v_name = vec_init.group(1)
            v_count = len([x for x in vec_init.group(2).split(",") if x.strip()])
            vector_sizes[v_name] = v_count

        for vn, vs in list(vector_sizes.items()):
            v_idx = re.search(rf"\b{re.escape(vn)}\s*(?:\[|\.at\()\s*(\d+)\s*(?:\]|\))", code_line)
            if v_idx:
                accessed_idx = int(v_idx.group(1))
                if accessed_idx >= vs:
                    is_guarded = False
                    for prev_i in range(max(0, line_no - 4), line_no):
                        prev_line = lines[prev_i] if prev_i < len(lines) else ""
                        if re.search(rf"\bif\s*\(.*{re.escape(vn)}\.size\(\)", prev_line):
                            is_guarded = True
                            break
                    if not is_guarded:
                        emit(
                            line_no,
                            "Vector Out of Bounds",
                            "High",
                            f"Vector '{vn}' has {vs} elements (indices 0..{vs-1}), but is accessed at out-of-bounds index {accessed_idx}.",
                            f"Ensure index is within bounds: 'if ({accessed_idx} < {vn}.size())'.",
                        )
        if re.search(r"\bgets\s*\(", code_line):
            emit(
                line_no,
                "Buffer Overflow",
                "Critical",
                "gets() reads input without any bounds checking.",
                "Replace gets() with fgets(), std::getline, or another bounded input routine.",
            )

        if re.search(r"\b(?:strcpy|strcat|sprintf)\s*\(", code_line):
            emit(
                line_no,
                "Unsafe String Function",
                "High",
                "A classic C string routine is being used without explicit bounds control.",
                "Use bounded alternatives such as strncpy/strncat/snprintf or switch to std::string.",
            )

        line_no_comment = raw_line.split("//")[0].strip()
        scanf_match = re.search(r"\b(scanf|sscanf|fscanf)\s*\((.+)\)\s*;?", line_no_comment)
        if scanf_match:
            fn_name = scanf_match.group(1)
            args = _split_args(scanf_match.group(2))
            fmt_idx = 1 if fn_name in ("sscanf", "fscanf") else 0
            if len(args) > fmt_idx:
                fmt = _string_literal_value(args[fmt_idx])
                if fmt and re.search(r"%\s*s", fmt) and not re.search(r"%\d+s", fmt):
                    emit(
                        line_no,
                        "Unbounded Input",
                        "High",
                        f"{fn_name}() is reading a string with %s and no width limit.",
                        "Add an explicit width specifier or use std::string with bounded parsing.",
                    )

        fmt_m = re.search(r"\b(?:printf|fprintf)\s*\(\s*([^,()]+)\s*\)\s*;", raw_line)
        if not fmt_m:
            fmt_m = re.search(r"\bfprintf\s*\(\s*[^,()]+\s*,\s*([^,()]+)\s*\)\s*;", raw_line)
        if fmt_m:
            fmt_arg = fmt_m.group(1).strip()
            if re.match(r"^[A-Za-z_]\w*$", fmt_arg):
                emit(
                    line_no,
                    "Format String Vulnerability",
                    "High",
                    "A non-literal format string is being used with printf/fprintf.",
                    "Use a fixed format string and pass user data as separate arguments.",
                )

        tmp_match = re.search(r"\b(tmpnam|tmpnam_s|mktemp|tempnam)\s*\(", code_line)
        if tmp_match:
            fn_banned = tmp_match.group(1)
            emit(
                line_no,
                "Insecure Temporary File",
                "High",
                f"{fn_banned}() generates predictable temporary file names vulnerable to symlink and race condition attacks (TOCTOU).",
                "Use mkstemp(), tmpfile(), or standard filesystem utilities (e.g. std::filesystem) instead.",
            )

        conv_match = re.search(r"\b(atoi|atol|atoll|atof)\s*\(", code_line)
        if conv_match:
            fn_conv = conv_match.group(1)
            emit(
                line_no,
                "Unchecked Type Conversion",
                "Medium",
                f"{fn_conv}() provides no error handling or range validation for invalid or overflowing numeric inputs.",
                "Use std::stoi, std::stol, std::stod, or std::from_chars with proper exception/error checking.",
            )

        mem_match = re.search(r"\b(memcpy|memmove)\s*\((.+)\)\s*;?\s*$", code_line)
        if mem_match:
            args = _split_args(mem_match.group(2))
            if len(args) >= 3 and _looks_like_raw_integer_size(args[2]):
                emit(
                    line_no,
                    "Unsafe Memory Copy",
                    "Medium",
                    f"{mem_match.group(1)}() is using a raw size expression instead of a verified sizeof-based bound.",
                    "Validate the copy length and prefer sizeof-driven limits or safer container-aware copying.",
                )

        if re.search(r"\bsystem\s*\(", code_line):
            emit(
                line_no,
                "Command Injection",
                "High",
                "system() executes a shell command and can be influenced by attacker-controlled input.",
                "Avoid shell execution. Use exec-style APIs or strict argument validation and escaping.",
            )

        if re.search(r"\brand\s*\(", code_line) and (
            _SENSITIVE_WORDS.search(raw_line) or _SENSITIVE_WORDS.search(code_line)
            or any(abs(line_no - prev) <= 1 for prev in recent_sensitive_lines)
        ):
            emit(
                line_no,
                "Weak Randomness",
                "High",
                "rand() is being used in a security-sensitive context.",
                "Use a cryptographically secure random source for keys, tokens, passwords, and secrets.",
            )

        if re.search(r"\bassert\s*\(", code_line) and not debug_guard_present:
            emit(
                line_no,
                "Disabled Safety Check",
                "Low",
                "assert() is being used as a safety boundary outside a clearly debug-only context.",
                "Keep runtime checks explicit and do not rely on assert() for production validation.",
            )

        if re.search(r"\b(TODO|FIXME)\b", raw_line, re.IGNORECASE) and (
            sensitive_here or any(abs(line_no - prev) <= 1 for prev in recent_sensitive_lines)
        ):
            emit(
                line_no,
                "Unresolved Security Debt",
                "Low",
                "A TODO/FIXME is sitting next to security-sensitive code.",
                "Resolve the security follow-up before shipping the code path.",
            )

        if re.search(r"\*\s*\(\s*[A-Za-z_]\w*\s*\+\s*[^)]+\)", code_line) or re.search(r"\b(?:[A-Za-z_]\w*(?:ptr|buf|data|cursor|p))\s*\+\+", code_line):
            emit(
                line_no,
                "Unsafe Pointer Arithmetic",
                "Medium",
                "Raw pointer arithmetic is present and may escape bounds checks.",
                "Prefer indexing with explicit bounds checks or use standard container iterators.",
            )

        is_pointer_decl = bool(re.search(r"\b(?:void|int|char|float|double|bool|short|long|unsigned|auto|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|size_t)\s*\*", code_line))
        is_func_header = bool(re.search(r"^\s*(?:[A-Za-z_]\w*[\s*&]+)+[A-Za-z_]\w*\s*\([^)]*\)\s*\{?", code_line))

        if not is_pointer_decl and not is_func_header and re.search(r"\b(?:[A-Za-z_]\w*\s*[\+\-\*/]\s*[A-Za-z_0-9()]+)\b", code_line) and (
            "INT_MAX" in code_line or "SIZE_MAX" in code_line or "sizeof" in code_line or re.search(r"\b(?:alloc|size|len|count|capacity)\b", code_line)
        ) and not (re.search(r">\s*0\b", code_line) or re.search(r"!=\s*0\b", code_line) or "sizeof" in code_line or "static_cast" in code_line):
            emit(
                line_no,
                "Integer Overflow",
                "High",
                "Arithmetic on size-like values may overflow before allocation or indexing.",
                "Validate operands before arithmetic and use checked addition/multiplication for allocation sizes.",
            )

        cmp_m = re.search(r"\b([A-Za-z_]\w*)\s*(<|<=|>|>=)\s*([A-Za-z_]\w*)\b", code_line)
        if cmp_m:
            c1, op, c2 = cmp_m.group(1), cmp_m.group(2), cmp_m.group(3)
            is_signed_compare = (
                (c1 in signed_vars and c2 in unsigned_vars)
                or (c1 in unsigned_vars and c2 in signed_vars)
                or ("signed" in raw_lower and "unsigned" in raw_lower)
            )
            if is_signed_compare and "static_cast" not in code_line:
                emit(
                    line_no,
                    "Signed/Unsigned Mismatch",
                    "Medium",
                    "Signed and unsigned types are being compared.",
                    "Cast operands explicitly to a common signed type.",
                )

        if "malloc(" in code_line:
            current_scope()["malloc_lines"].append(line_no)

        if "free(" in code_line:
            for scope in scope_stack:
                scope["free_seen"] = True

        if re.search(r"\bnew\s+(?:nothrow\s+)?(?:[A-Za-z_]|::)", code_line) and not re.search(r"\boperator\s+new\b", code_line):
            current_scope()["new_lines"].append(line_no)

        if re.search(r"\bdelete\s*(?:\[\])?\s*[A-Za-z_]", code_line):
            for scope in scope_stack:
                scope["delete_seen"] = True

        if re.search(r"\b(?:fopen|fopen_s|freopen)\s*\(", code_line):
            current_scope()["fopen_lines"].append(line_no)

        if "fclose(" in code_line:
            for scope in scope_stack:
                scope["fclose_seen"] = True

        for freed_name, freed_line in list(freed_vars.items()):
            if re.search(rf"(?<![\*\&])\b{re.escape(freed_name)}\s*=\s*(?:nullptr|NULL|0|\w+)\s*;", code_line):
                del freed_vars[freed_name]
                continue
            if re.search(rf"(?:\bdelete\s*(?:\[\])?\s*|\bfree\s*\(\s*){re.escape(freed_name)}\s*(?:\)|;)", code_line) and line_no != freed_line:
                emit(
                    line_no,
                    "Double Free",
                    "High",
                    "The same pointer appears to be freed or deleted more than once.",
                    "Set the pointer to nullptr immediately after freeing or switch to smart pointers.",
                )
            if re.search(rf"(?<!\w)\*\s*{re.escape(freed_name)}\b|\b{re.escape(freed_name)}\s*->|\b{re.escape(freed_name)}\s*\[", code_line):
                emit(
                    line_no,
                    "Use After Free",
                    "High",
                    "Memory appears to be accessed after it was freed.",
                    "Do not use the pointer after free/delete; prefer unique_ptr or reset the pointer to nullptr.",
                )

        free_match = re.search(r"(?:\bdelete\s*(?:\[\])?\s*|\bfree\s*\(\s*)([A-Za-z_]\w*)\s*(?:\)|;)", code_line)
        if free_match:
            freed_vars[free_match.group(1)] = line_no

        open_braces = code_line.count("{")
        close_braces = code_line.count("}")
        for _ in range(open_braces):
            scope_stack.append({"start_line": line_no, "malloc_lines": [], "free_seen": False, "new_lines": [], "delete_seen": False, "fopen_lines": [], "fclose_seen": False})
        for _ in range(close_braces):
            if len(scope_stack) <= 1:
                freed_vars.clear()
                continue
            finished = scope_stack.pop()
            if len(scope_stack) <= 1:
                freed_vars.clear()
            if finished["malloc_lines"] and not finished["free_seen"]:
                for malloc_line in finished["malloc_lines"]:
                    emit(
                        malloc_line,
                        "Potential Memory Leak",
                        "Medium",
                        "malloc() allocates memory in this scope without a matching free() before the scope closes.",
                        "Release the allocation with free() in the same scope or replace manual ownership with RAII/smart pointers.",
                    )
            if finished.get("new_lines") and not finished.get("delete_seen"):
                for new_line in finished["new_lines"]:
                    emit(
                        new_line,
                        "Potential Memory Leak",
                        "Medium",
                        "new allocates memory dynamically in this scope without a matching delete before the scope closes.",
                        "Release the allocated object with delete / delete[] or manage it using std::unique_ptr or std::shared_ptr.",
                    )
            if finished.get("fopen_lines") and not finished.get("fclose_seen"):
                for fopen_line in finished["fopen_lines"]:
                    emit(
                        fopen_line,
                        "File Descriptor Leak",
                        "Medium",
                        "fopen() opened a file stream in this scope without a matching fclose() before the scope closes.",
                        "Close the file with fclose(fp) before exiting scope or wrap the handle in an RAII container.",
                    )

    while len(scope_stack) > 1:
        finished = scope_stack.pop()
        if finished["malloc_lines"] and not finished["free_seen"]:
            for malloc_line in finished["malloc_lines"]:
                emit(
                    malloc_line,
                    "Potential Memory Leak",
                    "Medium",
                    "malloc() allocates memory in this scope without a matching free() before the scope closes.",
                    "Release the allocation with free() in the same scope or replace manual ownership with RAII/smart pointers.",
                )
        if finished.get("new_lines") and not finished.get("delete_seen"):
            for new_line in finished["new_lines"]:
                emit(
                    new_line,
                    "Potential Memory Leak",
                    "Medium",
                    "new allocates memory dynamically in this scope without a matching delete before the scope closes.",
                    "Release the allocated object with delete / delete[] or manage it using std::unique_ptr or std::shared_ptr.",
                )
        if finished.get("fopen_lines") and not finished.get("fclose_seen"):
            for fopen_line in finished["fopen_lines"]:
                emit(
                    fopen_line,
                    "File Descriptor Leak",
                    "Medium",
                    "fopen() opened a file stream in this scope without a matching fclose() before the scope closes.",
                    "Close the file with fclose(fp) before exiting scope or wrap the handle in an RAII container.",
                )

    return findings

def _dedupe_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    deduped: list[SecurityFinding] = []
    seen: set[tuple] = set()
    for finding in findings:
        key = (
            finding.file,
            finding.line,
            finding.column,
            finding.severity,
            finding.vulnerability_type,
            finding.description,
            finding.recommendation,
            finding.source,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    deduped.sort(
        key=lambda f: (
            _SEVERITY_ORDER[f.severity],
            f.file or "",
            f.line if f.line is not None else 10**9,
            f.column if f.column is not None else 10**9,
            f.vulnerability_type,
        )
    )
    return deduped

def analyze(source_path: str, compiler_errors: list[CompilerError]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    for error in compiler_errors or []:
        findings.extend(_diagnostic_findings(error))

    findings.extend(_scan_source_findings(source_path))

    try:
        import ast_security_rules
        ast_findings = ast_security_rules.analyze_ast(source_path)
        existing_keys = {(f.line, f.vulnerability_type) for f in findings}
        for af in ast_findings:
            if (af.line, af.vulnerability_type) not in existing_keys:
                findings.append(af)
                existing_keys.add((af.line, af.vulnerability_type))
    except Exception:
        pass

    return _dedupe_findings(findings)

def _severity_counts(findings: list[SecurityFinding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return counts

def _risk_label(score: int) -> str:
    if score == 0:
        return "Clean"
    if score <= 10:
        return "Low Risk"
    if score <= 30:
        return "Moderate"
    return "High Risk"

def format_security_report(findings: list[SecurityFinding]) -> str:
    findings = _dedupe_findings(findings)
    counts = _severity_counts(findings)
    score = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)

    lines: list[str] = [
        f"{counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, {counts['Low']} low findings",
        "",
    ]

    for severity in ("Critical", "High", "Medium", "Low"):
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"{severity.upper()}")
        for finding in group:
            location = finding.file
            if finding.line is not None:
                location += f":{finding.line}"
            badge = f"[{finding.severity.upper()}]"
            std_tag = ""
            if finding.cwe_id:
                std_tag += f" [{finding.cwe_id}]"
            if finding.cert_rule:
                std_tag += f" [{finding.cert_rule}]"
            lines.append(f"{badge}{std_tag} {finding.vulnerability_type} - {location}")
            lines.append(f"  Description: {finding.description}")
            lines.append(f"  Recommendation: {finding.recommendation}")
            lines.append("")

    lines.append(f"Risk score: {score} ({_risk_label(score)})")
    return "\n".join(lines).strip() + "\n"

def export_to_sarif(findings: list[SecurityFinding], run_info: dict | None = None) -> dict:
    findings = _dedupe_findings(findings)
    rules_map: dict[str, dict] = {}
    results: list[dict] = []

    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }

    for f in findings:
        rule_id = f.cwe_id or f.vulnerability_type.replace(" ", "_").upper()
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.cwe_name or f.vulnerability_type,
                "shortDescription": {"text": f.vulnerability_type},
                "fullDescription": {"text": f.description},
                "helpUri": f.cwe_url or "https://cwe.mitre.org/",
                "properties": {
                    "tags": ["security", "c++"],
                    "certRule": f.cert_rule or "",
                    "certUri": f.cert_url or "",
                },
            }

        file_uri = Path(f.file).as_posix() if f.file else "unknown.cpp"
        result_item = {
            "ruleId": rule_id,
            "level": level_map.get(f.severity, "warning"),
            "message": {
                "text": f"{f.description} Recommendation: {f.recommendation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri,
                        },
                        "region": {
                            "startLine": f.line if f.line is not None and f.line > 0 else 1,
                            "startColumn": f.column if f.column is not None and f.column > 0 else 1,
                        },
                    }
                }
            ],
        }
        results.append(result_item)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Self-Healing-Compiler-Security-Analyzer",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://cwe.mitre.org",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif

def save_sarif(findings: list[SecurityFinding], output_path: str) -> str:
    sarif_data = export_to_sarif(findings)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
    return str(out)
