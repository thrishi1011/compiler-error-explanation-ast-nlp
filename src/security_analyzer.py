from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Literal, Optional
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
    source: Literal["compiler_diagnostic", "static_scan"]

    def to_dict(self):
        return asdict(self)


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
    r"\b(gets|strcpy|strcat|sprintf|scanf|system|rand|memcpy|memmove|assert|malloc)\s*\(",
    re.IGNORECASE,
)
_DELETE_RE = re.compile(r"\bdelete\s*(?:\[\])?\s*([A-Za-z_]\w*)\s*;")
_RAW_POINTER_USE_RE = re.compile(r"(?:\*|->|\[)\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*(?:->|\[)")


def _empty_finding(file: str, severity: Severity, vulnerability_type: str, description: str, recommendation: str, line: int | None = None, column: int | None = None, source: str = "static_scan") -> SecurityFinding:
    return SecurityFinding(
        file=file,
        line=line,
        column=column,
        severity=severity,
        vulnerability_type=vulnerability_type,
        description=description,
        recommendation=recommendation,
        source=source,  # type: ignore[arg-type]
    )


def _normalize_path(source_path: str) -> str:
    try:
        return str(Path(source_path).resolve())
    except Exception:
        return source_path


def _make_finding(source_path: str, line: int | None, column: int | None, severity: Severity, vulnerability_type: str, description: str, recommendation: str, source: Literal["compiler_diagnostic", "static_scan"]) -> SecurityFinding:
    return SecurityFinding(
        file=_normalize_path(source_path),
        line=line,
        column=column,
        severity=severity,
        vulnerability_type=vulnerability_type,
        description=description,
        recommendation=recommendation,
        source=source,
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
        {"start_line": 1, "malloc_lines": [], "free_seen": False}
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
    current_fn: str | None = None
    fn_has_base_case = False
    fn_recursive_lines: list[int] = []

    for line_no, raw_line in enumerate(lines, start=1):
        code_line = _strip_code(raw_line, state).strip()
        raw_lower = raw_line.lower()
        code_lower = code_line.lower()

        sensitive_here = bool(_SENSITIVE_FUNCTIONS.search(code_line))
        if sensitive_here:
            recent_sensitive_lines.append(line_no)
            recent_sensitive_lines = recent_sensitive_lines[-3:]

        # ── 1. Infinite Recursion ─────────────────────────────────────────────
        fn_start = re.search(r"^\s*(?:int|void|bool|double|float|long|auto)\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", code_line)
        if fn_start:
            current_fn = fn_start.group(1)
            fn_has_base_case = False
            fn_recursive_lines = []

        if current_fn:
            if re.search(r"\bif\s*\(", code_line) or (re.search(r"\breturn\b", code_line) and not re.search(rf"\b{re.escape(current_fn)}\s*\(", code_line)):
                fn_has_base_case = True
            if re.search(rf"\b{re.escape(current_fn)}\s*\(", code_line) and not fn_start:
                fn_recursive_lines.append(line_no)

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
                if (
                    re.search(rf"^\s*{re.escape(uv)}\s*=", code_line)
                    or re.search(rf"cin\s*>>.*?\b{re.escape(uv)}\b", code_line)
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

        scanf_match = re.search(r"\bscanf\s*\((.+)\)\s*;?\s*$", code_line)
        if scanf_match:
            args = _split_args(scanf_match.group(1))
            if args:
                fmt = _string_literal_value(args[0])
                if fmt and re.search(r"%\s*s", fmt) and not re.search(r"%\d+s", fmt):
                    emit(
                        line_no,
                        "Unbounded Input",
                        "High",
                        "scanf() is reading a string with %s and no width limit.",
                        "Add an explicit width specifier or use std::string with bounded parsing.",
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

        if re.search(r"\b(?:[A-Za-z_]\w*\s*[\+\-\*/]\s*[A-Za-z_0-9()]+)\b", code_line) and (
            "INT_MAX" in code_line or "SIZE_MAX" in code_line or "sizeof" in code_line or re.search(r"\b(?:alloc|size|len|count|capacity)\b", code_line)
        ) and not (re.search(r">\s*0\b", code_line) or re.search(r"!=\s*0\b", code_line) or "sizeof" in code_line):
            emit(
                line_no,
                "Integer Overflow",
                "High",
                "Arithmetic on size-like values may overflow before allocation or indexing.",
                "Validate operands before arithmetic and use checked addition/multiplication for allocation sizes.",
            )

        if "malloc(" in code_line:
            current_scope()["malloc_lines"].append(line_no)

        if "free(" in code_line:
            for scope in scope_stack:
                scope["free_seen"] = True

        delete_match = _DELETE_RE.search(code_line)
        if delete_match:
            freed_vars[delete_match.group(1)] = line_no

        for freed_name, freed_line in list(freed_vars.items()):
            if re.search(rf"\bdelete\s*(?:\[\])?\s*{re.escape(freed_name)}\s*;", code_line) and line_no != freed_line:
                emit(
                    line_no,
                    "Double Free",
                    "High",
                    "The same pointer appears to be deleted more than once.",
                    "Set the pointer to nullptr immediately after delete or switch to smart pointers.",
                )
            if re.search(rf"\*\s*{re.escape(freed_name)}\b|{re.escape(freed_name)}\s*->|{re.escape(freed_name)}\s*\[", code_line):
                emit(
                    line_no,
                    "Use After Free",
                    "High",
                    "Memory appears to be accessed after it was freed.",
                    "Do not use the pointer after delete; prefer unique_ptr or reset the pointer to nullptr.",
                )

        open_braces = code_line.count("{")
        close_braces = code_line.count("}")
        for _ in range(open_braces):
            scope_stack.append({"start_line": line_no, "malloc_lines": [], "free_seen": False})
        for _ in range(close_braces):
            if len(scope_stack) <= 1:
                continue
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

    while len(scope_stack) > 1:
        finished = scope_stack.pop()
        if finished["malloc_lines"] and not finished["free_seen"]:
            for malloc_line in finished["malloc_lines"]:
                findings.append(
                    _make_finding(
                        source_path,
                        malloc_line,
                        None,
                        "Medium",
                        "Potential Memory Leak",
                        "malloc() allocates memory in this scope without a matching free() before the scope closes.",
                        "Release the allocation with free() in the same scope or replace manual ownership with RAII/smart pointers.",
                        "static_scan",
                    )
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
            lines.append(f"{badge} {finding.vulnerability_type} - {location}")
            lines.append(f"  Description: {finding.description}")
            lines.append(f"  Recommendation: {finding.recommendation}")
            lines.append("")

    lines.append(f"Risk score: {score} ({_risk_label(score)})")
    return "\n".join(lines).strip() + "\n"
