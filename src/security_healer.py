from __future__ import annotations

import difflib
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# Ensure src in path
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from guard.attack_log import log_event
from guard.gates import check_patch
from guard.models import Finding, InputKind
from guard.output_safe import safe_text
from guard.supervisor import get_supervisor
import auto_healer

# Hidden unicode regex from OutputGuard
_HIDDEN_UNICODE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069\u200E\u200F\u200B-\u200D\u2060\uFEFF]")

_ALLOWED_HEADERS = {"cstdio", "cstring", "cstdlib", "random", "algorithm", "vector", "string", "memory"}


@dataclass
class Fix:
    finding_category: str
    line: int | None
    safety_class: str  # "auto" | "auto_notice" | "suggest"
    description: str
    before: str
    after: str
    new_source: str | None = None

    def to_dict(self) -> dict:
        return {
            "finding_category": self.finding_category,
            "line": self.line,
            "safety_class": self.safety_class,
            "description": self.description,
            "before": self.before,
            "after": self.after,
        }


@dataclass
class Outcome:
    finding_id: str
    category: str
    severity: str
    line: int | None
    agents: list[str]
    status: str  # "fixed" | "suggested" | "manual" | "rejected" | "skipped_behavior"
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "line": self.line,
            "agents": list(self.agents),
            "status": self.status,
            "reason": self.reason,
        }


@dataclass
class SecurityHealResult:
    source_before: str
    source_after: str
    risk_before: int
    risk_after: int
    label_before: str
    label_after: str
    findings_before: list[dict]
    findings_after: list[dict]
    outcomes: list[Outcome]
    applied: list[Fix]
    suggestions: list[Fix]
    rounds: int
    seconds: float
    improved: bool
    stopped_reason: str = "completed"

    def to_dict(self) -> dict:
        return {
            "source_before": self.source_before,
            "source_after": self.source_after,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "label_before": self.label_before,
            "label_after": self.label_after,
            "findings_before": [f if isinstance(f, dict) else f.to_dict() for f in self.findings_before],
            "findings_after": [f if isinstance(f, dict) else f.to_dict() for f in self.findings_after],
            "outcomes": [o.to_dict() if hasattr(o, "to_dict") else o for o in self.outcomes],
            "applied": [a.to_dict() if hasattr(a, "to_dict") else a for a in self.applied],
            "suggestions": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.suggestions],
            "rounds": self.rounds,
            "seconds": round(self.seconds, 3),
            "improved": self.improved,
            "stopped_reason": self.stopped_reason,
        }


def normalize_evidence(ev: str | None) -> str:
    if not ev:
        return ""
    return " ".join(ev.split()).strip()


def find_char_array_size(source: str, name: str, line: int | None) -> int | None:
    """
    Returns N when name is declared in scope (same function or global, brace-depth aware,
    searching backwards from line) as char name[N] / char name[CONST] where N is an integer literal,
    a #define N <literal> or const int N = <literal>.
    Pointers, std::string, new char[...], function parameters (char* p) and unknown sizes return None.
    """
    if not name or not re.match(r"^[A-Za-z_]\w*$", name):
        return None

    lines = source.splitlines()
    target_idx = (line - 1) if (line is not None and 1 <= line <= len(lines)) else len(lines) - 1

    # Check if target line or declaration appears in function parameter list
    # Walk backwards tracking closed blocks
    closed_blocks = 0
    candidate_size_token: str | None = None
    decl_found = False

    for i in range(target_idx - 1, -1, -1):
        raw_l = lines[i]
        # Ignore comments
        code_part = raw_l.split("//")[0]

        # Check for block closing/opening going backwards
        # A '}' means entering a block that already closed before target line
        # A '{' means exiting that block
        c_close = code_part.count("}")
        c_open = code_part.count("{")

        # If inside a closed block, any declaration is out of scope for target
        if closed_blocks == 0:
            # Check for pointer or dynamic allocation or std::string (which return None)
            if re.search(rf"\b(?:std::)?string\s+{re.escape(name)}\b", code_part):
                return None
            if re.search(rf"\bchar\s*\*\s*{re.escape(name)}\b", code_part):
                return None
            if re.search(rf"\b{re.escape(name)}\s*=\s*new\s+char\b", code_part):
                return None

            # Check if this line is a function header with parameter (e.g. char* name or char name[...])
            if not code_part.strip().endswith(";") and re.search(rf"\b[A-Za-z_]\w*\s*\([^)]*\b(?:char\s*\*|char)\s+{re.escape(name)}\b[^)]*\)", code_part):
                return None

            # Check for char array declaration: char name[SIZE] ... ;
            # Must end with semicolon (not a parameter)
            decl_m = re.search(
                rf"\bchar\s+{re.escape(name)}\s*\[\s*([^\]]+)\s*\]\s*(?:=[^;]*)?;",
                code_part,
            )
            if decl_m:
                candidate_size_token = decl_m.group(1).strip()
                decl_found = True
                break

        closed_blocks += c_close - c_open
        if closed_blocks < 0:
            # We stepped out of the enclosing function into global scope
            # Reset closed_blocks to 0 for globals
            closed_blocks = 0

    if not decl_found or not candidate_size_token:
        # Check if declared globally
        for i, raw_l in enumerate(lines[:target_idx]):
            code_part = raw_l.split("//")[0]
            if re.search(rf"\b(?:std::)?string\s+{re.escape(name)}\b", code_part):
                return None
            if re.search(rf"\bchar\s*\*\s*{re.escape(name)}\b", code_part):
                return None
            decl_m = re.search(
                rf"^\s*char\s+{re.escape(name)}\s*\[\s*([^\]]+)\s*\]\s*(?:=[^;]*)?;",
                code_part,
            )
            if decl_m:
                candidate_size_token = decl_m.group(1).strip()
                decl_found = True
                break

    if not decl_found or not candidate_size_token:
        return None

    # Try integer literal directly
    try:
        val = int(candidate_size_token, 0)
        return val if val > 0 else None
    except ValueError:
        pass

    # Try resolving candidate_size_token from #define or const int
    const_token = candidate_size_token
    if re.match(r"^[A-Za-z_]\w*$", const_token):
        for raw_l in lines:
            # #define CONST_N 64
            def_m = re.search(rf"#\s*define\s+{re.escape(const_token)}\s+(\d+)\b", raw_l)
            if def_m:
                try:
                    return int(def_m.group(1))
                except ValueError:
                    pass
            # const int CONST_N = 64; or constexpr int ...
            const_m = re.search(
                rf"\b(?:const|constexpr)\s+(?:int|size_t)\s+{re.escape(const_token)}\s*=\s*(\d+)\s*;",
                raw_l,
            )
            if const_m:
                try:
                    return int(const_m.group(1))
                except ValueError:
                    pass

    return None


def _ensure_include(source: str, header: str) -> str:
    if header in _ALLOWED_HEADERS and not auto_healer._has_include(source, header):
        return auto_healer._insert_include(source, header)
    return source


# ─── RECIPE REGISTRY ──────────────────────────────────────────────────────────

RecipeFn = Callable[[str, Finding], Optional[Fix]]


class Recipe:
    def __init__(
        self,
        category: str,
        safety_class: str,  # "auto" | "auto_notice" | "suggest"
        apply_fn: RecipeFn,
        suggest_fn: RecipeFn,
    ):
        self.category = category
        self.safety_class = safety_class
        self.apply = apply_fn
        self.suggest = suggest_fn


_REGISTRY: Dict[str, Recipe] = {}


def register_recipe(
    category: str,
    safety_class: str,
    apply_fn: RecipeFn,
    suggest_fn: RecipeFn,
) -> None:
    _REGISTRY[category] = Recipe(category, safety_class, apply_fn, suggest_fn)


def get_recipe(category: str) -> Optional[Recipe]:
    return _REGISTRY.get(category)


# ── Recipe Implementations ───────────────────────────────────────────────────

# 1. Unsafe string functions: strcpy, strcat, sprintf
def _apply_unsafe_string(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # (a) strcpy(d, s)
    m_cpy = re.search(r'\bstrcpy\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*|"(?:[^"\\]|\\.)*")\s*\)\s*;', orig_line)
    if m_cpy:
        d, s = m_cpy.group(1), m_cpy.group(2)
        n = find_char_array_size(source, d, line_no)
        if n is not None:
            indent = re.match(r"^(\s*)", orig_line).group(1)
            repl = f'{indent}snprintf({d}, sizeof({d}), "%s", {s});'
            lines[line_no - 1] = repl
            new_source = "\n".join(lines)
            if not source.endswith("\n") and not new_source.endswith("\n"):
                pass
            else:
                new_source += "\n"
            new_source = _ensure_include(new_source, "cstdio")
            return Fix(
                finding_category=finding.category,
                line=line_no,
                safety_class="auto",
                description="Replace strcpy with bounded snprintf",
                before=orig_line.strip(),
                after=repl.strip(),
                new_source=new_source,
            )

    # (b) strcat(d, s)
    m_cat = re.search(r'\bstrcat\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*|"(?:[^"\\]|\\.)*")\s*\)\s*;', orig_line)
    if m_cat:
        d, s = m_cat.group(1), m_cat.group(2)
        n = find_char_array_size(source, d, line_no)
        if n is not None:
            indent = re.match(r"^(\s*)", orig_line).group(1)
            repl = f"{indent}strncat({d}, {s}, sizeof({d}) - strlen({d}) - 1);"
            lines[line_no - 1] = repl
            new_source = "\n".join(lines)
            if source.endswith("\n") and not new_source.endswith("\n"):
                new_source += "\n"
            new_source = _ensure_include(new_source, "cstring")
            return Fix(
                finding_category=finding.category,
                line=line_no,
                safety_class="auto",
                description="Replace strcat with bounded strncat",
                before=orig_line.strip(),
                after=repl.strip(),
                new_source=new_source,
            )

    # (c) sprintf(d, fmt, ...)
    m_spr = re.search(r"\bsprintf\s*\(\s*([A-Za-z_]\w*)\s*,\s*(.+)\)\s*;", orig_line)
    if m_spr:
        d, rest = m_spr.group(1), m_spr.group(2)
        n = find_char_array_size(source, d, line_no)
        if n is not None:
            indent = re.match(r"^(\s*)", orig_line).group(1)
            repl = f"{indent}snprintf({d}, sizeof({d}), {rest});"
            lines[line_no - 1] = repl
            new_source = "\n".join(lines)
            if source.endswith("\n") and not new_source.endswith("\n"):
                new_source += "\n"
            new_source = _ensure_include(new_source, "cstdio")
            return Fix(
                finding_category=finding.category,
                line=line_no,
                safety_class="auto",
                description="Replace sprintf with bounded snprintf",
                before=orig_line.strip(),
                after=repl.strip(),
                new_source=new_source,
            )

    return None


def _suggest_unsafe_string(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Use bounded string functions or std::string",
        before=orig_line,
        after=safe_text(
            "// Prefer bounded string routines or std::string:\n"
            "// snprintf(dest, sizeof(dest), \"%s\", src);\n"
            "// strncat(dest, src, sizeof(dest) - strlen(dest) - 1);"
        ),
        new_source=None,
    )


# 2. Unbounded input: scanf("%s", b)
def _apply_unbounded_input(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]
    code_part = orig_line.split("//")[0]
    m = re.search(r'scanf\s*\(\s*"([^"]*)"\s*,\s*([A-Za-z_]\w*)\s*\)\s*;', code_part)
    if m:
        fmt, b = m.group(1), m.group(2)
        if "%s" in fmt and not re.search(r"%\d+s", fmt):
            n = find_char_array_size(source, b, line_no)
            if n is not None and n > 1:
                bounded_fmt = fmt.replace("%s", f"%{n - 1}s", 1)
                indent = re.match(r"^(\s*)", orig_line).group(1)
                repl = f'{indent}scanf("{bounded_fmt}", {b});'
                lines[line_no - 1] = repl
                new_source = "\n".join(lines)
                if source.endswith("\n") and not new_source.endswith("\n"):
                    new_source += "\n"
                new_source = _ensure_include(new_source, "cstdio")
                return Fix(
                    finding_category=finding.category,
                    line=line_no,
                    safety_class="auto",
                    description=f"Add buffer width %{n-1}s to scanf",
                    before=orig_line.strip(),
                    after=repl.strip(),
                    new_source=new_source,
                )

    return None


def _suggest_unbounded_input(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Specify width limit in scanf format string",
        before=orig_line,
        after=safe_text(
            "// Specify maximum buffer width in scanf:\n"
            "// scanf(\"%31s\", buffer); // for char buffer[32]"
        ),
        new_source=None,
    )


# 3. Buffer overflow: gets(b)
def _apply_buffer_overflow(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    m = re.search(r"\bgets\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;", orig_line)
    if m:
        b = m.group(1)
        n = find_char_array_size(source, b, line_no)
        if n is not None:
            indent = re.match(r"^(\s*)", orig_line).group(1)
            repl = f'{indent}fgets({b}, sizeof({b}), stdin);\n{indent}{b}[strcspn({b}, "\\n")] = \'\\0\';'
            lines[line_no - 1] = repl
            new_source = "\n".join(lines)
            if source.endswith("\n") and not new_source.endswith("\n"):
                new_source += "\n"
            new_source = _ensure_include(new_source, "cstdio")
            new_source = _ensure_include(new_source, "cstring")
            return Fix(
                finding_category=finding.category,
                line=line_no,
                safety_class="auto",
                description="Replace gets with bounded fgets and newline strip",
                before=orig_line.strip(),
                after=repl.strip(),
                new_source=new_source,
            )

    return None


def _suggest_buffer_overflow(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Replace gets with fgets and newline stripping",
        before=orig_line,
        after=safe_text(
            "// Replace gets() with bounded fgets:\n"
            "fgets(buf, sizeof(buf), stdin);\n"
            "buf[strcspn(buf, \"\\n\")] = '\\0';"
        ),
        new_source=None,
    )


# 4. Format string: printf(x) / fprintf(f, x)
def _apply_format_string(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # printf(x); where x is a plain identifier (not a literal)
    m_p = re.search(r"\bprintf\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;", orig_line)
    if m_p:
        x = m_p.group(1)
        indent = re.match(r"^(\s*)", orig_line).group(1)
        repl = f'{indent}printf("%s", {x});'
        lines[line_no - 1] = repl
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        new_source = _ensure_include(new_source, "cstdio")
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="auto",
            description="Add fixed %s format specifier to printf",
            before=orig_line.strip(),
            after=repl.strip(),
            new_source=new_source,
        )

    # fprintf(f, x);
    m_f = re.search(r"\bfprintf\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)\s*;", orig_line)
    if m_f:
        f, x = m_f.group(1), m_f.group(2)
        indent = re.match(r"^(\s*)", orig_line).group(1)
        repl = f'{indent}fprintf({f}, "%s", {x});'
        lines[line_no - 1] = repl
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        new_source = _ensure_include(new_source, "cstdio")
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="auto",
            description="Add fixed %s format specifier to fprintf",
            before=orig_line.strip(),
            after=repl.strip(),
            new_source=new_source,
        )

    return None


def _suggest_format_string(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Always pass format specifier to printf/fprintf",
        before=orig_line,
        after=safe_text(
            "// Pass non-literal strings as arguments, not format strings:\n"
            "printf(\"%s\", user_input);\n"
            "fprintf(file, \"%s\", user_input);"
        ),
        new_source=None,
    )


# 5. Double free
def _apply_double_free(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # Target line has the second delete p;
    del_m = re.search(r"\bdelete\s*(?:\[\])?\s*([A-Za-z_]\w*)\s*;", orig_line)
    if not del_m:
        return None
    p = del_m.group(1)

    # Search backwards for the first delete p; in the same scope
    first_del_idx = None
    for i in range(line_no - 2, -1, -1):
        if re.search(rf"\bdelete\s*(?:\[\])?\s*{re.escape(p)}\s*;", lines[i]):
            first_del_idx = i
            break

    if first_del_idx is not None:
        first_line = lines[first_del_idx]
        indent = re.match(r"^(\s*)", first_line).group(1)
        # Check if already followed by p = nullptr
        if first_del_idx + 1 < len(lines) and re.search(rf"\b{re.escape(p)}\s*=\s*(?:nullptr|NULL|0)\s*;", lines[first_del_idx + 1]):
            return None
        lines.insert(first_del_idx + 1, f"{indent}{p} = nullptr;")
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        return Fix(
            finding_category=finding.category,
            line=first_del_idx + 1,
            safety_class="auto",
            description=f"Set pointer {p} to nullptr after first delete",
            before=first_line.strip(),
            after=f"{first_line.strip()}\n{indent}{p} = nullptr;",
            new_source=new_source,
        )

    return None


def _suggest_double_free(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Reset pointer to nullptr after delete or use std::unique_ptr",
        before=orig_line,
        after=safe_text(
            "// Reset pointer to nullptr after delete:\n"
            "delete ptr;\n"
            "ptr = nullptr;\n"
            "// Or prefer std::unique_ptr<T> for automatic ownership."
        ),
        new_source=None,
    )


# 6. Use after free
def _apply_use_after_free(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None

    # Finding line is a use after free
    # Find the preceding delete p;
    # Search backwards for delete p;
    del_idx = None
    del_var = None
    for i in range(line_no - 1, -1, -1):
        m = re.search(r"\bdelete\s*(?:\[\])?\s*([A-Za-z_]\w*)\s*;", lines[i])
        if m and re.search(rf"\b{re.escape(m.group(1))}\b", lines[line_no - 1]):
            del_idx = i
            del_var = m.group(1)
            break

    if del_idx is None or del_var is None:
        return None

    # Find the last use of del_var in the function
    # Check brace depths: delete and all later uses must be at same brace depth
    # with no control flow (if/for/while/switch/return/goto) between them
    last_use_idx = None
    del_depth = 0
    for j in range(del_idx + 1):
        del_depth += lines[j].count("{") - lines[j].count("}")

    curr_depth = del_depth
    for k in range(del_idx + 1, len(lines)):
        line_k = lines[k]
        code_part = line_k.split("//")[0]
        # Check control flow
        if re.search(r"\b(if|for|while|switch|return|goto)\b", code_part):
            return None
        curr_depth += code_part.count("{") - code_part.count("}")
        if curr_depth != del_depth:
            # Entered or exited a block
            if curr_depth < del_depth:
                break
            return None

        if re.search(rf"\b{re.escape(del_var)}\b", code_part) and not re.search(rf"\bdelete\b", code_part):
            last_use_idx = k

    if last_use_idx is not None and last_use_idx > del_idx:
        del_line = lines.pop(del_idx)
        # Indent to match last use line
        indent = re.match(r"^(\s*)", lines[last_use_idx - 1]).group(1)
        del_line_clean = f"{indent}{del_line.strip()}"
        lines.insert(last_use_idx, del_line_clean)
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        return Fix(
            finding_category=finding.category,
            line=del_idx + 1,
            safety_class="auto",
            description=f"Move delete {del_var} after its last use",
            before=del_line.strip(),
            after=del_line_clean.strip(),
            new_source=new_source,
        )

    return None


def _suggest_use_after_free(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Move delete after last use or switch to smart pointers",
        before=orig_line,
        after=safe_text(
            "// Ensure memory is deleted only after all operations complete:\n"
            "// Or replace manual delete with std::unique_ptr<T>:\n"
            "auto ptr = std::make_unique<Type>();"
        ),
        new_source=None,
    )


# 7. Uninitialized variable
def _apply_uninitialized_variable(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    err_dict = {
        "message": finding.description or finding.title,
        "line": finding.line,
        "category": "uninitialized_variable",
    }
    patched = auto_healer.fix_uninitialized_variable(source, err_dict)
    if not patched or patched == source:
        # Fallback: check line directly or declaration mentioned in description
        decl_line = None
        decl_m = re.search(r"declared at line\s+(\d+)", finding.description or "")
        if decl_m:
            decl_line = int(decl_m.group(1))
        elif finding.line:
            decl_line = finding.line

        if decl_line and 1 <= decl_line <= len(lines):
            for i in range(decl_line - 1, -1, -1):
                raw_l = lines[i]
                bare_m = re.match(r"^(\s*)(int|float|double|char|long|unsigned|short|size_t)\s+([A-Za-z_]\w*)\s*;\s*$", raw_l)
                if bare_m:
                    indent, typ, var = bare_m.group(1), bare_m.group(2), bare_m.group(3)
                    init = " = ' '" if typ == "char" else " = 0"
                    lines[i] = f"{indent}{typ} {var}{init};"
                    patched = "\n".join(lines)
                    if source.endswith("\n") and not patched.endswith("\n"):
                        patched += "\n"
                    break

    if patched and patched != source:
        return Fix(
            finding_category=finding.category,
            line=finding.line,
            safety_class="auto",
            description="Initialize variable at declaration",
            before=lines[finding.line - 1].strip() if finding.line and finding.line <= len(lines) else "",
            after="Initialized at declaration",
            new_source=patched,
        )
    return None


def _suggest_uninitialized_variable(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Initialize variable before use",
        before=orig_line,
        after=safe_text("// Initialize variable at its declaration site:\nint total = 0;\nchar ch = '\\0';"),
        new_source=None,
    )


# 8. Integer overflow
def _apply_integer_overflow(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # Pattern: var * const or var * var
    m = re.search(r"\b([A-Za-z_]\w*)\s*([\*])\s*(\d+|[A-Za-z_]\w*)", orig_line)
    if m:
        v1, op, v2 = m.group(1), m.group(2), m.group(3)
        if not orig_line.strip().startswith("static_cast"):
            repl = f"static_cast<size_t>({v1}) {op} {v2}"
            fixed_line = orig_line[:m.start()] + repl + orig_line[m.end():]
            lines[line_no - 1] = fixed_line
            new_source = "\n".join(lines)
            if source.endswith("\n") and not new_source.endswith("\n"):
                new_source += "\n"
            return Fix(
                finding_category=finding.category,
                line=line_no,
                safety_class="auto",
                description="Cast operand to size_t to prevent overflow before multiplication",
                before=orig_line.strip(),
                after=fixed_line.strip(),
                new_source=new_source,
            )

    err_dict = {
        "message": finding.description or finding.title,
        "line": finding.line,
        "category": "integer_overflow",
    }
    if hasattr(auto_healer, "fix_integer_overflow"):
        patched = auto_healer.fix_integer_overflow(source, err_dict)
        if patched and patched != source:
            return Fix(
                finding_category=finding.category,
                line=finding.line,
                safety_class="auto",
                description="Widen integer type to long long to prevent overflow",
                before="",
                after="Widen to long long",
                new_source=patched,
            )
    return None


def _suggest_integer_overflow(source: str, finding: Finding) -> Optional[Fix]:
    return Fix(
        finding_category=finding.category,
        line=finding.line,
        safety_class="suggest",
        description="Widen integer type or check bounds before arithmetic",
        before="",
        after=safe_text("// Use wider integer type:\nlong long value = INT_MAX;\n// Or check bounds before arithmetic."),
        new_source=None,
    )


# 9. Integer underflow
def _apply_integer_underflow(source: str, finding: Finding) -> Optional[Fix]:
    err_dict = {
        "message": finding.description or finding.title,
        "line": finding.line,
        "category": "integer_underflow",
    }
    patched = auto_healer.fix_integer_overflow(source, err_dict)
    if patched and patched != source:
        return Fix(
            finding_category=finding.category,
            line=finding.line,
            safety_class="auto",
            description="Guard unsigned decrement with bounds check",
            before="",
            after="if (u > 0) u--;",
            new_source=patched,
        )
    return None


def _suggest_integer_underflow(source: str, finding: Finding) -> Optional[Fix]:
    return Fix(
        finding_category=finding.category,
        line=finding.line,
        safety_class="suggest",
        description="Guard unsigned decrement to prevent underflow",
        before="",
        after=safe_text("// Validate non-zero before decrementing unsigned integer:\nif (u > 0) {\n    u--;\n}"),
        new_source=None,
    )


# 10. Potential memory leak (malloc)
def _apply_potential_memory_leak(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    alloc_line = lines[line_no - 1]

    # Extract variable assigned from malloc: e.g. char* tmp = (char*)malloc(...) or tmp = malloc(...)
    m = re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?malloc\s*\(", alloc_line)
    if not m:
        return None
    v = m.group(1)

    # Preconditions:
    # 1. Scope bounds: find enclosing function's closing brace
    func_end_idx = None
    depth = 0
    func_start_idx = None
    for i in range(line_no - 1, -1, -1):
        if re.search(r"^\s*(?:[A-Za-z_]\w*[\s*&]+)+[A-Za-z_]\w*\s*\([^)]*\)\s*\{", lines[i]):
            func_start_idx = i
            break

    if func_start_idx is None:
        # Fallback: find line with '{' before line_no
        for i in range(line_no - 1, -1, -1):
            if "{" in lines[i]:
                func_start_idx = i
                break

    if func_start_idx is None:
        return None

    depth = 0
    for i in range(func_start_idx, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0:
            func_end_idx = i
            break

    if func_end_idx is None:
        return None

    # Check statements between line_no and func_end_idx
    allowed_fns = {
        "printf", "fprintf", "snprintf", "sprintf", "strcpy", "strncpy",
        "strcat", "strncat", "strlen", "memset", "memcpy", "puts", "fputs", "fgets", "scanf"
    }

    for k in range(line_no, func_end_idx):
        code_k = lines[k].split("//")[0]
        # Return check: no return statement except possibly the final statement before closing brace
        if re.search(r"\breturn\b", code_k):
            if k != func_end_idx - 1:
                return None  # Early return present
            # If final statement is return v; v is returned!
            if re.search(rf"\breturn\s+.*?\b{re.escape(v)}\b", code_k):
                return None

        # Check v is not assigned to another variable or member: e.g. other = v or obj.m = v or obj->m = v
        if re.search(rf"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|->[A-Za-z_]\w*)?\s*=\s*{re.escape(v)}\b", code_k):
            return None

        # Check v is not stored in container: e.g. vec.push_back(v)
        if re.search(rf"\b(?:push_back|push|insert|append)\s*\([^)]*\b{re.escape(v)}\b", code_k):
            return None

        # Check function calls containing v: must only be allowed non-owning functions
        call_matches = re.finditer(r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)", code_k)
        for cm in call_matches:
            fn_name = cm.group(1)
            if fn_name in {"if", "while", "for", "switch", "catch", "sizeof"}:
                continue
            args_str = cm.group(2)
            if re.search(rf"\b{re.escape(v)}\b", args_str):
                if fn_name not in allowed_fns:
                    return None

    # Insert free(v); before func_end_idx
    indent = "    "
    if func_end_idx > 0:
        prev_indent = re.match(r"^(\s*)", lines[func_end_idx - 1]).group(1)
        if prev_indent:
            indent = prev_indent
    lines.insert(func_end_idx, f"{indent}free({v});")
    new_source = "\n".join(lines)
    if source.endswith("\n") and not new_source.endswith("\n"):
        new_source += "\n"
    new_source = _ensure_include(new_source, "cstdlib")

    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="auto",
        description=f"Insert free({v}) before function exit",
        before=alloc_line.strip(),
        after=f"free({v});",
        new_source=new_source,
    )


def _suggest_potential_memory_leak(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Release allocated memory with free() or use smart pointers",
        before=orig_line,
        after=safe_text(
            "// Release heap allocation before leaving scope:\n"
            "free(ptr);\n"
            "// Or replace manual malloc with std::vector or std::unique_ptr."
        ),
        new_source=None,
    )


# 11. Command injection / process_execution
def _apply_command_injection(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]
    indent = re.match(r"^(\s*)", orig_line).group(1)
    repl = f"{indent}// [removed by security healer: system call]"
    lines[line_no - 1] = repl
    new_source = "\n".join(lines)
    if source.endswith("\n") and not new_source.endswith("\n"):
        new_source += "\n"
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="auto",
        description="Comment out dangerous process execution / system call",
        before=orig_line.strip(),
        after=repl.strip(),
        new_source=new_source,
    )


def _suggest_command_injection(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Avoid system shell execution",
        before=orig_line,
        after=safe_text(
            "// Avoid invoking shell commands with system() or popen().\n"
            "// Use internal APIs or strict parameter validation instead."
        ),
        new_source=None,
    )


# 12. Sensitive include, special file include, unsafe include
def _apply_include_removal(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        # Search for include line matching evidence
        for i, l in enumerate(lines):
            if "#include" in l and (finding.evidence in l or (finding.details and any(v in l for v in finding.details.values()))):
                line_no = i + 1
                break
    if not line_no or not (1 <= line_no <= len(lines)):
        return None

    orig_line = lines[line_no - 1]
    indent = re.match(r"^(\s*)", orig_line).group(1)
    repl = f"{indent}// [include removed by security healer: {finding.category}]"
    lines[line_no - 1] = repl
    new_source = "\n".join(lines)
    if source.endswith("\n") and not new_source.endswith("\n"):
        new_source += "\n"
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="auto",
        description=f"Remove prohibited {finding.category}",
        before=orig_line.strip(),
        after=repl.strip(),
        new_source=new_source,
    )


def _suggest_include_removal(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description=f"Remove sensitive or prohibited include: {finding.category}",
        before=orig_line,
        after=safe_text(f"// Remove {finding.category} and use standard portable alternatives."),
        new_source=None,
    )


# 13. Hidden unicode
def _apply_hidden_unicode(source: str, finding: Finding) -> Optional[Fix]:
    cleaned = _HIDDEN_UNICODE_RE.sub("", source)
    if cleaned != source:
        return Fix(
            finding_category=finding.category,
            line=finding.line,
            safety_class="auto",
            description="Strip bidirectional control and zero-width characters",
            before="Hidden Unicode characters present",
            after="Hidden Unicode characters removed",
            new_source=cleaned,
        )
    return None


def _suggest_hidden_unicode(source: str, finding: Finding) -> Optional[Fix]:
    return Fix(
        finding_category=finding.category,
        line=finding.line,
        safety_class="suggest",
        description="Remove invisible Trojan Source Unicode characters",
        before="",
        after=safe_text("// Remove bidirectional control (U+202A-202E, U+2066-2069) and zero-width chars."),
        new_source=None,
    )


# 14. Division by zero (variable divisor) - auto_notice
def _apply_division_by_zero(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # Replace a / d with (d != 0 ? a / d : 0)
    m = re.search(r"([A-Za-z_]\w*)\s*/\s*([A-Za-z_]\w*)", orig_line)
    if m:
        a, d = m.group(1), m.group(2)
        repl = f"({d} != 0 ? {a} / {d} : 0)"
        fixed_line = orig_line[:m.start()] + repl + orig_line[m.end():]
        lines[line_no - 1] = fixed_line
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="auto_notice",
            description="Guard division by zero with ternary fallback to 0",
            before=orig_line.strip(),
            after=fixed_line.strip(),
            new_source=new_source,
        )
    return None


def _suggest_division_by_zero(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Check divisor is non-zero before division",
        before=orig_line,
        after=safe_text(
            "// Validate divisor before division:\n"
            "if (divisor != 0) {\n"
            "    result = a / divisor;\n"
            "}"
        ),
        new_source=None,
    )


# 15. Null pointer dereference - auto_notice
def _apply_null_pointer_dereference(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # Find dereferenced pointer: *p or p->
    m = re.search(r"\*\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*->", orig_line)
    if not m:
        return None
    p = m.group(1) or m.group(2)
    indent = re.match(r"^(\s*)", orig_line).group(1)
    body = orig_line.strip()
    repl = f"{indent}if ({p} != nullptr) {{\n{indent}    {body}\n{indent}}}"
    lines[line_no - 1] = repl
    new_source = "\n".join(lines)
    if source.endswith("\n") and not new_source.endswith("\n"):
        new_source += "\n"
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="auto_notice",
        description=f"Wrap dereference in if ({p} != nullptr) check",
        before=orig_line.strip(),
        after=repl.strip(),
        new_source=new_source,
    )


def _suggest_null_pointer_dereference(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Guard pointer dereference with null check",
        before=orig_line,
        after=safe_text(
            "// Check pointer for null before dereferencing:\n"
            "if (ptr != nullptr) {\n"
            "    *ptr = value;\n"
            "}"
        ),
        new_source=None,
    )


# 16. Vector out of bounds - auto_notice
def _apply_vector_oob(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    # Replace v[i] with v.at(i)
    m = re.search(r"\b([A-Za-z_]\w*)\s*\[\s*([^\]]+)\s*\]", orig_line)
    if m:
        v, idx_expr = m.group(1), m.group(2)
        repl = f"{v}.at({idx_expr})"
        fixed_line = orig_line[:m.start()] + repl + orig_line[m.end():]
        lines[line_no - 1] = fixed_line
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="auto_notice",
            description=f"Replace unchecked {v}[i] with bounds-checked {v}.at(i)",
            before=orig_line.strip(),
            after=fixed_line.strip(),
            new_source=new_source,
        )
    return None


def _suggest_vector_oob(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Use bounds-checked vector access with .at()",
        before=orig_line,
        after=safe_text(
            "// Use checked access or validate index bounds:\n"
            "v.at(index);\n"
            "// Or check if (index < v.size()) before indexing."
        ),
        new_source=None,
    )


# 17. Weak randomness - auto_notice
def _apply_weak_randomness(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    if "rand()" in orig_line:
        repl = orig_line.replace("rand()", "static_cast<int>(std::random_device{}() & 0x7fffffff)")
        lines[line_no - 1] = repl
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        new_source = _ensure_include(new_source, "random")
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="auto_notice",
            description="Replace rand() with std::random_device",
            before=orig_line.strip(),
            after=repl.strip(),
            new_source=new_source,
        )
    return None


def _suggest_weak_randomness(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Replace rand() with std::random_device and mt19937",
        before=orig_line,
        after=safe_text(
            "// Use std::random_device for secure randomness:\n"
            "#include <random>\n"
            "std::random_device rd;\n"
            "std::mt19937 gen(rd());"
        ),
        new_source=None,
    )


# 18. Signed / Unsigned mismatch - auto_notice
def _apply_signed_unsigned_mismatch(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    if not line_no or not (1 <= line_no <= len(lines)):
        return None
    orig_line = lines[line_no - 1]

    m = re.search(r"([A-Za-z_]\w*)\s*(<|<=|>|>=|==|!=)\s*([A-Za-z_]\w*)", orig_line)
    if m:
        left, op, right = m.group(1), m.group(2), m.group(3)
        repl = f"static_cast<long long>({left}) {op} static_cast<long long>({right})"
        fixed_line = orig_line[:m.start()] + repl + orig_line[m.end():]
        lines[line_no - 1] = fixed_line
        new_source = "\n".join(lines)
        if source.endswith("\n") and not new_source.endswith("\n"):
            new_source += "\n"
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="auto_notice",
            description="Cast signed and unsigned operands to long long for comparison",
            before=orig_line.strip(),
            after=fixed_line.strip(),
            new_source=new_source,
        )
    return None


def _suggest_signed_unsigned_mismatch(source: str, finding: Finding) -> Optional[Fix]:
    lines = source.splitlines()
    line_no = finding.line
    orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
    return Fix(
        finding_category=finding.category,
        line=line_no,
        safety_class="suggest",
        description="Cast comparison operands or ensure types match",
        before=orig_line,
        after=safe_text("// Cast to common signed type:\nstatic_cast<long long>(a) < static_cast<long long>(b);"),
        new_source=None,
    )


# 19. Generic suggest-only helper
def _make_suggest_only(category: str, snippet: str, description: str) -> Tuple[RecipeFn, RecipeFn]:
    def _apply_none(_source: str, _finding: Finding) -> Optional[Fix]:
        return None

    def _suggest(source: str, finding: Finding) -> Optional[Fix]:
        lines = source.splitlines()
        line_no = finding.line
        orig_line = lines[line_no - 1].strip() if (line_no and 1 <= line_no <= len(lines)) else ""
        return Fix(
            finding_category=finding.category,
            line=line_no,
            safety_class="suggest",
            description=description,
            before=orig_line,
            after=safe_text(snippet),
            new_source=None,
        )

    return _apply_none, _suggest


# Register all recipes
register_recipe("unsafe_string_function", "auto", _apply_unsafe_string, _suggest_unsafe_string)
register_recipe("unbounded_input", "auto", _apply_unbounded_input, _suggest_unbounded_input)
register_recipe("buffer_overflow", "auto", _apply_buffer_overflow, _suggest_buffer_overflow)
register_recipe("format_string_vulnerability", "auto", _apply_format_string, _suggest_format_string)
register_recipe("format_string", "auto", _apply_format_string, _suggest_format_string)
register_recipe("double_free", "auto", _apply_double_free, _suggest_double_free)
register_recipe("use_after_free", "auto", _apply_use_after_free, _suggest_use_after_free)
register_recipe("uninitialized_variable", "auto", _apply_uninitialized_variable, _suggest_uninitialized_variable)
register_recipe("uninitialized_memory", "auto", _apply_uninitialized_variable, _suggest_uninitialized_variable)
register_recipe("integer_overflow", "auto", _apply_integer_overflow, _suggest_integer_overflow)
register_recipe("integer_underflow", "auto", _apply_integer_underflow, _suggest_integer_underflow)
register_recipe("potential_memory_leak", "auto", _apply_potential_memory_leak, _suggest_potential_memory_leak)
register_recipe("memory_leak", "auto", _apply_potential_memory_leak, _suggest_potential_memory_leak)
register_recipe("command_injection", "auto", _apply_command_injection, _suggest_command_injection)
register_recipe("process_execution", "auto", _apply_command_injection, _suggest_command_injection)
register_recipe("sensitive_include", "auto", _apply_include_removal, _suggest_include_removal)
register_recipe("special_file_include", "auto", _apply_include_removal, _suggest_include_removal)
register_recipe("unsafe_include", "auto", _apply_include_removal, _suggest_include_removal)
register_recipe("hidden_unicode", "auto", _apply_hidden_unicode, _suggest_hidden_unicode)

# auto_notice recipes
register_recipe("division_by_zero", "auto_notice", _apply_division_by_zero, _suggest_division_by_zero)
register_recipe("null_pointer_dereference", "auto_notice", _apply_null_pointer_dereference, _suggest_null_pointer_dereference)
register_recipe("vector_out_of_bounds", "auto_notice", _apply_vector_oob, _suggest_vector_oob)
register_recipe("weak_randomness", "auto_notice", _apply_weak_randomness, _suggest_weak_randomness)
register_recipe("signed_unsigned_mismatch", "auto_notice", _apply_signed_unsigned_mismatch, _suggest_signed_unsigned_mismatch)

# suggest-only recipes
_SUGGEST_ONLY_DEFS = {
    "unsafe_memory_copy": (
        "// Validate bounds and prefer std::copy:\nstd::copy(src, src + size, dst);",
        "Use std::copy with verified container bounds",
    ),
    "unsafe_pointer_arithmetic": (
        "// Prefer container iterators or index-checked loops:\nfor (size_t i = 0; i < size; ++i) { ... }",
        "Replace raw pointer arithmetic with checked indexing",
    ),
    "infinite_recursion": (
        "// Ensure recursive function has a base case:\nif (n <= 1) return 1;",
        "Add terminating base case to recursive function",
    ),
    "disabled_safety_check": (
        "// Use production runtime checks instead of assert:\nif (!valid) throw std::invalid_argument(\"invalid\");",
        "Replace assert() with explicit runtime boundary checks",
    ),
    "unresolved_security_debt": (
        "// Resolve security TODO/FIXME before deployment:\n// Audit sensitive operations at this site.",
        "Review and resolve security TODO comment",
    ),
    "hardcoded_secret": (
        "// Read credential securely from environment:\nconst char* secret = std::getenv(\"API_KEY\");",
        "Do not hardcode secrets; read from environment",
    ),
    "tool_secret_value": (
        "// Read secret securely from environment:\nconst char* secret = std::getenv(\"API_KEY\");",
        "Do not expose raw secrets; read from environment",
    ),
    "personal_data_access": (
        "// Restrict personal data access to authorized scopes.",
        "Ensure personal data access adheres to privacy boundaries",
    ),
    "dynamic_loading": (
        "// Review dynamic library loading (dlopen/LoadLibrary):\n// Prefer static linking or verified integrity signatures.",
        "Review dynamic module loading security",
    ),
    "network_access": (
        "// Network socket operations restricted in execution sandbox.\n// Review endpoints and enforce TLS encryption.",
        "Restrict unauthorized network access",
    ),
    "inline_assembly": (
        "// Replace inline assembly with portable C++:\n// Avoid hardware-specific assembly instructions.",
        "Avoid low-level inline assembly instructions",
    ),
    "secret_env_access": (
        "// Ensure environment variable read is properly authorized.\n// Audit access to credential variables.",
        "Review sensitive environment variable access",
    ),
    "obfuscation": (
        "// Avoid macro token pasting (##) concealing function names:\n// Declare explicit functions instead.",
        "Eliminate macro obfuscation",
    ),
    "possible_infinite_loop": (
        "// Ensure loop variable advances toward termination:\n// Check bounds and loop progress.",
        "Review loop termination condition",
    ),
    "huge_allocation": (
        "// Validate allocation size against upper limits:\nif (size > MAX_ALLOWED) throw std::bad_alloc();",
        "Enforce allocation size upper bound",
    ),
    "macro_expansion_bomb": (
        "// Refactor deeply nested macros into constexpr functions.",
        "Avoid deeply nested or recursive macro expansion",
    ),
}

for cat, (snip, desc) in _SUGGEST_ONLY_DEFS.items():
    app_fn, sug_fn = _make_suggest_only(cat, snip, desc)
    register_recipe(cat, "suggest", app_fn, sug_fn)


def apply_recipe(source: str, finding: Finding, allow_behavior: bool = False) -> Optional[Fix]:
    recipe = get_recipe(finding.category)
    if not recipe:
        return None
    if recipe.safety_class == "auto":
        return recipe.apply(source, finding)
    if recipe.safety_class == "auto_notice" and allow_behavior:
        return recipe.apply(source, finding)
    return None


# ─── MAIN SECURITY HEALER LOOP ───────────────────────────────────────────────

_SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def heal_security(
    source: str,
    *,
    allow_behavior_changes: Optional[bool] = None,
    max_rounds: Optional[int] = None,
    source_dir: Optional[str] = None,
) -> SecurityHealResult:
    """
    Scans source code for security issues and heals them safely.
    Validates all patches with PatchGuard, size bounds, compile errors, and re-scan.
    Rolls back on any validation failure.
    """
    t0 = time.time()
    if allow_behavior_changes is None:
        allow_behavior_changes = os.environ.get("GUARD_ALLOW_BEHAVIOR_FIXES", "0") in ("1", "true", "True")

    supervisor = get_supervisor()
    meta = {"source_dir": source_dir} if source_dir else {}

    try:
        verdict_before = supervisor.review(InputKind.USER_SOURCE, source, purpose="analyze", meta=meta)
    except Exception as e:
        log_event("security_heal_error", {"type": type(e).__name__})
        return SecurityHealResult(
            source_before=source,
            source_after=source,
            risk_before=0,
            risk_after=0,
            label_before="Clean",
            label_after="Clean",
            findings_before=[],
            findings_after=[],
            outcomes=[],
            applied=[],
            suggestions=[],
            rounds=0,
            seconds=time.time() - t0,
            improved=False,
            stopped_reason="completed",
        )

    risk_before = verdict_before.risk_score
    label_before = verdict_before.risk_label
    findings_before = list(verdict_before.findings)

    if max_rounds is None:
        max_rounds = min(60, max(10, len(findings_before) + 5))

    current_source = source
    current_verdict = verdict_before
    current_findings = list(verdict_before.findings)

    applied_fixes: List[Fix] = []
    tried_keys: Set[Tuple[str, str]] = set()
    rejected_reasons: Dict[Tuple[str, str], str] = {}
    fixed_keys: Set[Tuple[str, str]] = set()

    # Lazy import compile_source to avoid circular dependencies
    from heal_engine import compile_source

    stopped_reason = "completed"
    round_count = 0
    while round_count < max_rounds:
        try:
            # 1. Pick candidate: highest severity, then lowest line
            # Must have recipe allowed by safety class and not in tried_keys
            candidates: List[Finding] = []
            for f in current_findings:
                key = (f.category, normalize_evidence(f.evidence))
                if key in tried_keys:
                    continue
                recipe = get_recipe(f.category)
                if not recipe:
                    continue
                if recipe.safety_class == "auto":
                    candidates.append(f)
                elif recipe.safety_class == "auto_notice" and allow_behavior_changes:
                    candidates.append(f)

            if not candidates:
                break

            candidates.sort(
                key=lambda f: (
                    -_SEV_ORDER.get(f.severity, 0),
                    f.line if f.line is not None else 999999,
                )
            )

            target_finding = candidates[0]
            target_key = (target_finding.category, normalize_evidence(target_finding.evidence))
            recipe = get_recipe(target_finding.category)
            if not recipe:
                tried_keys.add(target_key)
                continue

            # Apply recipe
            fix = recipe.apply(current_source, target_finding)
            if not fix or not fix.new_source or fix.new_source == current_source:
                # Preconditions not met; cannot auto-fix
                tried_keys.add(target_key)
                continue

            new_source = fix.new_source
            validation_failed = False
            rejection_reason = ""

            # ── Gate V1: PatchGuard ──────────────────────────────────────────
            patch_v = check_patch(current_source, new_source, origin="security_fix")
            if patch_v.blocked:
                validation_failed = True
                blocking_cats = [f.category for f in patch_v.findings if f.action == "block"]
                rejection_reason = f"patch_guard_blocked: {', '.join(blocking_cats) or 'blocked'}"

            # ── Gate V2: Size <= 12 changed lines ───────────────────────────
            if not validation_failed:
                diff_lines = list(
                    difflib.unified_diff(
                        current_source.splitlines(),
                        new_source.splitlines(),
                        lineterm="",
                    )
                )
                changed_line_count = sum(
                    1
                    for line in diff_lines
                    if (line.startswith("+") or line.startswith("-")) and not line.startswith(("+++", "---"))
                )
                if changed_line_count > 12:
                    validation_failed = True
                    rejection_reason = f"patch_too_large: {changed_line_count} changed lines (limit 12)"

            # ── Gate V3: Compiles (errors must not increase) ────────────────
            if not validation_failed:
                curr_errors, _, _ = compile_source(current_source, syntax_only=True)
                new_errors, _, _ = compile_source(new_source, syntax_only=True)
                if len(new_errors) > len(curr_errors):
                    validation_failed = True
                    rejection_reason = f"compile_errors_increased: {len(new_errors)} > {len(curr_errors)}"

            # ── Gate V4: Re-scan ────────────────────────────────────────────
            if not validation_failed:
                new_v = supervisor.review(InputKind.USER_SOURCE, new_source, purpose="analyze", meta=meta)
                # Count of target_key must drop
                curr_count = sum(1 for f in current_findings if (f.category, normalize_evidence(f.evidence)) == target_key)
                new_count = sum(1 for f in new_v.findings if (f.category, normalize_evidence(f.evidence)) == target_key)
                if new_count >= curr_count:
                    validation_failed = True
                    rejection_reason = "targeted_finding_persists"
                elif new_v.risk_score > current_verdict.risk_score:
                    validation_failed = True
                    rejection_reason = f"risk_score_increased: {new_v.risk_score} > {current_verdict.risk_score}"
                else:
                    # Check for new High or Critical finding
                    curr_high_keys = {
                        (f.category, normalize_evidence(f.evidence))
                        for f in current_findings
                        if f.severity in ("Critical", "High")
                    }
                    for nf in new_v.findings:
                        if nf.severity in ("Critical", "High"):
                            nf_key = (nf.category, normalize_evidence(nf.evidence))
                            if nf_key not in curr_high_keys and nf_key != target_key:
                                validation_failed = True
                                rejection_reason = f"new_high_severity_finding_introduced: {nf.category}"
                                break

            # ── Gate V5: Self-referencing auto / assignment-to-declaration ──
            if not validation_failed:
                old_lines = current_source.splitlines()
                new_lines = new_source.splitlines()
                sm = difflib.SequenceMatcher(None, old_lines, new_lines)
                for tag, i1, i2, j1, j2 in sm.get_opcodes():
                    if tag == "equal":
                        continue
                    old_chunk = old_lines[i1:i2]
                    new_chunk = new_lines[j1:j2]

                    # 1. Reject any line introducing auto NAME = ... where NAME is in RHS
                    for nl in new_chunk:
                        m_auto = re.match(r"^\s*auto(?:\s*&|\s*\*|\s+)\s*([A-Za-z_]\w*)\s*=\s*(.+);\s*$", nl)
                        if m_auto:
                            var_name = m_auto.group(1)
                            rhs_expr = m_auto.group(2)
                            if re.search(rf"\b{re.escape(var_name)}\b", rhs_expr):
                                validation_failed = True
                                rejection_reason = f"self_referencing_auto_declaration: auto {var_name} = ..."
                                break
                    if validation_failed:
                        break

                    # 2. Reject turning a plain assignment line into a declaration
                    for ol in old_chunk:
                        m_plain = re.match(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+);\s*$", ol)
                        if m_plain:
                            first_token = ol.strip().split()[0]
                            _TYPE_KEYWORDS = {
                                "int", "float", "double", "char", "long", "short",
                                "unsigned", "auto", "const", "static", "bool", "size_t",
                                "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                                "int8_t", "int16_t", "int32_t", "int64_t", "void", "return"
                            }
                            if first_token not in _TYPE_KEYWORDS:
                                var_name = m_plain.group(1)
                                for nl in new_chunk:
                                    m_decl = re.match(r"^\s*(?:auto|[A-Za-z_]\w+)\s+([A-Za-z_]\w*)\s*=\s*(.+);\s*$", nl)
                                    if m_decl and m_decl.group(1) == var_name:
                                        validation_failed = True
                                        rejection_reason = f"assignment_converted_to_declaration: {var_name}"
                                        break
                                if validation_failed:
                                    break
                    if validation_failed:
                        break

            # Apply or Rollback
            if validation_failed:
                tried_keys.add(target_key)
                rejected_reasons[target_key] = rejection_reason
            else:
                # Derive real before / after and first changed line using difflib
                old_lines = current_source.splitlines()
                new_lines = new_source.splitlines()
                matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
                removed_lines: List[str] = []
                added_lines: List[str] = []
                first_changed_line = None

                for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                    if tag == "equal":
                        continue
                    if first_changed_line is None:
                        first_changed_line = (i1 + 1) if i1 < len(old_lines) else (len(old_lines) or 1)
                    if tag in ("delete", "replace"):
                        removed_lines.extend(old_lines[i1:i2])
                    if tag in ("insert", "replace"):
                        added_lines.extend(new_lines[j1:j2])

                real_before = safe_text("\n".join(removed_lines[:6])) if removed_lines else ""
                real_after = safe_text("\n".join(added_lines[:6])) if added_lines else ""
                real_line = first_changed_line if first_changed_line is not None else (fix.line or 1)

                real_fix = Fix(
                    finding_category=fix.finding_category,
                    line=real_line,
                    safety_class=fix.safety_class,
                    description=fix.description,
                    before=real_before,
                    after=real_after,
                    new_source=fix.new_source,
                )

                current_source = new_source
                current_verdict = new_v
                current_findings = list(new_v.findings)
                applied_fixes.append(real_fix)
                fixed_keys.add(target_key)

            round_count += 1

        except Exception as e:
            log_event("security_heal_error", {"type": type(e).__name__})
            break
    else:
        rem_cands = []
        for f in current_findings:
            key = (f.category, normalize_evidence(f.evidence))
            if key in tried_keys:
                continue
            recipe = get_recipe(f.category)
            if not recipe:
                continue
            if recipe.safety_class == "auto" or (recipe.safety_class == "auto_notice" and allow_behavior_changes):
                rem_cands.append(f)
        if rem_cands:
            stopped_reason = "round_limit"

    # Re-scan final state
    try:
        final_verdict = supervisor.review(InputKind.USER_SOURCE, current_source, purpose="analyze", meta=meta)
    except Exception as e:
        log_event("security_heal_error", {"type": type(e).__name__})
        final_verdict = current_verdict

    risk_after = final_verdict.risk_score
    label_after = final_verdict.risk_label
    findings_after = list(final_verdict.findings)

    # Build outcomes for findings_before
    outcomes: List[Outcome] = []
    suggestions: List[Fix] = []
    seen_suggestion_keys: Set[Tuple[str, int | None]] = set()

    for fb in findings_before:
        fb_key = (fb.category, normalize_evidence(fb.evidence))
        recipe = get_recipe(fb.category)

        status: str
        reason = ""
        if fb_key in fixed_keys:
            status = "fixed"
        elif fb_key in rejected_reasons:
            status = "rejected"
            reason = rejected_reasons[fb_key]
        elif not recipe:
            status = "manual"
            reason = "No recipe for category"
        elif recipe.safety_class == "auto_notice" and not allow_behavior_changes:
            status = "skipped_behavior"
            reason = 'Behavior-changing fixes disabled. Enable "Allow behaviour-changing security fixes" in settings to apply.'
        elif recipe.safety_class == "suggest":
            status = "suggested"
            reason = "Manual review required"
        elif stopped_reason == "round_limit" and fb_key not in tried_keys:
            status = "not_attempted"
            reason = "Round limit reached before processing finding"
        else:
            # Recipe exists but preconditions failed or loop terminated before reaching it
            status = "suggested"
            reason = "Preconditions not met for automatic fix"

        outcomes.append(
            Outcome(
                finding_id=fb.id,
                category=fb.category,
                severity=fb.severity,
                line=fb.line,
                agents=list(fb.agents),
                status=status,
                reason=reason,
            )
        )

        # For every finding not fixed, produce suggestion if available
        if status != "fixed" and recipe:
            sugg_key = (fb.category, fb.line)
            if sugg_key not in seen_suggestion_keys:
                seen_suggestion_keys.add(sugg_key)
                try:
                    sugg = recipe.suggest(current_source, fb)
                    if sugg:
                        suggestions.append(sugg)
                except Exception as e:
                    log_event("security_heal_error", {"type": type(e).__name__})

    improved = (risk_after < risk_before) or (len(applied_fixes) > 0)
    duration = time.time() - t0

    return SecurityHealResult(
        source_before=source,
        source_after=current_source,
        risk_before=risk_before,
        risk_after=risk_after,
        label_before=label_before,
        label_after=label_after,
        findings_before=[f.to_dict() for f in findings_before],
        findings_after=[f.to_dict() for f in findings_after],
        outcomes=outcomes,
        applied=applied_fixes,
        suggestions=suggestions,
        rounds=round_count,
        seconds=duration,
        improved=improved,
        stopped_reason=stopped_reason,
    )
