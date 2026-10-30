"""
complexity_analyzer.py
----------------------
Static heuristic complexity scanner for C++ source code.
Runs locally and instantly without external API dependencies.
Produces preliminary time and space complexity estimates and flags algorithmic bottlenecks.
"""

from __future__ import annotations

import sys
import os
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class LocalComplexityEstimate:
    time_hint: str          # e.g. "O(n log n)", "O(n²)", "O(n)", "O(1)", "Unknown"
    space_hint: str         # e.g. "O(n)", "O(1)", "Unknown"
    signals: List[Dict[str, Any]] = field(default_factory=list)
    confidence: str = "Medium"  # "High" | "Medium" | "Low"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Common patterns for detection
_RE_FOR_LOOP = re.compile(r"\bfor\s*\([^;]*;[^;]*;[^)]*\)", re.MULTILINE)
_RE_WHILE_LOOP = re.compile(r"\bwhile\s*\([^)]+\)", re.MULTILINE)
_RE_STD_SORT = re.compile(r"\b(?:std::)?sort\s*\(", re.MULTILINE)
_RE_STD_MAP = re.compile(r"\b(?:std::)?(?:map|set|priority_queue)\b")
_RE_UNORDERED_MAP = re.compile(r"\b(?:std::)?(?:unordered_map|unordered_set)\b")
_RE_VECTOR_DECL = re.compile(r"\b(?:std::)?vector\s*<[^>]+>\s+([a-zA-Z_]\w*)")
_RE_PASS_BY_VALUE_CONTAINER = re.compile(
    r"\b(?:std::)?(?:vector|string|map|set|unordered_map|unordered_set)<[^>]+>\s+([a-zA-Z_]\w*)\s*[,)]"
)
_RE_LARGE_STATIC_ARRAY = re.compile(r"\b(?:int|double|float|char|long|size_t)\s+[a-zA-Z_]\w*\[\s*([0-9]+)\s*\]")


def _strip_comments_and_strings(source: str) -> str:
    """Removes C/C++ style comments and string literals safely and fast without regex backtracking."""
    out = []
    i = 0
    n = len(source)
    while i < n:
        if source[i] == '/' and i + 1 < n and source[i+1] == '/':
            i += 2
            while i < n and source[i] != '\n':
                i += 1
        elif source[i] == '/' and i + 1 < n and source[i+1] == '*':
            i += 2
            while i + 1 < n and not (source[i] == '*' and source[i+1] == '/'):
                if source[i] == '\n':
                    out.append('\n')
                i += 1
            i += 2
        elif source[i] == '"':
            out.append('""')
            i += 1
            while i < n and source[i] != '"':
                if source[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    if source[i] == '\n':
                        out.append('\n')
                    i += 1
            i += 1
        elif source[i] == "'":
            out.append("''")
            i += 1
            while i < n and source[i] != "'":
                if source[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


def _analyze_loop_nesting(lines: List[str]) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Computes maximum loop nesting depth and flags loop bottlenecks.
    Properly tracks block scopes so sequential loops never falsely compound depth.
    """
    signals: List[Dict[str, Any]] = []
    max_depth = 0

    loop_stack: List[int] = []
    current_brace = 0
    pending_loop = False

    for idx, raw_line in enumerate(lines, start=1):
        line = _strip_comments_and_strings(raw_line)
        has_loop = bool(re.search(r"\b(for|while)\s*\(", line))

        for ch in line:
            if ch == '{':
                current_brace += 1
                if pending_loop:
                    loop_stack.append(current_brace)
                    pending_loop = False
            elif ch == '}':
                while loop_stack and current_brace <= loop_stack[-1]:
                    loop_stack.pop()
                current_brace = max(0, current_brace - 1)

        if has_loop:
            if '{' in line:
                depth = len(loop_stack)
            else:
                if re.search(r"\b(for|while)\s*\([^)]*\)\s*[^;{]*;", line):
                    depth = len(loop_stack) + 1
                else:
                    pending_loop = True
                    depth = len(loop_stack) + 1

            if depth > max_depth:
                max_depth = depth

            signals.append({
                "line": idx,
                "pattern": "loop",
                "depth": depth,
                "note": f"Loop statement (nesting depth {depth})"
            })

    return max_depth, signals


def _detect_recursion(lines: List[str], cleaned_source: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Identifies genuine recursive functions by checking if a function calls itself
    within its own body. Classifies into Divide-and-Conquer, Tree/Graph DFS, or Exponential.
    """
    signals: List[Dict[str, Any]] = []
    rec_meta: Dict[str, Any] = {
        "has_exponential": False,
        "has_divide_and_conquer": False,
        "has_tree_traversal": False,
        "has_linear_recursion": False,
    }

    func_pattern = re.compile(r"\b([a-zA-Z_]\w*)\s*\([^;)]*\)\s*(?:const)?\s*\{", re.MULTILINE)
    for m in func_pattern.finditer(cleaned_source):
        func_name = m.group(1)
        if func_name in ("main", "if", "while", "for", "switch", "catch", "return", "sizeof"):
            continue

        start_brace = m.end() - 1
        brace_count = 1
        idx = start_brace + 1
        n = len(cleaned_source)
        while idx < n and brace_count > 0:
            ch = cleaned_source[idx]
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
            idx += 1

        if brace_count == 0:
            body = cleaned_source[start_brace + 1 : idx - 1]
            call_matches = list(re.finditer(rf"\b{re.escape(func_name)}\s*\(", body))
            if call_matches:
                line_no = cleaned_source[:m.start()].count('\n') + 1
                num_calls = len(call_matches)

                is_dnc = bool(re.search(r"/\s*2|\bmid\b|\bleft\b|\bright\b|>>\s*1|\bmerge\b|\bpartition\b", body, re.I))
                is_tree = bool(re.search(r"->\s*(?:left|right|children|next)|pair\.second|\bnode\b", body, re.I))

                if is_dnc:
                    rec_meta["has_divide_and_conquer"] = True
                    signals.append({
                        "line": line_no,
                        "pattern": "recursion",
                        "note": f"Divide-and-conquer recursion in '{func_name}' - typical O(n log n) or O(log n)."
                    })
                elif is_tree:
                    rec_meta["has_tree_traversal"] = True
                    signals.append({
                        "line": line_no,
                        "pattern": "recursion",
                        "note": f"Tree/Trie recursive traversal in '{func_name}' - O(N) over data elements."
                    })
                elif num_calls >= 2 and re.search(r"-\s*1|-\s*2", body):
                    rec_meta["has_exponential"] = True
                    signals.append({
                        "line": line_no,
                        "pattern": "recursion",
                        "note": f"Branching unmemoized recursion in '{func_name}' (potential O(2^n))."
                    })
                else:
                    rec_meta["has_linear_recursion"] = True
                    signals.append({
                        "line": line_no,
                        "pattern": "recursion",
                        "note": f"Recursive call inside '{func_name}'."
                    })

    return signals, rec_meta


def scan(source_code: str) -> LocalComplexityEstimate:
    """
    Scans C++ source code using fast heuristics.
    Never raises an exception.
    """
    if not source_code or not source_code.strip():
        return LocalComplexityEstimate(time_hint="O(1)", space_hint="O(1)", confidence="Low")

    try:
        lines = source_code.splitlines()
        cleaned = _strip_comments_and_strings(source_code)
        all_signals: List[Dict[str, Any]] = []

        # 1. Loop nesting analysis
        max_loop_depth, loop_signals = _analyze_loop_nesting(lines)
        all_signals.extend(loop_signals)

        # 2. Recursion detection with semantic classification
        rec_signals, rec_meta = _detect_recursion(lines, cleaned)
        all_signals.extend(rec_signals)

        # 3. STL Algorithms & Containers
        has_std_sort = bool(_RE_STD_SORT.search(cleaned))
        has_map = bool(_RE_STD_MAP.search(cleaned))
        has_vector = bool(_RE_VECTOR_DECL.search(cleaned))

        for idx, line in enumerate(lines, start=1):
            strp = _strip_comments_and_strings(line)
            if _RE_STD_SORT.search(strp):
                all_signals.append({
                    "line": idx,
                    "pattern": "std::sort",
                    "note": "std::sort call - typical complexity O(n log n)."
                })

            val_match = _RE_PASS_BY_VALUE_CONTAINER.search(strp)
            if val_match:
                all_signals.append({
                    "line": idx,
                    "pattern": "pass_by_value",
                    "note": f"Heavy container '{val_match.group(1)}' passed by value - creates redundant copy."
                })

            arr_match = _RE_LARGE_STATIC_ARRAY.search(strp)
            if arr_match:
                size_val = int(arr_match.group(1))
                if size_val >= 1000:
                    all_signals.append({
                        "line": idx,
                        "pattern": "large_allocation",
                        "note": f"Large fixed buffer ({size_val} elements) allocated on stack."
                    })

        # Determine Time Complexity Hint
        time_hint = "O(1)"
        confidence = "Medium"

        if rec_meta.get("has_exponential", False):
            time_hint = "O(2^n)"
            confidence = "High" if len(lines) < 150 else "Medium"
        elif rec_meta.get("has_divide_and_conquer", False):
            if max_loop_depth >= 2:
                time_hint = "O(n²)"
            else:
                time_hint = "O(n log n)"
            confidence = "High"
        elif rec_meta.get("has_tree_traversal", False):
            if max_loop_depth >= 2:
                time_hint = "O(n²)"
            elif has_std_sort:
                time_hint = "O(n log n)"
            else:
                time_hint = "O(n)"
            confidence = "Medium"
        elif max_loop_depth >= 3:
            time_hint = "O(n³)"
            confidence = "High"
        elif max_loop_depth == 2:
            time_hint = "O(n²)"
            confidence = "High"
        elif max_loop_depth == 1:
            if has_std_sort:
                time_hint = "O(n log n)"
            else:
                time_hint = "O(n)"
            confidence = "Medium"
        elif has_std_sort:
            time_hint = "O(n log n)"
            confidence = "High"
        elif has_map:
            time_hint = "O(log n)"
            confidence = "Medium"
        elif has_vector:
            time_hint = "O(n)"
            confidence = "Medium"
        else:
            time_hint = "O(1)"
            confidence = "High"

        # Determine Space Complexity Hint
        space_hint = "O(1)"
        if rec_meta.get("has_exponential", False) or rec_meta.get("has_divide_and_conquer", False) or rec_meta.get("has_tree_traversal", False):
            space_hint = "O(n)"
        elif any(s.get("pattern") in ("pass_by_value", "large_allocation") for s in all_signals):
            space_hint = "O(n)"
        elif has_vector or has_map:
            space_hint = "O(n)"
        else:
            space_hint = "O(1)"

        return LocalComplexityEstimate(
            time_hint=time_hint,
            space_hint=space_hint,
            signals=all_signals,
            confidence=confidence
        )

    except Exception as exc:
        return LocalComplexityEstimate(
            time_hint="Unknown",
            space_hint="Unknown",
            signals=[{"line": 0, "pattern": "error", "note": str(exc)}],
            confidence="Low"
        )
