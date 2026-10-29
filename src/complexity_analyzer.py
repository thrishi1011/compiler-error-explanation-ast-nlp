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
    time_hint: str          # e.g. "O(n²)", "O(n)", "O(1)", "Unknown"
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
    """Removes C/C++ style comments and string literals to prevent false regex matches."""
    # Remove block comments
    cleaned = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    # Remove line comments
    cleaned = re.sub(r"//.*$", " ", cleaned, flags=re.MULTILINE)
    # Remove string literals
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"', '""', cleaned)
    # Remove character literals
    cleaned = re.sub(r"'(?:\\.|[^'\\])*'", "''", cleaned)
    return cleaned


def _analyze_loop_nesting(lines: List[str]) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Approximates maximum loop nesting depth and records loop locations.
    Returns (max_depth, signals).
    """
    signals: List[Dict[str, Any]] = []
    max_depth = 0
    current_depth = 0
    loop_brace_stacks: List[int] = []
    brace_depth = 0

    for idx, raw_line in enumerate(lines, start=1):
        line = _strip_comments_and_strings(raw_line)
        has_loop = bool(re.search(r"\b(for|while)\s*\(", line))
        opens = line.count("{")
        closes = line.count("}")

        if has_loop:
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
            
            note = f"Loop statement (nesting depth {current_depth})"
            signals.append({
                "line": idx,
                "pattern": "loop",
                "depth": current_depth,
                "note": note
            })
            loop_brace_stacks.append(brace_depth + opens)

        brace_depth += (opens - closes)
        
        while loop_brace_stacks and brace_depth < loop_brace_stacks[-1]:
            loop_brace_stacks.pop()
            current_depth = max(0, current_depth - 1)

    return max_depth, signals


def _detect_recursion(lines: List[str], cleaned_source: str) -> List[Dict[str, Any]]:
    """Identifies self-calling functions which could indicate O(2^n) or O(log n)."""
    signals = []
    func_defs = re.findall(
        r"\b([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{",
        cleaned_source
    )
    for func_name in set(func_defs):
        if func_name in ("main", "if", "while", "for", "switch", "catch"):
            continue
        call_pattern = re.compile(rf"\b{func_name}\s*\(")
        for idx, line in enumerate(lines, start=1):
            stripped = _strip_comments_and_strings(line)
            if call_pattern.search(stripped) and not stripped.strip().endswith("{"):
                signals.append({
                    "line": idx,
                    "pattern": "recursion",
                    "note": f"Recursive call to '{func_name}' detected."
                })
    return signals


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

        # 2. Recursion detection
        rec_signals = _detect_recursion(lines, cleaned)
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

        if rec_signals:
            if max_loop_depth >= 1:
                time_hint = "O(2^n)"
            else:
                time_hint = "O(log n)"
            confidence = "Low"
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
            confidence = "Medium"
        elif has_map:
            time_hint = "O(log n)"
            confidence = "Low"
        else:
            time_hint = "O(1)"
            confidence = "High"

        # Determine Space Complexity Hint
        space_hint = "O(1)"
        if any(s.get("pattern") in ("pass_by_value", "large_allocation") for s in all_signals):
            space_hint = "O(n)"
        elif has_vector or rec_signals:
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
