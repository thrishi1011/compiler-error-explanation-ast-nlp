"""
diff_viewer.py
--------------
Generates a clean, structured line-by-line diff between two source strings.
Returns a list of DiffLine objects suitable for both terminal printing and
rich GUI rendering.
"""

import difflib
import html
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class DiffLine:
    line_no_old: Optional[int]   # line number in original  (None for additions)
    line_no_new: Optional[int]   # line number in patched   (None for deletions)
    kind: str                    # '+' | '-' | ' '
    content: str                 # raw text of the line (no newline)


from guard.output_safe import safe_text


def compute_diff(original: str, patched: str, context: int = 3) -> List[DiffLine]:
    """
    Compare two source strings and return a list of DiffLine objects.
    Lines with no changes are included only within `context` lines of a change.
    """
    orig_lines = original.splitlines()
    new_lines  = patched.splitlines()

    result: List[DiffLine] = []
    matcher = difflib.SequenceMatcher(None, orig_lines, new_lines, autojunk=False)

    for group in matcher.get_grouped_opcodes(context):
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for k, (o, n) in enumerate(zip(orig_lines[i1:i2], new_lines[j1:j2])):
                    result.append(DiffLine(i1 + k + 1, j1 + k + 1, " ", o))

            elif tag in ("replace", "delete"):
                for k, line in enumerate(orig_lines[i1:i2]):
                    result.append(DiffLine(i1 + k + 1, None, "-", line))

            if tag in ("replace", "insert"):
                for k, line in enumerate(new_lines[j1:j2]):
                    result.append(DiffLine(None, j1 + k + 1, "+", line))

    return result


def format_diff_text(diff: List[DiffLine]) -> str:
    """
    Plain-text representation of the diff, suitable for the terminal pane.
    Example:
        Line  3  -  cout << "Hello";
        Line  3  +  std::cout << "Hello";
    """
    lines = []
    for d in diff:
        if d.kind == "-":
            label = f"Line {d.line_no_old:>4}"
        elif d.kind == "+":
            label = f"Line {d.line_no_new:>4}"
        else:
            label = f"Line {d.line_no_new:>4}"
        lines.append(f"  {label}  {d.kind}  {d.content}")
    return "\n".join(lines)


def format_diff_html(diff: List[DiffLine],
                     font_family: str = "JetBrains Mono",
                     color_add: str = "#34d399",
                     color_del: str = "#f87171",
                     color_ctx: str = "#94a3b8",
                     color_line_num: str = "#64748b") -> str:
    """
    HTML representation of the diff for embedding in a QTextEdit / QLabel.
    """
    rows = []
    for d in diff:
        if d.kind == "-":
            color = color_del
            line_label = str(d.line_no_old)
            prefix = "−"
        elif d.kind == "+":
            color = color_add
            line_label = str(d.line_no_new)
            prefix = "+"
        else:
            color = color_ctx
            line_label = str(d.line_no_new)
            prefix = " "

        safe_content = (
            safe_text(d.content)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
            .replace(" ", "&nbsp;")
        )

        row = (
            f"<span style='color:{color}; font-family:{font_family}; font-size:12px;'>"
            f"<b>{prefix}</b>&nbsp;"
            f"<span style='color:{color_line_num}; font-weight:bold;'>Line&nbsp;{line_label:>4}&nbsp;&nbsp;</span>"
            f"<span style='color:{color};'>{safe_content}</span>"
            f"</span><br>"
        )
        rows.append(row)

    return "".join(rows)


def has_changes(diff: List[DiffLine]) -> bool:
    """Return True if the diff contains any additions or deletions."""
    return any(d.kind in ("+", "-") for d in diff)


def infer_line_rationale(
    new_line: Optional[str],
    old_line: Optional[str] = None,
    optimizations: Optional[List[str]] = None
) -> Optional[str]:
    """
    Infers a brief, user-understandable explanation comment for why a C++ code line
    was added, modified, or removed during optimization.
    """
    nl = new_line.strip() if new_line else ""
    ol = old_line.strip() if old_line else ""

    # Ignore standalone structural braces/keywords
    if nl in ("}", "};", "{", "} else {", "else {", "else", "try {", "} catch(...) {"):
        return None

    # Check against explicit optimizations provided by the AI/engine
    if optimizations:
        for opt in optimizations:
            opt_clean = str(opt).strip()
            if "const ref" in opt_clean.lower() and ("const " in nl and "&" in nl):
                return "Why: Passed parameter by const reference to eliminate deep copy overhead."
            if "unordered_map" in opt_clean.lower() and "unordered_map" in nl:
                return "Why: Uses unordered_map for O(1) key lookups instead of sequential searching."
            if "unordered_set" in opt_clean.lower() and "unordered_set" in nl:
                return "Why: Uses unordered_set for O(1) presence checks and fast deduplication."

    # 1. Header inclusions
    if re.search(r'#include\s*<unordered_(?:set|map)>', nl):
        return "Why: Added hash container library for O(1) average lookup time."
    if re.search(r'#include\s*<algorithm>', nl):
        return "Why: Added standard algorithms library for optimized STL operations."
    if re.search(r'#include\s*<vector>', nl):
        return "Why: Included vector container for dynamic array operations."
    if re.search(r'#include\s*<string>', nl):
        return "Why: Included string library for text operations."
    if re.search(r'#include\s*<(?:chrono|numeric|cmath)>', nl):
        return "Why: Added standard header for optimized mathematical/timing functions."
    if nl.startswith("#include"):
        return "Why: Added required library header."

    # 2. Loop refactoring (check before parameter refactoring!)
    if "for (" in nl or "for(" in nl or "while (" in nl or "while(" in nl:
        if "const auto&" in nl or "const auto &" in nl or "auto&" in nl or ":" in nl:
            return "Why: Used range-based loop with const reference for faster, cleaner iteration."
        return "Why: Refactored loop structure for better iteration efficiency."

    # 3. Parameter passing / function signatures (const &)
    if "(" in nl and (")" in nl or "{" in nl) and ("const " in nl or "&" in nl):
        if any(t in nl for t in ["vector", "string", "map", "set", "deque", "auto"]):
            return "Why: Passed parameter by const reference to avoid expensive deep copies."
        return "Why: Passed by reference to avoid copy overhead."

    # 4. Hash set / map declaration
    if re.search(r'unordered_(?:set|map)\s*<', nl):
        return "Why: Created hash table for instant O(1) lookup and duplicate tracking."

    # 5. Early guard clause / continue / return
    if re.search(r'if\s*\([^)]*\)\s*(?:continue|return|break);?', nl) or (".empty()" in nl and ("continue" in nl or "return" in nl)):
        return "Why: Added early guard condition to skip unnecessary processing."

    # 6. Container lookup & insert
    if any(m in nl for m in [".find(", "->find(", ".count(", "->count(", ".contains("]):
        return "Why: Uses O(1) hash lookup to quickly check if element exists."
    if any(m in nl for m in [".insert(", "->insert("]):
        return "Why: Records element in hash container in O(1) time."

    # 7. Fast I/O
    if ("'\\n'" in nl or '"\\n"' in nl) and ol and "endl" in ol:
        return "Why: Replaced std::endl with '\\n' to prevent costly buffer flushes."
    if "sync_with_stdio" in nl or "cin.tie" in nl:
        return "Why: Accelerated standard I/O streams for fast console input/output."

    # 8. Memory & reallocation
    if ".reserve(" in nl:
        return "Why: Pre-allocated memory capacity to prevent repeated dynamic reallocations."
    if "emplace_back" in nl or "emplace(" in nl:
        return "Why: Constructs element in-place to eliminate copy/move overhead."
    if "std::move" in nl:
        return "Why: Transferred resource ownership via move semantics to avoid copying."

    # 9. Dynamic Programming / Caching
    if any(kw in nl for kw in ["memo[", "memo.", "dp[", "cache["]):
        return "Why: Cached result in lookup table to avoid redundant recalculation."

    # 10. Security
    if ol and "strcpy" in ol and "strcpy" not in nl:
        return "Why: Replaced unsafe strcpy with bounds-checked alternative to prevent buffer overflow."
    if ol and "gets(" in ol and "gets(" not in nl:
        return "Why: Replaced dangerous gets() with safe bounded input handling."
    if ol and "sprintf" in ol and ("snprintf" in nl or "string" in nl):
        return "Why: Replaced sprintf with snprintf to enforce buffer limits."

    # 11. Output statement updates
    if ("cout" in nl or "printf" in nl) and ol and ("cout" in ol or "printf" in ol):
        return "Why: Updated output statement to print matching elements directly."

    # 12. General conditionals
    if nl.startswith("if (") or nl.startswith("if("):
        return "Why: Added conditional check to handle condition efficiently."

    # 13. Deletion (when old_line existed but new_line is empty)
    if ol and not nl:
        if "for (" in ol or "for(" in ol:
            return "Why: Removed redundant loop to eliminate quadratic O(n²) bottleneck."
        if "endl" in ol:
            return "Why: Removed slow buffer-flushing std::endl."
        return "Why: Removed redundant or inefficient statement."

    if ol:
        return "Why: Refactored line for higher execution performance."
    return "Why: Added logic to improve execution efficiency."


def format_annotated_diff_html(
    original: str,
    patched: str,
    optimizations: Optional[List[str]] = None,
    expanded: bool = False,
    context: int = 3
) -> str:
    """
    Renders an HTML-formatted diff view with line-by-line brief explanatory comments
    (e.g., // Why: ...) so the user can easily understand the rationale for every change.
    """
    if not original or not patched or original.strip() == patched.strip():
        return (
            "<div style='font-family: Consolas, monospace; font-size: 11px; padding: 12px; color: #94a3b8; background-color: #0d1117; border-radius: 6px;'>"
            "✓ Code is identical. No differences to display."
            "</div>"
        )

    orig_lines = original.splitlines()
    new_lines = patched.splitlines()

    matcher = difflib.SequenceMatcher(None, orig_lines, new_lines, autojunk=False)
    html_lines = [
        "<div style='font-family: Consolas, \"JetBrains Mono\", monospace; font-size: 11px; line-height: 1.45; background-color: #0d1117; padding: 8px; border-radius: 6px;'>"
    ]

    if expanded:
        html_lines.append(
            "<div style='background-color: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 6px; padding: 7px 10px; margin-bottom: 8px; color: #bae6fd; font-size: 11px;'>"
            "<b>Line-by-Line Optimization Rationale:</b> Brief comments explain why each change was made so you can understand the edits."
            "</div>"
        )

    for group in matcher.get_grouped_opcodes(context):
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for k, (o, n) in enumerate(zip(orig_lines[i1:i2], new_lines[j1:j2])):
                    escaped = html.escape(o) if o else "&nbsp;"
                    num = str(j1 + k + 1)
                    html_lines.append(
                        f"<div style='background-color: transparent; color: #8b949e; padding: 1px 4px; margin: 1px 0; border-radius: 2px; white-space: pre;'>"
                        f"<span style='color: #484f58; font-size: 10px;'>{num:>3} </span>"
                        f"<b>  </b>{escaped}"
                        f"</div>"
                    )
            elif tag == "delete":
                for k, line in enumerate(orig_lines[i1:i2]):
                    escaped = html.escape(line) if line else "&nbsp;"
                    num = str(i1 + k + 1)
                    html_lines.append(
                        f"<div style='background-color: rgba(248, 81, 73, 0.22); color: #f85149; padding: 1px 4px; margin: 1px 0; border-radius: 2px; white-space: pre;'>"
                        f"<span style='color: #484f58; font-size: 10px;'>{num:>3} </span>"
                        f"<b>- </b>{escaped}"
                        f"</div>"
                    )
                    r = infer_line_rationale(None, line, optimizations)
                    if r:
                        html_lines.append(
                            f"<div style='color: #38bdf8; font-style: italic; font-size: 10.5px; margin: 1px 0 3px 26px; padding: 2px 8px; background-color: rgba(56, 189, 248, 0.08); border-left: 2px solid #38bdf8; border-radius: 3px; white-space: normal;'>"
                            f"// {html.escape(r)}"
                            f"</div>"
                        )
            elif tag == "insert":
                for k, line in enumerate(new_lines[j1:j2]):
                    escaped = html.escape(line) if line else "&nbsp;"
                    num = str(j1 + k + 1)
                    html_lines.append(
                        f"<div style='background-color: rgba(46, 160, 67, 0.22); color: #3fb950; padding: 1px 4px; margin: 1px 0; border-radius: 2px; white-space: pre;'>"
                        f"<span style='color: #484f58; font-size: 10px;'>{num:>3} </span>"
                        f"<b>+ </b>{escaped}"
                        f"</div>"
                    )
                    r = infer_line_rationale(line, None, optimizations)
                    if r:
                        html_lines.append(
                            f"<div style='color: #38bdf8; font-style: italic; font-size: 10.5px; margin: 1px 0 3px 26px; padding: 2px 8px; background-color: rgba(56, 189, 248, 0.08); border-left: 2px solid #38bdf8; border-radius: 3px; white-space: normal;'>"
                            f"// {html.escape(r)}"
                            f"</div>"
                        )
            elif tag == "replace":
                old_chunk = orig_lines[i1:i2]
                new_chunk = new_lines[j1:j2]
                for k, line in enumerate(old_chunk):
                    escaped = html.escape(line) if line else "&nbsp;"
                    num = str(i1 + k + 1)
                    html_lines.append(
                        f"<div style='background-color: rgba(248, 81, 73, 0.22); color: #f85149; padding: 1px 4px; margin: 1px 0; border-radius: 2px; white-space: pre;'>"
                        f"<span style='color: #484f58; font-size: 10px;'>{num:>3} </span>"
                        f"<b>- </b>{escaped}"
                        f"</div>"
                    )
                for k, line in enumerate(new_chunk):
                    escaped = html.escape(line) if line else "&nbsp;"
                    num = str(j1 + k + 1)
                    html_lines.append(
                        f"<div style='background-color: rgba(46, 160, 67, 0.22); color: #3fb950; padding: 1px 4px; margin: 1px 0; border-radius: 2px; white-space: pre;'>"
                        f"<span style='color: #484f58; font-size: 10px;'>{num:>3} </span>"
                        f"<b>+ </b>{escaped}"
                        f"</div>"
                    )
                    old_corresp = old_chunk[k] if k < len(old_chunk) else (old_chunk[0] if old_chunk else None)
                    r = infer_line_rationale(line, old_corresp, optimizations)
                    if r:
                        html_lines.append(
                            f"<div style='color: #38bdf8; font-style: italic; font-size: 10.5px; margin: 1px 0 3px 26px; padding: 2px 8px; background-color: rgba(56, 189, 248, 0.08); border-left: 2px solid #38bdf8; border-radius: 3px; white-space: normal;'>"
                            f"// {html.escape(r)}"
                            f"</div>"
                        )

    html_lines.append("</div>")
    return "\n".join(html_lines)
