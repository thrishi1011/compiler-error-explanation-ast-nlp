from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

try:
    from security_analyzer import _strip_code
except ImportError:
    _src = str(Path(__file__).resolve().parent.parent)
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from security_analyzer import _strip_code

_STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')


def strip_code(line: str, state: dict[str, Any]) -> str:
    """
    Strips single-line and multi-line comments and string literals from a C++ line.
    State carries across lines with keys 'in_block_comment' and 'raw_delim'.
    """
    return _strip_code(line, state)


def extract_string_literals(raw_line: str) -> list[str]:
    """Extracts all string literal contents from a raw C++ source line."""
    return _STRING_LITERAL_RE.findall(raw_line)


_RAW_STRING_START = re.compile(r'R"([a-zA-Z0-9_{}\[\]#<>%:;.?*+\-/^&|~!=,"\']{0,16})\(')


def classify_line_contexts(line: str, state: dict[str, Any]) -> list[str]:
    """
    Returns a list of context tags ('comment', 'string', or 'code') corresponding
    to each character position in the given C++ source line, updating parser state.
    """
    in_block_comment = bool(state.get("in_block_comment"))
    raw_delim = state.get("raw_delim")
    contexts: list[str] = []
    i = 0
    n = len(line)

    while i < n:
        if raw_delim is not None:
            raw_end = line.find(")" + str(raw_delim) + '"', i)
            if raw_end == -1:
                contexts.extend(["string"] * (n - i))
                state["raw_delim"] = raw_delim
                return contexts
            end_idx = raw_end + len(str(raw_delim)) + 2
            contexts.extend(["string"] * (end_idx - i))
            i = end_idx
            raw_delim = None
            continue

        if in_block_comment:
            comment_end = line.find("*/", i)
            if comment_end == -1:
                contexts.extend(["comment"] * (n - i))
                state["in_block_comment"] = True
                return contexts
            end_idx = comment_end + 2
            contexts.extend(["comment"] * (end_idx - i))
            i = end_idx
            in_block_comment = False
            continue

        if line.startswith("//", i):
            contexts.extend(["comment"] * (n - i))
            break

        if line.startswith("/*", i):
            in_block_comment = True
            contexts.extend(["comment", "comment"])
            i += 2
            continue

        raw_match = _RAW_STRING_START.match(line, i)
        if raw_match:
            raw_delim = raw_match.group(1)
            match_len = raw_match.end() - i
            contexts.extend(["string"] * match_len)
            i = raw_match.end()
            continue

        ch = line[i]
        if ch in ("'", '"'):
            quote = ch
            start_q = i
            i += 1
            while i < n:
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            contexts.extend(["string"] * (i - start_q))
            continue

        contexts.append("code")
        i += 1

    state["in_block_comment"] = in_block_comment
    state["raw_delim"] = raw_delim
    return contexts

