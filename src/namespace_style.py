"""
namespace_style.py
------------------
Detects and enforces C++ std namespace styling:
- If the original code uses 'using namespace std;', maintains 'using namespace std;' and un-prefixes std::.
- If the original code does NOT use 'using namespace std;', strips any injected 'using namespace std;' and ensures standard symbols use 'std::'.
"""

from __future__ import annotations
import re
from typing import List

STD_SYMBOLS: List[str] = [
    "vector", "string", "unordered_map", "unordered_set", "map", "set",
    "pair", "make_pair", "queue", "stack", "deque", "list", "array",
    "cout", "cin", "cerr", "endl", "min", "max", "swap", "sort",
    "size_t", "nullptr_t"
]


def uses_namespace_std(code: str) -> bool:
    """Returns True if the C++ code contains 'using namespace std;'."""
    if not code:
        return False
    return bool(re.search(r'\busing\s+namespace\s+std\s*;', code))


def enforce_std_namespace_style(code: str, target_has_using_std: bool) -> str:
    """
    Enforces the target std namespace convention across the C++ source code.
    - target_has_using_std=True: Ensures 'using namespace std;' exists and standard library symbols are clean.
    - target_has_using_std=False: Ensures 'using namespace std;' is removed and standard symbols use 'std::'.
    Preserves #include headers, comments, and strings intact.
    """
    if not code or not code.strip():
        return code

    current_has_using_std = uses_namespace_std(code)
    lines = code.splitlines(keepends=True)
    new_lines = []

    if target_has_using_std:
        # 1. Ensure 'using namespace std;' exists
        if not current_has_using_std:
            last_inc = -1
            for i, l in enumerate(lines):
                if l.strip().startswith("#include"):
                    last_inc = i
            insert_pos = last_inc + 1 if last_inc >= 0 else 0
            lines.insert(insert_pos, "using namespace std;\n")

        # 2. Strip redundant std:: prefix on code lines (skip includes and comments)
        strip_pattern = r'(?<!::)\bstd::(' + '|'.join(STD_SYMBOLS) + r')\b'
        for l in lines:
            stripped = l.strip()
            if stripped.startswith("#include") or stripped.startswith("//"):
                new_lines.append(l)
                continue
            if "//" in l:
                code_part, comment_part = l.split("//", 1)
                fixed_code = re.sub(strip_pattern, r'\1', code_part)
                new_lines.append(fixed_code + "//" + comment_part)
            else:
                new_lines.append(re.sub(strip_pattern, r'\1', l))
        return "".join(new_lines)
    else:
        # 1. Remove 'using namespace std;' lines
        lines = [l for l in lines if not re.match(r'^\s*using\s+namespace\s+std\s*;\s*$', l)]

        # 2. Add std:: prefix to standard library symbols on code lines
        add_pattern = r'(?<!::)(?<![\w\.\>])\b(' + '|'.join(STD_SYMBOLS) + r')\b'
        for l in lines:
            stripped = l.strip()
            if stripped.startswith("#include") or stripped.startswith("//"):
                new_lines.append(l)
                continue
            if "//" in l:
                code_part, comment_part = l.split("//", 1)
                fixed_code = re.sub(add_pattern, r'std::\1', code_part)
                new_lines.append(fixed_code + "//" + comment_part)
            else:
                new_lines.append(re.sub(add_pattern, r'std::\1', l))
        return "".join(new_lines)
