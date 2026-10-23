"""
ui_text.py
----------
Pure UI text and HTML formatting helpers.
Extracts compiler diagnostic messages and formats them into safe HTML
for rendering in desktop rich-text widgets.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from guard.output_safe import html_text


DEFAULT_COLORS = {
    "red": "#ef4444",
    "yellow": "#f59e0b",
    "text_main": "#f1f5f9",
    "text_dim": "#94a3b8",
}


def build_compiler_html(
    errors: List[Dict[str, Any]],
    file_name: str = "",
    colors: Optional[Dict[str, str]] = None,
) -> str:
    """
    Build safe HTML representation of compiler diagnostics for rich-text display.
    Ensures that every dynamic value (file name, error type, line, column,
    message text, context source lines) is sanitized via html_text.
    """
    if colors is None:
        c = DEFAULT_COLORS
    else:
        c = {**DEFAULT_COLORS, **colors}

    red = c.get("red", DEFAULT_COLORS["red"])
    yellow = c.get("yellow", DEFAULT_COLORS["yellow"])
    text_main = c.get("text_main", DEFAULT_COLORS["text_main"])
    text_dim = c.get("text_dim", DEFAULT_COLORS["text_dim"])

    parts: List[str] = []

    for e in errors:
        raw_type = (e.get("type") or e.get("error_type") or "error")
        etype_str = str(raw_type).lower()
        is_error = "error" in etype_str
        tag_color = red if is_error else yellow

        etype_safe = html_text(etype_str)
        raw_file = e.get("file") or file_name or "source.cpp"
        fname_safe = html_text(os.path.basename(str(raw_file)))

        raw_line = e.get("line", "?")
        raw_col = e.get("column", "?")
        line_safe = html_text(str(raw_line))
        col_safe = html_text(str(raw_col))

        msg_safe = html_text(e.get("message", ""))

        header = (
            f"<span style='color:{tag_color}; font-weight:bold;'>[{etype_safe.upper()}]</span> "
            f"{fname_safe}:{line_safe}:{col_safe}: "
            f"<span style='color:{tag_color};'>{etype_safe}:</span> {msg_safe}<br>"
        )
        parts.append(header)

        context = e.get("context", {})
        if isinstance(context, dict):
            lines = context.get("lines", [])
            start = context.get("start_line", 1)
            if lines and isinstance(lines, list):
                for i, lt in enumerate(lines, start=start):
                    txt_safe = html_text(str(lt).rstrip("\r\n"))
                    if str(i) == str(raw_line):
                        parts.append(
                            f" <span style='color:{tag_color}; font-weight:bold;'>&gt;</span> "
                            f"{i:3} | <b style='color:{text_main}'>{txt_safe}</b><br>"
                        )
                        if raw_col != "?":
                            try:
                                c_int = int(raw_col)
                                indent = " " * (len(str(i)) + 2 + c_int)
                                parts.append(
                                    f"       {indent}<span style='color:{tag_color}; font-weight:bold;'>^</span><br>"
                                )
                            except Exception:
                                pass
                    else:
                        parts.append(
                            f"   {i:3} | <span style='color:{text_dim}'>{txt_safe}</span><br>"
                        )

        parts.append("<br>")

    parts.append(f"<span style='color:{text_dim};'>C++_ANALYZER_V2.0.1_READY &gt; _</span>")
    return "".join(parts)
