"""
output_safe.py
--------------
Deterministic sanitizers for text displayed in terminals, GUI widgets,
and web interfaces. Total functions: accepts any input type, never raises.
"""

from __future__ import annotations

import html
import re
from typing import Any

from .secrets import mask_secrets

# CSI sequences (e.g. \x1b[31m) and OSC sequences (e.g. \x1b]0;title\x07)
_ANSI_CSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1B\](?:[^\x07\x1b]|\x1b(?!\x5c))*(?:\x07|\x1b\x5c)")
_ANSI_OTHER_RE = re.compile(r"\x1B[@-Z\\-_]")

# C0 control characters except \t (0x09) and \n (0x0A), plus DEL (0x7F)
# Note: \r (0x0D), \b (0x08), \x00, etc. are stripped
_C0_CONTROLS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Bidirectional controls: U+202A-U+202E, U+2066-U+2069, U+200E, U+200F
_BIDI_CONTROLS_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069\u200E\u200F]")

# Zero-width characters: U+200B-U+200D, U+2060, U+FEFF
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")


def safe_text(s: Any, limit: int | None = 2000) -> str:
    """
    Cleans raw text for safe terminal/GUI rendering:
    - Removes ANSI/terminal escape sequences (CSI and OSC)
    - Removes C0 control characters except \\n and \\t (strips \\r, \\b, etc.)
    - Removes bidirectional controls and zero-width characters
    - Caps output length at limit, appending '...' if truncated.

    Total function: never raises on None or non-strings.
    """
    if s is None:
        return ""
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            return ""

    # Mask secrets before any display rendering or stripping
    s = mask_secrets(s)

    # Remove ANSI escapes
    text = _ANSI_CSI_RE.sub("", s)
    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_OTHER_RE.sub("", text)

    # Remove C0 control characters (preserves \t and \n)
    text = _C0_CONTROLS_RE.sub("", text)

    # Remove bidirectional controls
    text = _BIDI_CONTROLS_RE.sub("", text)

    # Remove zero-width characters
    text = _ZERO_WIDTH_RE.sub("", text)

    # Cap length
    if limit is not None and limit >= 0 and len(text) > limit:
        text = text[:limit] + "..."

    return text


def html_text(s: Any, limit: int | None = 2000) -> str:
    """
    Returns HTML-escaped safe text suitable for embedding in rich labels / web pages.
    Quotes are escaped (quote=True). Total function: never raises.
    """
    return html.escape(safe_text(s, limit=limit), quote=True)
