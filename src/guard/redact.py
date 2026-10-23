from __future__ import annotations

import re

from .secrets import mask_secrets

# Match well-known API key formats
_API_KEY_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"gsk_[0-9A-Za-z_\-]{20,}"),
    re.compile(r"sk-[0-9A-Za-z_\-]{20,}"),
    re.compile(r"ghp_[0-9A-Za-z]{20,}"),
]

# Match KEY=value style assignments (e.g. GEMINI_API_KEY=..., SECRET="...", token='...')
_KEY_VALUE_PATTERN = re.compile(
    r'(?i)\b([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Za-z0-9_]*\s*=\s*)(["\']?)(?:(?!\2)[^\s,;])+\2'
)

# Control characters (ASCII 0-31 and 127-159)
_CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def redact(text: str | None, limit: int = 80) -> str:
    """
    Sanitizes evidence text by:
    - Masking KEY=value assignments and known API key patterns
    - Removing control characters (replacing with single space)
    - Capping length to limit characters
    """
    if not text:
        return ""

    s = mask_secrets(str(text))

    # 1. Mask KEY=value assignments
    s = _KEY_VALUE_PATTERN.sub(r"\1\2[REDACTED]\2", s)

    # 2. Mask known API key formats
    for pattern in _API_KEY_PATTERNS:
        s = pattern.sub("[REDACTED_KEY]", s)

    # 3. Remove control characters and normalize whitespace
    s = _CONTROL_CHARS_PATTERN.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()

    # 4. Cap length
    if len(s) > limit:
        s = s[:limit]

    return s
