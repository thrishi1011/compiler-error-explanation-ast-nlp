"""
secrets.py
----------
Pure functions for detecting, scanning, and masking sensitive credentials,
API keys, tokens, and environment secrets.
Standard library only, deterministic, no LLM, no external dependencies.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, List


_EXACT_SENSITIVE_NAMES = {
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "HF_TOKEN",
    "GITHUB_TOKEN",
}

_SUBSTRING_SENSITIVE_NAMES = (
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
)


@dataclass
class SecretHit:
    kind: str
    start: int
    end: int
    severity: str  # "Critical" | "High" | "Medium" | "Low"


def is_sensitive_name(name: Any) -> bool:
    """
    Returns True if an environment variable or identifier name is sensitive:
    - Contains (case-insensitive): KEY, TOKEN, SECRET, PASSWORD, PASSWD, CREDENTIAL
    - Equals: GEMINI_API_KEY, GROQ_API_KEY, HF_TOKEN, GITHUB_TOKEN
    - Starts with: AWS_
    """
    if not isinstance(name, str):
        return False
    upper = name.upper()
    if upper in _EXACT_SENSITIVE_NAMES:
        return True
    if any(term in upper for term in _SUBSTRING_SENSITIVE_NAMES):
        return True
    if upper.startswith("AWS_"):
        return True
    return False


def env_secret_values(min_len: int = 8) -> List[str]:
    """
    Returns current values of sensitive environment variables with at least min_len chars.
    Reads os.environ dynamically on every call; never caches across calls.
    """
    secrets: List[str] = []
    for k, v in os.environ.items():
        if is_sensitive_name(k) and isinstance(v, str) and len(v) >= min_len:
            secrets.append(v)
    # Deduplicate while preserving order, longest first for greedier matching
    unique_secrets = list(dict.fromkeys(secrets))
    unique_secrets.sort(key=len, reverse=True)
    return unique_secrets


# Regex patterns for well-known secrets (linear-time, no nested quantifiers)
_PATTERN_SPECS = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "High"),
    ("groq_api_key", re.compile(r"gsk_[0-9A-Za-z_\-]{20,}"), "High"),
    ("openai_api_key", re.compile(r"sk-[0-9A-Za-z_\-]{20,}"), "High"),
    ("github_token", re.compile(r"ghp_[0-9A-Za-z]{20,}"), "High"),
    ("github_pat", re.compile(r"github_pat_[0-9A-Za-z_]{20,}"), "High"),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "High"),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "High"),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "High"),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "High"),
    (
        "credential_assignment",
        re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']"),
        "Medium",
    ),
]


def scan_secrets(text: Any) -> List[SecretHit]:
    """
    Scans text for secrets and returns a list of SecretHit objects.
    Finds regex patterns and exact matches of environment sensitive values.
    """
    if text is None or not isinstance(text, str):
        return []

    hits: List[SecretHit] = []

    # 1. Exact matches from environment secrets (Critical)
    for sec_val in env_secret_values(min_len=8):
        start_idx = 0
        while True:
            idx = text.find(sec_val, start_idx)
            if idx == -1:
                break
            hits.append(SecretHit(
                kind="tool_secret",
                start=idx,
                end=idx + len(sec_val),
                severity="Critical",
            ))
            start_idx = idx + len(sec_val)

    # 2. Pattern matches (High / Medium)
    for kind, pattern, severity in _PATTERN_SPECS:
        for match in pattern.finditer(text):
            hits.append(SecretHit(
                kind=kind,
                start=match.start(),
                end=match.end(),
                severity=severity,
            ))

    # Sort hits by start ascending, then length descending
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    return hits


def mask_secrets(text: Any) -> str:
    """
    Replaces every secret hit with [REDACTED:<kind>].
    Never includes any part of the secret, nor its length.
    Total function: accepts None or non-strings, never raises.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return ""

    hits = scan_secrets(text)
    if not hits:
        return text

    # Filter out overlapping hits (first/longest wins)
    non_overlapping: List[SecretHit] = []
    last_end = -1
    for h in hits:
        if h.start >= last_end:
            non_overlapping.append(h)
            last_end = h.end
        elif h.kind == "tool_secret" and non_overlapping and non_overlapping[-1].kind != "tool_secret":
            # Prefer tool_secret over credential assignment
            non_overlapping.pop()
            non_overlapping.append(h)
            last_end = h.end

    # Replace from back to front so indices remain valid
    result = text
    for h in reversed(non_overlapping):
        result = result[:h.start] + f"[REDACTED:{h.kind}]" + result[h.end:]

    return result
