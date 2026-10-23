from __future__ import annotations

import os

from .secrets import is_sensitive_name


def scrubbed_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """
    Returns a copy of the environment (or base dict) without sensitive credentials.
    Uses is_sensitive_name to filter variables.
    """
    source = os.environ if base is None else base
    cleaned: dict[str, str] = {}

    for k, v in source.items():
        if is_sensitive_name(k):
            continue
        cleaned[k] = v

    return cleaned
