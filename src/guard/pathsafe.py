"""
pathsafe.py
-----------
Path validation utilities to prevent unauthorized file reads, path traversal,
and sensitive file leakage (e.g. .env, ssh keys, credentials).
Standard library only, deterministic, safe for Windows and Linux.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any, List, Optional


SENSITIVE_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    ".ssh",
    ".aws",
    ".gnupg",
    "credentials*",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "shadow",
    "passwd",
    "known_hosts",
]


_ALLOWED_ROOTS: List[Path] = [Path.cwd().resolve()]


def set_allowed_roots(roots: List[str | Path]) -> None:
    """
    Sets the allowed root directories for safe file reads.
    Resolves each path to canonical form.
    """
    global _ALLOWED_ROOTS
    new_roots: List[Path] = []
    for r in roots:
        try:
            if r:
                new_roots.append(Path(r).resolve())
        except Exception:
            pass
    _ALLOWED_ROOTS = new_roots if new_roots else [Path.cwd().resolve()]


def get_allowed_roots() -> List[Path]:
    """Returns a copy of the currently registered allowed root directories."""
    return list(_ALLOWED_ROOTS)


def is_sensitive_path_component(name: str) -> bool:
    """Returns True if a filename or path component matches the sensitive list."""
    if not isinstance(name, str):
        return False
    name_clean = name.strip()
    name_lower = name_clean.lower()
    for pat in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(name_lower, pat.lower()):
            return True
    return False


def is_safe_to_read(path: Any, allowed_roots: Optional[List[str | Path]] = None) -> bool:
    """
    Determines if a path is safe for the tool to read:
    - Resolves path to canonical form (evaluates symlinks, ../, etc.)
    - Denies if any path component or the file name matches a sensitive pattern
    - Denies if the resolved path is outside all allowed roots
    Never raises an exception; returns False on invalid input or failure.
    """
    if path is None:
        return False
    try:
        p = Path(path).resolve()

        # Check all path components against sensitive name patterns
        for part in p.parts:
            # Strip drive suffix on Windows like 'C:\\' -> 'C:' before matching
            clean_part = part.rstrip("\\/").rstrip(":")
            if clean_part and is_sensitive_path_component(clean_part):
                return False

        # Determine roots
        if allowed_roots is not None:
            roots = [Path(r).resolve() for r in allowed_roots if r]
        else:
            roots = get_allowed_roots()

        if not roots:
            return False

        # Check if resolved path is inside one of the allowed roots
        inside_root = False
        norm_p = os.path.normcase(str(p))
        for r in roots:
            try:
                if p.is_relative_to(r):
                    inside_root = True
                    break
            except Exception:
                pass
            norm_r = os.path.normcase(str(r))
            if norm_p == norm_r:
                inside_root = True
                break
            if not norm_r.endswith(os.sep):
                norm_r += os.sep
            if norm_p.startswith(norm_r):
                inside_root = True
                break

        return inside_root

    except Exception:
        return False
