from __future__ import annotations

import os
from typing import Literal

Severity = Literal["Critical", "High", "Medium", "Low"]
Action = Literal["block", "warn", "allow"]

# Severity weights (matches security_analyzer.py)
SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical": 10,
    "High": 5,
    "Medium": 2,
    "Low": 1,
}

# Severity hierarchy for duplicate merging (lower number = higher precedence)
SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

# Action hierarchy (lower number = stronger action)
ACTION_ORDER: dict[str, int] = {
    "block": 0,
    "warn": 1,
    "allow": 2,
}

# Risk label thresholds (matches security_analyzer._risk_label)
def get_risk_label(score: int) -> str:
    if score == 0:
        return "Clean"
    if score <= 10:
        return "Low Risk"
    if score <= 30:
        return "Moderate"
    return "High Risk"


# Scan limits
MAX_SCAN_BYTES: int = 2 * 1024 * 1024  # 2 MB
MAX_HEADER_DEPTH: int = 3
MAX_HEADER_COUNT: int = 20
MAX_HEADER_BYTES: int = 256 * 1024     # 256 KB

# Log configuration
DEFAULT_LOG_PATH: str = os.path.normpath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "attack_log.jsonl")
)
LOG_ROTATION_BYTES: int = 5 * 1024 * 1024  # 5 MB

# Safe subprocess execution timeouts in seconds
# Can be overridden per kind via environment variables: GUARD_TIMEOUT_<KIND> (e.g. GUARD_TIMEOUT_COMPILE=40)
DEFAULT_TIMEOUTS: dict[str, float] = {
    "compile": 20.0,
    "build": 20.0,
    "syntax": 10.0,
    "ast": 20.0,
    "ai_validate": 10.0,
    "analysis": 60.0,
    "run": 5.0,
}


def get_timeout_for_kind(kind: str, custom_timeout: float | None = None) -> float:
    """
    Returns timeout in seconds for a given execution kind.
    Checks environment variable GUARD_TIMEOUT_<KIND> first, then custom_timeout,
    then defaults from DEFAULT_TIMEOUTS (falling back to 20.0s).
    """
    env_key = f"GUARD_TIMEOUT_{kind.upper()}"
    if env_key in os.environ:
        try:
            return float(os.environ[env_key])
        except ValueError:
            pass
    if custom_timeout is not None:
        return float(custom_timeout)
    return DEFAULT_TIMEOUTS.get(kind.lower(), 20.0)


# Phase 3: Web endpoint limits and timeouts
ENDPOINT_MAX_BODY: int = 512_000
ENDPOINT_MAX_CODE_CHARS: int = 200_000
ENDPOINT_RATE: tuple[int, int] = (120, 60)  # (events, seconds)
ENDPOINT_CONCURRENCY: dict[str, int] = {
    "/api/heal": 2,
    "/api/compile": 4,
    "/api/run": 2,
}
SOCKET_TIMEOUT_SECONDS: int = 30

# Phase 5: AI limits and Patch Guard constants
GUARD_AI_MAX_CALLS_PER_HOUR: int = 60
GUARD_AI_MAX_PROMPT_CHARS: int = 60_000

PATCH_MAX_CHANGED_LINES_AI_PERCENT: float = 0.25
PATCH_MAX_CHANGED_LINES_AI_MIN: int = 10
PATCH_MAX_CHANGED_LINES_OFFLINE: int = 12

CPP_STANDARD_HEADERS: set[str] = {
    # C++ standard library headers
    "algorithm", "any", "array", "atomic", "barrier", "bit", "bitset", "charconv",
    "chrono", "codecvt", "compare", "complex", "concepts", "coroutine", "deque",
    "exception", "execution", "expected", "format", "forward_list", "fstream",
    "functional", "future", "generator", "initializer_list", "iomanip", "ios",
    "iosfwd", "iostream", "istream", "iterator", "latch", "limits", "list",
    "locale", "map", "mdspan", "memory", "memory_resource", "mutex", "new",
    "numbers", "numeric", "optional", "ostream", "print", "queue", "random",
    "ranges", "ratio", "regex", "scoped_allocator", "semaphore", "set", "shared_mutex",
    "source_location", "span", "spanstream", "sstream", "stack", "stacktrace",
    "stdexcept", "stop_token", "streambuf", "string", "string_view", "syncstream",
    "system_error", "tuple", "type_traits", "typeindex", "typeinfo", "unordered_map",
    "unordered_set", "utility", "valarray", "variant", "vector", "version",
    # C library headers (C++ wrapper style)
    "cassert", "cctype", "cerrno", "cfenv", "cfloat", "cinttypes", "ciso646",
    "climits", "clocale", "cmath", "csetjmp", "csignal", "cstdarg", "cstdbool",
    "cstddef", "cstdint", "cstdio", "cstdlib", "cstring", "ctgmath", "ctime",
    "cuchar", "cwchar", "cwctype",
    # C library headers (.h style)
    "assert.h", "ctype.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
    "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h",
    "stdarg.h", "stdbool.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h",
    "string.h", "tgmath.h", "time.h", "uchar.h", "wchar.h", "wctype.h",
}
