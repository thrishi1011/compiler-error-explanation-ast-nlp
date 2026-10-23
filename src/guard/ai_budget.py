"""
ai_budget.py
------------
Thread-safe rate and prompt-size budget tracker for AI model requests.
Enforces:
1. Max prompt characters (system + prompt).
2. Max calls per rolling hour.
Supports an injectable clock for deterministic testing.
Deterministic Python, standard library only.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional, Tuple

from .config import GUARD_AI_MAX_CALLS_PER_HOUR, GUARD_AI_MAX_PROMPT_CHARS


class AiBudget:
    def __init__(self, clock: Optional[Callable[[], float]] = None) -> None:
        self._lock = threading.Lock()
        self._clock = clock or time.time
        self._call_timestamps: list[float] = []

    def set_clock(self, clock_fn: Callable[[], float]) -> None:
        """Injectable clock for unit testing."""
        with self._lock:
            self._clock = clock_fn

    def reset(self) -> None:
        """Resets call timestamps and restores default clock."""
        with self._lock:
            self._call_timestamps.clear()
            self._clock = time.time

    def try_consume(self, kind: str, prompt_chars: int) -> Tuple[bool, str]:
        """
        Attempts to consume one AI call budget unit.
        Returns (True, "") if allowed, or (False, reason) if refused.
        """
        try:
            max_chars = int(os.environ.get("GUARD_AI_MAX_PROMPT_CHARS", GUARD_AI_MAX_PROMPT_CHARS))
        except (ValueError, TypeError):
            max_chars = GUARD_AI_MAX_PROMPT_CHARS

        try:
            max_calls = int(os.environ.get("GUARD_AI_MAX_CALLS_PER_HOUR", GUARD_AI_MAX_CALLS_PER_HOUR))
        except (ValueError, TypeError):
            max_calls = GUARD_AI_MAX_CALLS_PER_HOUR

        if prompt_chars > max_chars:
            return False, f"Prompt length ({prompt_chars} chars) exceeds maximum allowed limit ({max_chars} chars)"

        with self._lock:
            now = self._clock()
            cutoff = now - 3600.0
            self._call_timestamps = [t for t in self._call_timestamps if t > cutoff]

            if len(self._call_timestamps) >= max_calls:
                return False, f"AI call limit exceeded: {len(self._call_timestamps)} calls in rolling hour (limit: {max_calls})"

            self._call_timestamps.append(now)
            return True, ""


_AI_BUDGET_SINGLETON: Optional[AiBudget] = None
_INIT_LOCK = threading.Lock()


def get_ai_budget() -> AiBudget:
    """Returns singleton AiBudget instance."""
    global _AI_BUDGET_SINGLETON
    if _AI_BUDGET_SINGLETON is None:
        with _INIT_LOCK:
            if _AI_BUDGET_SINGLETON is None:
                _AI_BUDGET_SINGLETON = AiBudget()
    return _AI_BUDGET_SINGLETON
