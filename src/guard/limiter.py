"""
limiter.py
----------
Thread-safe concurrency and rate limiting primitives for guarding
heavy and rate-sensitive web server endpoints.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable


class Busy(Exception):
    """Raised when ConcurrencyLimiter cannot acquire a slot."""
    pass


class ConcurrencyLimiter:
    """
    Limits concurrent in-flight operations using a BoundedSemaphore.
    Provides non-blocking try_acquire(), safe release(), and context manager
    usage that raises Busy when full.
    """

    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max(1, int(max_concurrent))
        self._sem = threading.BoundedSemaphore(self.max_concurrent)

    def try_acquire(self) -> bool:
        """Attempts to acquire a slot without blocking. Returns True if acquired."""
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        """Releases an acquired slot. Tolerates redundant releases gracefully."""
        try:
            self._sem.release()
        except ValueError:
            pass

    def __enter__(self) -> ConcurrencyLimiter:
        if not self.try_acquire():
            raise Busy(f"Concurrency limit of {self.max_concurrent} exceeded")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class RateLimiter:
    """
    Sliding window rate limiter. Thread-safe with injectable clock for tests.
    """

    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_events = int(max_events)
        self.window_seconds = float(window_seconds)
        self.clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """
        Returns True and records the event if within rate limit;
        otherwise returns False.
        """
        now = self.clock()
        with self._lock:
            cutoff = now - self.window_seconds
            while self._events and self._events[0] <= cutoff:
                self._events.popleft()

            if len(self._events) < self.max_events:
                self._events.append(now)
                return True
            return False
