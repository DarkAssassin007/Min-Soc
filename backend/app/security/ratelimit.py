"""Rate limiting (spec section 24).

A bounded sliding-window limiter, applied per client and per route class. Two
limits matter operationally: a generous general API limit, and a much stricter
limit on authentication endpoints so credential stuffing is not free.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    reset_after_seconds: float
    key: str

    def headers(self) -> dict[str, str]:
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(self.remaining, 0)),
            "X-RateLimit-Reset": str(int(max(self.reset_after_seconds, 0))),
        }


class SlidingWindowLimiter:
    """Thread-safe sliding-window counter."""

    def __init__(self, *, max_keys: int = 20000) -> None:
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.RLock()
        self.blocked = 0
        self.allowed = 0

    def check(self, key: str, *, limit: int, window_seconds: float) -> RateLimitResult:
        if limit <= 0:
            return RateLimitResult(True, limit, limit, 0.0, key)
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            entries = self._hits.get(key)
            if entries is None:
                entries = deque()
                self._hits[key] = entries
                if len(self._hits) > self.max_keys:
                    self._evict(cutoff)
            while entries and entries[0] < cutoff:
                entries.popleft()
            if len(entries) >= limit:
                self.blocked += 1
                reset = max(window_seconds - (now - entries[0]), 0.0)
                return RateLimitResult(False, 0, limit, reset, key)
            entries.append(now)
            self.allowed += 1
            remaining = max(limit - len(entries), 0)
            reset = window_seconds - (now - entries[0]) if entries else window_seconds
            return RateLimitResult(True, remaining, limit, reset, key)

    def _evict(self, cutoff: float) -> None:
        stale = [key for key, entries in self._hits.items() if not entries or entries[-1] < cutoff]
        for key in stale[: self.max_keys // 2]:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
            self.blocked = 0
            self.allowed = 0

    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "keys": len(self._hits),
                "allowed": self.allowed,
                "blocked": self.blocked,
            }


__all__ = ["RateLimitResult", "SlidingWindowLimiter"]
