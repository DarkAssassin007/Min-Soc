"""Deduplication: stop identical events producing duplicate alerts.

A bounded, thread-safe TTL set. Memory is capped by ``max_entries`` and entries
expire after ``window_seconds``, so a Mini SOC can run for weeks without the
dedupe cache becoming a leak.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from ..config.logging_config import get_logger

logger = get_logger(__name__)


class Deduplicator:
    """Time-windowed set of recently seen dedupe hashes."""

    def __init__(self, *, window_seconds: int = 5, max_entries: int = 50_000) -> None:
        self.window_seconds = max(int(window_seconds), 0)
        self.max_entries = max(int(max_entries), 1)
        self._entries: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def seen(self, key: str) -> bool:
        """Return True when ``key`` was observed inside the window."""
        if not key:
            return False
        if self.window_seconds == 0:
            return False
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            previous = self._entries.get(key)
            self._entries[key] = now
            self._entries.move_to_end(key)
            if previous is not None and (now - previous) <= self.window_seconds:
                self.hits += 1
                return True
            self.misses += 1
            return False

    def is_duplicate(self, key: str) -> bool:
        """Alias kept for readability at call sites."""
        return self.seen(key)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._entries:
            key, stamp = next(iter(self._entries.items()))
            if stamp >= cutoff and len(self._entries) <= self.max_entries:
                break
            self._entries.pop(key, None)

    def stats(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "window_seconds": self.window_seconds,
                "duplicates_suppressed": self.hits,
                "unique_events": self.misses,
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self.hits = 0
            self.misses = 0


__all__ = ["Deduplicator"]
