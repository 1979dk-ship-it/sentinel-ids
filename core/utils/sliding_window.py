from collections import Counter, deque
from typing import Hashable, Iterable


class SlidingWindow:
    """
    Time-bounded event counter with O(1) lookups.

    Each event carries an optional `key` (e.g. dst_port for port scans,
    qname for DNS). Internally we keep two structures in sync:

      - deque of (timestamp, key) – used to know when to expire events
      - Counter mapping key -> count – the actual count, queried in O(1)

    When an event falls out of the window, its key's count is decremented;
    keys that hit zero are deleted so per-key memory does not grow without
    bound when many distinct keys appear once and never return.
    """

    def __init__(self, window_seconds: float):
        self._window  = window_seconds
        self._log:    deque                  = deque()
        self._counts: Counter[Hashable]      = Counter()

    def add(self, now: float, key: Hashable = None) -> int:
        """Record an event at `now` for `key`, prune expired ones, return key's count."""
        self._prune(now)
        self._log.append((now, key))
        self._counts[key] += 1
        return self._counts[key]

    def count(self, key: Hashable = None) -> int:
        return self._counts.get(key, 0)

    def total(self) -> int:
        return len(self._log)

    def distinct(self) -> int:
        return len(self._counts)

    def keys(self) -> Iterable[Hashable]:
        return self._counts.keys()

    def clear(self) -> None:
        self._log.clear()
        self._counts.clear()

    def is_empty(self) -> bool:
        return not self._log

    def prune(self, now: float) -> None:
        """Expire events older than the window relative to `now`, without adding one."""
        self._prune(now)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._log and self._log[0][0] < cutoff:
            _, expired = self._log.popleft()
            self._counts[expired] -= 1
            if self._counts[expired] <= 0:
                del self._counts[expired]


def prune_idle_windows(windows: dict[Hashable, SlidingWindow], now: float) -> int:
    """Prune each window to `now`, drop the ones left empty, return the count.

    SlidingWindow expires events only lazily, so a window must be pruned before
    is_empty() tells the truth. Call periodically to bound a per-key window dict:
    otherwise it keeps one entry per key that ever appeared.
    """
    removed = 0
    for key in list(windows.keys()):   # snapshot: we delete while iterating
        window = windows[key]
        window.prune(now)
        if window.is_empty():
            del windows[key]
            removed += 1
    return removed
