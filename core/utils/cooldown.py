from typing import Hashable


class CooldownTracker:
    """
    Per-key alert suppression with bounded memory.

    After an alert fires on `key`, mark() records the time. Subsequent
    calls to is_cooling() return True until `cooldown_seconds` elapse.

    A naive dict would grow forever as new keys appear; mark() therefore
    opportunistically prunes entries older than the cooldown, so memory
    stays proportional to the number of keys that alerted recently rather
    than the lifetime of the process.
    """

    def __init__(self, cooldown_seconds: float):
        self._cooldown    = cooldown_seconds
        self._last:       dict[Hashable, float] = {}
        self._last_prune: float = 0.0

    def is_cooling(self, key: Hashable, now: float) -> bool:
        last = self._last.get(key)
        if last is None:
            return False
        return (now - last) < self._cooldown

    def mark(self, key: Hashable, now: float) -> None:
        self._last[key] = now
        if (now - self._last_prune) > self._cooldown:
            self._prune(now)
            self._last_prune = now

    def _prune(self, now: float) -> None:
        cutoff  = now - self._cooldown
        expired = [k for k, t in self._last.items() if t < cutoff]
        for k in expired:
            del self._last[k]
