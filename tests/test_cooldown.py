"""Unit tests for CooldownTracker - per-key alert suppression.

As with SlidingWindow, `now` is injected into every call, so these tests are
deterministic and never sleep on a real clock.
"""
from core.utils.cooldown import CooldownTracker


def test_not_cooling_before_any_mark():
    tracker = CooldownTracker(cooldown_seconds=60)

    # A key we never marked is not cooling - there is nothing to suppress yet.
    assert not tracker.is_cooling("1.1.1.1", now=100.0)


def test_cooling_immediately_after_mark():
    tracker = CooldownTracker(cooldown_seconds=60)
    tracker.mark("1.1.1.1", now=100.0)

    assert tracker.is_cooling("1.1.1.1", now=100.0)
    assert tracker.is_cooling("1.1.1.1", now=130.0)   # 30s elapsed, still < 60s


def test_not_cooling_after_cooldown_elapses():
    tracker = CooldownTracker(cooldown_seconds=60)
    tracker.mark("1.1.1.1", now=100.0)

    # 61s later the cooldown has lapsed, so the key may alert again.
    assert not tracker.is_cooling("1.1.1.1", now=161.0)


def test_cooling_one_tick_before_edge():
    tracker = CooldownTracker(cooldown_seconds=60)
    tracker.mark("1.1.1.1", now=100.0)

    # 59.999s in: still inside the cooldown.
    assert tracker.is_cooling("1.1.1.1", now=159.999)


def test_not_cooling_exactly_at_edge():
    tracker = CooldownTracker(cooldown_seconds=60)
    tracker.mark("1.1.1.1", now=100.0)

    # is_cooling uses `elapsed < cooldown`, so 60 < 60 is False - the cooldown
    # is already considered lapsed the instant it reaches its own boundary.
    assert not tracker.is_cooling("1.1.1.1", now=160.0)


def test_keys_are_independent():
    tracker = CooldownTracker(cooldown_seconds=60)
    tracker.mark("1.1.1.1", now=100.0)

    # Marking one key must not start cooling a different key.
    assert tracker.is_cooling("1.1.1.1", now=110.0)
    assert not tracker.is_cooling("2.2.2.2", now=110.0)


def test_remark_refreshes_the_cooldown():
    tracker = CooldownTracker(cooldown_seconds=60)
    tracker.mark("1.1.1.1", now=100.0)
    tracker.mark("1.1.1.1", now=150.0)   # restarts the clock from 150, not 100

    assert tracker.is_cooling("1.1.1.1", now=200.0)      # 50s since re-mark
    assert not tracker.is_cooling("1.1.1.1", now=211.0)  # 61s since re-mark


def test_stale_keys_are_pruned_from_memory():
    tracker = CooldownTracker(cooldown_seconds=60)

    # Mark 100 keys early, then one key far later. The late mark triggers a
    # prune that evicts every key older than (now - cooldown).
    for i in range(100):
        tracker.mark(f"10.0.0.{i}", now=100.0)
    tracker.mark("1.1.1.1", now=1000.0)

    # White-box on purpose: pruning frees memory but changes no public output,
    # so the only way to confirm the map stays bounded is to look inside _last.
    assert len(tracker._last) == 1
    assert "1.1.1.1" in tracker._last
