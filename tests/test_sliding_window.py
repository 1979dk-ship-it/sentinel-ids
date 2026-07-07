"""Unit tests for SlidingWindow - the time-bounded event counter.

There is no `import time` here: every test supplies `now` by hand, so the tests
are deterministic and run in microseconds instead of sleeping on a real clock.
"""
from core.utils.sliding_window import SlidingWindow, prune_idle_windows


def test_add_returns_running_count_for_key():
    window = SlidingWindow(window_seconds=5)

    assert window.add(now=100.0, key="port-22") == 1
    assert window.add(now=101.0, key="port-22") == 2


def test_count_returns_zero_for_unseen_key():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")

    # A key we never added counts as 0 rather than raising KeyError.
    assert window.count("port-80") == 0


def test_count_distinct_and_total_track_multiple_keys():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")
    window.add(now=100.0, key="port-22")
    window.add(now=100.0, key="port-80")

    assert window.count("port-22") == 2
    assert window.count("port-80") == 1
    assert window.distinct() == 2
    assert window.total() == 3


def test_event_expires_after_window_elapses():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")
    assert window.total() == 1

    window.prune(now=106.0)   # event is now 6s old, past the 5s window
    assert window.total() == 0
    assert window.count("port-22") == 0


def test_event_exactly_at_window_edge_survives():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")

    # cutoff = now - window = 100, and pruning drops events with ts < cutoff,
    # so an event whose ts equals the cutoff survives its final instant.
    window.prune(now=105.0)
    assert window.total() == 1


def test_event_one_tick_past_window_edge_expires():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")

    # One tick later the cutoff is 100.001, so the event at 100.0 falls out.
    window.prune(now=105.001)
    assert window.total() == 0


def test_only_events_outside_window_expire():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")
    window.add(now=104.0, key="port-80")

    window.prune(now=106.0)   # cutoff = 101: drops 100.0, keeps 104.0
    assert window.total() == 1
    assert window.count("port-22") == 0
    assert window.count("port-80") == 1
    assert window.distinct() == 1


def test_clear_empties_the_window():
    window = SlidingWindow(window_seconds=5)
    window.add(now=100.0, key="port-22")
    window.add(now=100.0, key="port-80")
    assert not window.is_empty()

    window.clear()

    assert window.is_empty()
    assert window.total() == 0
    assert window.distinct() == 0
    assert window.count("port-22") == 0


def test_prune_idle_windows_removes_only_drained_windows():
    active = SlidingWindow(window_seconds=5)
    active.add(now=104.0, key="x")          # recent – still inside the window at 106
    idle = SlidingWindow(window_seconds=5)
    idle.add(now=100.0, key="y")            # 6s old at 106 – has drained

    windows = {"active": active, "idle": idle}
    removed = prune_idle_windows(windows, now=106.0)   # cutoff = 101

    assert removed == 1
    assert set(windows) == {"active"}


def test_prune_idle_windows_on_empty_dict_is_noop():
    windows: dict = {}
    assert prune_idle_windows(windows, now=100.0) == 0
    assert windows == {}
