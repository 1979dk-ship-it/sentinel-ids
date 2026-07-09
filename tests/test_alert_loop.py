"""Integration tests for _handle_alert – the dedup routing in the alert loop.

Drives the real Deduplicator and a real per-test DB against a fake TUI app that
only records push_alert calls, so we can assert what reaches persistence and the
live feed without a running Textual app.
"""
from core.alerts.alert import Alert
from core.alerts.deduplicator import Deduplicator
from db.queries import alerts_since
from main import _handle_alert


class _FakeApp:
    """Stand-in for the TUI: call_from_thread runs the callback inline."""

    def __init__(self):
        self.pushed = []
        self.counts = []

    def call_from_thread(self, fn, *args):
        fn(*args)

    def push_alert(self, alert):
        self.pushed.append(alert)

    def push_alert_count(self, alert, count):
        self.counts.append((alert, count))


def _alert(t, src="1.1.1.1", atype="DNS_ANOMALY", sev="HIGH"):
    return Alert(type=atype, severity=sev, src_ip=src, timestamp=t)


def test_new_alert_is_persisted_and_pushed(session_factory):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    _handle_alert(_alert(1000.0), session_factory, deduper, app)

    rows = alerts_since(session_factory, seconds=3600, now=1000.0)
    assert len(rows) == 1
    assert rows[0].count == 1
    assert len(app.pushed) == 1


def test_storm_collapses_to_one_row_and_one_push(session_factory):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    for i in range(500):   # a DNS-tunnel storm: 500 identical alerts in the window
        _handle_alert(_alert(1000.0 + i * 0.01), session_factory, deduper, app)

    rows = alerts_since(session_factory, seconds=3600, now=1010.0)
    assert len(rows) == 1                       # one row, not 500
    assert rows[0].count == 500                 # the counter carries the magnitude
    assert rows[0].last_seen == 1000.0 + 499 * 0.01
    assert len(app.pushed) == 1                 # live feed saw one new alert – storm suppressed
    assert len(app.counts) == 499               # the repeats arrived as count bumps
    assert app.counts[-1][1] == 500             # the last bump carries the final total


def test_new_episode_after_window_makes_a_second_row(session_factory):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    _handle_alert(_alert(1000.0), session_factory, deduper, app)
    _handle_alert(_alert(1100.0), session_factory, deduper, app)   # 100s later -> new episode

    rows = alerts_since(session_factory, seconds=3600, now=1100.0)
    assert len(rows) == 2
    assert len(app.pushed) == 2
