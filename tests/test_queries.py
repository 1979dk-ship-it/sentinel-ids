"""Unit tests for db/queries.

Each test runs against a fresh, file-backed SQLite database provided by the
`session_factory` fixture, so tests are fully isolated. The queries take `now`
explicitly, so time-based filtering is deterministic.
"""
import pytest

from core.alerts.alert import Alert
from db.database import init_db
from db.queries import (
    active_blocks,
    alerts_since,
    is_blocked,
    record_block,
    record_unblock,
    save_alert,
)


@pytest.fixture
def session_factory(tmp_path):
    """A fresh, isolated SQLite database (its own file) for each test."""
    return init_db((tmp_path / "test.db").as_posix())


def test_save_alert_and_query_back(session_factory):
    alert = Alert(type="PORT_SCAN", severity="HIGH", src_ip="1.2.3.4",
                  timestamp=1000.0, details={"ports": [22, 80]})
    save_alert(session_factory, alert)

    rows = alerts_since(session_factory, seconds=3600, now=1000.0)
    assert len(rows) == 1
    assert rows[0].type == "PORT_SCAN"
    assert rows[0].severity == "HIGH"
    assert rows[0].src_ip == "1.2.3.4"
    assert rows[0].details == {"ports": [22, 80]}


def test_alerts_since_filters_window_and_orders_newest_first(session_factory):
    save_alert(session_factory, Alert("OLD", "LOW", "0.0.0.0", timestamp=1000.0))
    save_alert(session_factory, Alert("A", "LOW", "1.1.1.1", timestamp=4000.0))
    save_alert(session_factory, Alert("B", "LOW", "2.2.2.2", timestamp=4500.0))

    rows = alerts_since(session_factory, seconds=3600, now=5000.0)   # cutoff = 1400
    # OLD (t=1000 < 1400) is excluded; the rest come back newest-first.
    assert [r.type for r in rows] == ["B", "A"]


def test_record_block_makes_ip_blocked(session_factory):
    assert is_blocked(session_factory, "1.2.3.4") is False
    record_block(session_factory, "1.2.3.4", reason="port scan", blocked_by="user", now=1000.0)
    assert is_blocked(session_factory, "1.2.3.4") is True


def test_unblock_lifts_block_and_returns_true(session_factory):
    record_block(session_factory, "1.2.3.4", "scan", "user", now=1000.0)

    lifted = record_unblock(session_factory, "1.2.3.4", now=1100.0)
    assert lifted is True
    assert is_blocked(session_factory, "1.2.3.4") is False


def test_unblock_when_not_blocked_returns_false(session_factory):
    assert record_unblock(session_factory, "9.9.9.9") is False


def test_active_blocks_lists_only_active(session_factory):
    record_block(session_factory, "1.1.1.1", "scan", "user", now=1000.0)
    record_block(session_factory, "2.2.2.2", "flood", "user", now=2000.0)
    record_unblock(session_factory, "1.1.1.1", now=1500.0)

    active = active_blocks(session_factory)
    assert [b.ip for b in active] == ["2.2.2.2"]


def test_reblock_after_unblock_creates_new_active_row(session_factory):
    record_block(session_factory, "1.1.1.1", "scan", "user", now=1000.0)
    record_unblock(session_factory, "1.1.1.1", now=1100.0)
    assert is_blocked(session_factory, "1.1.1.1") is False

    # Blocking again adds a NEW row; the lifted one stays as an audit record.
    record_block(session_factory, "1.1.1.1", "scan again", "user", now=2000.0)
    assert is_blocked(session_factory, "1.1.1.1") is True
    assert len(active_blocks(session_factory)) == 1
