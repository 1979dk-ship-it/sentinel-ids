"""Unit tests for the alert line formatter.

Pure string formatting – no Textual app is mounted; we only assert what a
rendered alert line contains, in particular the repeat counter.
"""
from core.alerts.alert import Alert
from ui.tui.widgets.alert_panel import format_alert_line


def _alert():
    return Alert(type="ARP_SPOOF", severity="HIGH", src_ip="10.0.0.1", timestamp=1000.0)


def test_count_of_one_shows_no_multiplier():
    line = format_alert_line(_alert(), count=1)
    assert "×" not in line
    assert "ARP_SPOOF" in line


def test_count_above_one_shows_multiplier():
    line = format_alert_line(_alert(), count=473)
    assert "×473" in line
