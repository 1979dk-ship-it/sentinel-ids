"""Unit tests for PortScanDetector.

Tests drive `_process(packet)` directly instead of the background thread, so
each packet is handled synchronously and the assertions are deterministic - no
sleeping to wait for a worker thread. Alerts are read back from the alert queue.
"""
import queue

import pytest

from core.detectors.port_scan import PortScanDetector


def make_packet(**overrides):
    """A TCP SYN packet dict with sane defaults; override any field per test."""
    packet = {
        "src_ip": "10.0.0.5",
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "S",
        "timestamp": 1000.0,
    }
    packet.update(overrides)
    return packet


def test_syn_scan_fires_high_alert():
    alerts = queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3, window_seconds=5)

    for port in (80, 81, 82, 83):   # 4 distinct ports, one over the threshold of 3
        detector._process(make_packet(dst_port=port))

    alert = alerts.get_nowait()
    assert alert.type == "PORT_SCAN"
    assert alert.severity == "HIGH"
    assert alert.src_ip == "10.0.0.5"
    assert alert.details["scan_type"] == "SYN"
    assert alert.details["port_count"] == 4
    assert alert.details["ports"] == [80, 81, 82, 83]
    assert alerts.empty()           # exactly one alert, not one per packet


def test_ports_at_threshold_do_not_alert():
    alerts = queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3, window_seconds=5)

    for port in (80, 81, 82):       # 3 distinct == threshold; firing needs > threshold
        detector._process(make_packet(dst_port=port))

    assert alerts.empty()


@pytest.mark.parametrize("flags, scan_type", [
    ("",    "NULL"),   # no flags set
    ("F",   "FIN"),    # FIN only
    ("FPU", "XMAS"),   # FIN + PSH + URG
])
def test_stealth_scan_fires_low_alert(flags, scan_type):
    alerts = queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3)

    # A single packet with a stealth flag combo alerts on its own - no window.
    detector._process(make_packet(flags=flags))

    alert = alerts.get_nowait()
    assert alert.severity == "LOW"
    assert alert.details["scan_type"] == scan_type


def test_repeat_scan_within_cooldown_is_suppressed():
    alerts = queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3,
                                window_seconds=5, cooldown_seconds=60)

    for port in (80, 81, 82, 83):
        detector._process(make_packet(dst_port=port, timestamp=1000.0))
    assert alerts.get_nowait().severity == "HIGH"

    # Same source scans again 10s later, still inside the 60s cooldown.
    for port in (90, 91, 92, 93):
        detector._process(make_packet(dst_port=port, timestamp=1010.0))
    assert alerts.empty()


def test_scan_fires_again_after_cooldown():
    alerts = queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3,
                                window_seconds=5, cooldown_seconds=60)

    for port in (80, 81, 82, 83):
        detector._process(make_packet(dst_port=port, timestamp=1000.0))
    assert alerts.get_nowait().severity == "HIGH"

    # 61s later the cooldown has lapsed, so a fresh scan alerts again.
    for port in (90, 91, 92, 93):
        detector._process(make_packet(dst_port=port, timestamp=1061.0))
    assert alerts.get_nowait().severity == "HIGH"


def test_missing_fields_do_not_crash_or_alert():
    alerts = queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3)

    detector._process(make_packet(src_ip=None))            # window path guard
    detector._process(make_packet(dst_port=None))          # window path guard
    detector._process(make_packet(flags=None))             # skips stealth, no port scan
    detector._process(make_packet(src_ip=None, flags=""))  # stealth path, _emit guard

    assert alerts.empty()
