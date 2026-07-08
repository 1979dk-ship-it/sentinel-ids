"""Unit tests for BruteForceDetector.

Packets are fed to `_process` directly (synchronous, deterministic) and alerts
read back from the alert queue. Note the fire condition is `count >= threshold`
(fires AT the threshold), unlike the port-scan detector's strict `>`.
"""
import queue

import pytest

from core.detectors.brute_force import BruteForceDetector


def make_tcp(**overrides):
    """A TCP SYN packet to SSH by default; override fields per test."""
    packet = {
        "protocol": "TCP",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "flags": "S",
        "timestamp": 1000.0,
        "payload": b"",
    }
    packet.update(overrides)
    return packet


@pytest.mark.parametrize("dst_port, service", [
    (22,  "SSH"),
    (443, "HTTPS"),
])
def test_syn_brute_force_fires_at_threshold(dst_port, service):
    alerts = queue.Queue()
    detector = BruteForceDetector(queue.Queue(), alerts,
                                  ssh_threshold=5, https_threshold=5)

    for _ in range(5):   # count reaches 5 == threshold -> fires (>=)
        detector._process(make_tcp(dst_port=dst_port, flags="S"))

    alert = alerts.get_nowait()
    assert alert.type == "BRUTE_FORCE"
    assert alert.severity == "HIGH"
    assert alert.details["service"] == service
    assert alert.details["attempt_count"] == 5
    assert alerts.empty()


def test_ssh_below_threshold_is_quiet():
    alerts = queue.Queue()
    detector = BruteForceDetector(queue.Queue(), alerts, ssh_threshold=5)

    for _ in range(4):   # 4 < 5 -> no alert
        detector._process(make_tcp(dst_port=22, flags="S"))

    assert alerts.empty()


def test_http_login_brute_force_fires():
    alerts = queue.Queue()
    detector = BruteForceDetector(queue.Queue(), alerts, http_threshold=3)

    for _ in range(3):
        detector._process(make_tcp(dst_port=80, flags="PA",
                                   payload=b"POST /login HTTP/1.1"))

    alert = alerts.get_nowait()
    assert alert.details["service"] == "HTTP"
    assert alert.details["attempt_count"] == 3
    assert alerts.empty()


@pytest.mark.parametrize("payload", [
    b"GET /index.html HTTP/1.1",   # neither POST nor /login
    b"POST /search HTTP/1.1",      # POST but not /login
    b"GET /login HTTP/1.1",        # /login but not POST
])
def test_http_non_login_traffic_ignored(payload):
    alerts = queue.Queue()
    detector = BruteForceDetector(queue.Queue(), alerts, http_threshold=3)

    for _ in range(10):   # well over threshold, but none match POST + /login
        detector._process(make_tcp(dst_port=80, flags="PA", payload=payload))

    assert alerts.empty()


def test_repeat_within_cooldown_is_suppressed():
    alerts = queue.Queue()
    detector = BruteForceDetector(queue.Queue(), alerts, ssh_threshold=5, cooldown_seconds=60)

    for _ in range(5):
        detector._process(make_tcp(dst_port=22, flags="S", timestamp=1000.0))
    assert alerts.get_nowait().details["service"] == "SSH"

    # Same (src, dst, port) key 10s later, still cooling: stays quiet.
    for _ in range(5):
        detector._process(make_tcp(dst_port=22, flags="S", timestamp=1010.0))
    assert alerts.empty()


def test_idle_session_windows_are_swept():
    # White-box: idle (src,dst,port) windows are reclaimed so _windows stays bounded.
    detector = BruteForceDetector(queue.Queue(), queue.Queue(), ssh_threshold=5)

    for i in range(3):   # one SYN per distinct source, below threshold
        detector._process(make_tcp(src_ip=f"10.0.0.{i}", dst_port=22, timestamp=1000.0))
    assert len(detector._windows) == 3

    detector._process(make_tcp(src_ip="10.0.0.99", dst_port=22, timestamp=1031.0))
    assert list(detector._windows.keys()) == [("10.0.0.99", "10.0.0.1", 22)]


def test_non_tcp_and_missing_fields_ignored():
    alerts = queue.Queue()
    detector = BruteForceDetector(queue.Queue(), alerts, ssh_threshold=1)

    detector._process(make_tcp(protocol="UDP", dst_port=22))   # not TCP
    detector._process(make_tcp(src_ip=None))                   # no source IP
    detector._process(make_tcp(dst_ip=None))                   # no dest IP
    detector._process(make_tcp(dst_port=None))                 # no dest port

    assert alerts.empty()
