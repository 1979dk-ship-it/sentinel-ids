"""Unit tests for ArpSpoofDetector.

Like the port-scan tests, packets are fed to `_process` directly so handling is
synchronous and deterministic, and alerts are read back from the alert queue.
"""
import queue

from core.detectors.arp_spoof import ArpSpoofDetector


def make_arp(**overrides):
    """A normal ARP reply (op=2) whose src_ip != dst_ip, so it is NOT gratuitous.

    Gratuitous-flood tests override dst_ip to equal src_ip.
    """
    packet = {
        "protocol": "ARP",
        "src_ip": "10.0.0.5",
        "src_mac": "aa:aa:aa:aa:aa:aa",
        "dst_ip": "10.0.0.1",
        "arp_op": 2,
        "timestamp": 1000.0,
    }
    packet.update(overrides)
    return packet


def test_mac_conflict_fires_high_alert():
    alerts = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts)

    detector._process(make_arp(src_ip="10.0.0.5", src_mac="aa:aa:aa:aa:aa:aa"))
    detector._process(make_arp(src_ip="10.0.0.5", src_mac="bb:bb:bb:bb:bb:bb"))

    alert = alerts.get_nowait()
    assert alert.type == "ARP_SPOOF"
    assert alert.severity == "HIGH"
    assert alert.details["reason"] == "mac_conflict"
    assert alert.details["known_mac"] == "aa:aa:aa:aa:aa:aa"
    assert alert.details["new_mac"] == "bb:bb:bb:bb:bb:bb"
    assert alerts.empty()


def test_first_sighting_is_learned_silently():
    alerts = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts)

    # An IP seen for the first time is recorded, not alerted on.
    detector._process(make_arp(src_ip="10.0.0.5", src_mac="aa:aa:aa:aa:aa:aa"))

    assert alerts.empty()


def test_same_mac_does_not_conflict():
    alerts = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts)

    detector._process(make_arp(src_ip="10.0.0.5", src_mac="aa:aa:aa:aa:aa:aa"))
    detector._process(make_arp(src_ip="10.0.0.5", src_mac="aa:aa:aa:aa:aa:aa"))

    assert alerts.empty()


def test_gratuitous_flood_fires_medium_alert():
    alerts = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts, gratuitous_threshold=3)

    # src_ip == dst_ip makes each reply gratuitous; 4 of them exceed the threshold.
    for _ in range(4):
        detector._process(make_arp(dst_ip="10.0.0.5"))

    alert = alerts.get_nowait()
    assert alert.type == "ARP_SPOOF"
    assert alert.severity == "MEDIUM"
    assert alert.details["reason"] == "gratuitous_arp_flood"
    assert alert.details["count"] == 4
    assert alerts.empty()


def test_gratuitous_below_threshold_is_quiet():
    alerts = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts, gratuitous_threshold=3)

    for _ in range(3):   # 3 == threshold; a flood needs > threshold
        detector._process(make_arp(dst_ip="10.0.0.5"))

    assert alerts.empty()


def test_non_arp_and_missing_fields_are_ignored():
    alerts = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts)

    detector._process(make_arp(protocol="TCP"))   # not ARP at all
    detector._process(make_arp(src_ip=None))      # no source IP
    detector._process(make_arp(src_mac=None))     # no source MAC

    assert alerts.empty()
