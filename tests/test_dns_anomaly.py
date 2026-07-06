"""Unit tests for DnsAnomalyDetector.

Packets are fed to `_process` directly (synchronous, deterministic) and alerts
read back from the alert queue. The three signals are checked in order - long
subdomain, then high entropy, then query flood - and the first match wins.
"""
import queue

from core.detectors.dns_anomaly import DnsAnomalyDetector


def make_dns(**overrides):
    """A benign DNS A-query on UDP/53; override fields per test."""
    packet = {
        "protocol": "UDP",
        "dst_port": 53,
        "src_ip": "10.0.0.5",
        "dns_qname": "www.example.com",
        "dns_qtype": 1,          # A record
        "timestamp": 1000.0,
    }
    packet.update(overrides)
    return packet


def test_long_subdomain_fires_high():
    alerts = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts, subdomain_max_length=10)

    # 11-char leftmost label, all identical (so entropy stays 0 - isolates signal 1).
    detector._process(make_dns(dns_qname="aaaaaaaaaaa.example.com"))

    alert = alerts.get_nowait()
    assert alert.type == "DNS_ANOMALY"
    assert alert.severity == "HIGH"
    assert alert.details["reason"] == "LONG_SUBDOMAIN"
    assert alert.details["value"] == 11
    assert alerts.empty()


def test_subdomain_at_max_length_does_not_fire():
    alerts = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts, subdomain_max_length=10)

    # Exactly 10 chars: signal 1 needs strictly > max_length, so this stays quiet.
    detector._process(make_dns(dns_qname="aaaaaaaaaa.example.com"))

    assert alerts.empty()


def test_high_entropy_subdomain_fires_high():
    alerts = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts, entropy_threshold=3.5)

    # 16 distinct chars -> Shannon entropy log2(16) = 4.0 > 3.5, but short enough
    # that the long-subdomain signal does not fire first.
    detector._process(make_dns(dns_qname="abcdefghijklmnop.example.com"))

    alert = alerts.get_nowait()
    assert alert.severity == "HIGH"
    assert alert.details["reason"] == "HIGH_ENTROPY"
    assert alerts.empty()


def test_normal_query_is_quiet():
    alerts = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts)

    # A short, low-entropy label queried once trips none of the three signals.
    detector._process(make_dns(dns_qname="mail.example.com"))

    assert alerts.empty()


def test_query_flood_fires_medium():
    alerts = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts, query_threshold=5)

    for _ in range(5):   # same short, low-entropy name; 5th hits the threshold (>=)
        detector._process(make_dns(dns_qname="data.example.com"))

    alert = alerts.get_nowait()
    assert alert.severity == "MEDIUM"
    assert alert.details["reason"] == "QUERY_FLOOD"
    assert alert.details["value"] == 5
    assert alerts.empty()


def test_non_dns_and_missing_fields_ignored():
    alerts = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts, subdomain_max_length=5)

    # A long subdomain that WOULD fire signal 1 if any guard were bypassed.
    tunnel = "aaaaaaaaaaaaaaaa.example.com"
    detector._process(make_dns(protocol="TCP", dns_qname=tunnel))   # not UDP
    detector._process(make_dns(dst_port=80, dns_qname=tunnel))      # not port 53
    detector._process(make_dns(dns_qname=None))                     # no query name
    detector._process(make_dns(src_ip=None, dns_qname=tunnel))      # no source IP

    assert alerts.empty()
