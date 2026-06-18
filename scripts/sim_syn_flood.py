"""
Simulates a SYN flood (DoS) over the network interface.

Run SENTINEL first, then execute this script from a second terminal:
    python scripts/sim_syn_flood.py

The source IP of every packet is randomized on purpose. A real SYN flood
spoofs its source – the attacker never needs the SYN-ACK reply – so the
detector keys on the *destination* IP, the one stable anchor. This script
proves the detector still fires even when every source address is fake.

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

from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

IFACE       = conf.iface
TARGET_HIGH = "192.168.1.10"   # victim for the HIGH scenario
TARGET_MED  = "192.168.1.20"   # different victim to avoid the per-dst cooldown


def _random_ip() -> str:
    """A fresh spoofed source for every packet."""
    return f"{random.randint(11, 250)}.{random.randint(0, 255)}." \
           f"{random.randint(0, 255)}.{random.randint(1, 254)}"


def _send_syn(target: str):
    pkt = IP(src=_random_ip(), dst=target) / TCP(dport=80, flags="S")
    send(pkt, iface=IFACE, verbose=False)


def _send_ack(target: str):
    pkt = IP(src=_random_ip(), dst=target) / TCP(dport=80, flags="A")
    send(pkt, iface=IFACE, verbose=False)


def scenario_a_high():
    print("[A] HIGH flood – 60 spoofed SYNs to one target, zero ACKs...")
    for i in range(60):
        _send_syn(TARGET_HIGH)
        if (i + 1) % 10 == 0:
            print(f"  {i + 1} SYNs sent")
        time.sleep(0.02)
    print("[A] Done – expect SYN_FLOOD HIGH alert (src=None).\n")


def scenario_b_medium():
    print("[B] MEDIUM flood – 30 spoofed SYNs + 2 ACKs to a second target...")
    for i in range(30):
        _send_syn(TARGET_MED)
        time.sleep(0.02)
    _send_ack(TARGET_MED)
    _send_ack(TARGET_MED)
    print("[B] Done – ratio ~15, expect SYN_FLOOD MEDIUM alert.\n")


if __name__ == "__main__":
    print("=== SYN Flood Simulation ===\n")
    scenario_a_high()
    time.sleep(3)
    scenario_b_medium()
    print("=== Simulation complete ===")
