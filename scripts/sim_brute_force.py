"""
Simulates brute force login attempts over the network interface.

Run SENTINEL first, then execute this script from a second terminal:
    python scripts/sim_brute_force.py

Scenario A – SSH Brute Force:
    Sends repeated TCP SYN packets to port 22 from a fake attacker IP.
    Each SYN represents a new connection attempt (the SSH server would
    close the connection after each failed auth, forcing a reconnect).
    Expected: one BRUTE_FORCE HIGH alert with service=SSH.

Scenario B – HTTP Login Brute Force:
    Sends TCP packets carrying a POST /login payload to port 80.
    Payload is plaintext HTTP, so the detector can inspect it directly.
    Expected: one BRUTE_FORCE HIGH alert with service=HTTP.
"""

import time

from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send

IFACE    = conf.iface
ATTACKER = "10.0.0.77"     # fake source IP – simulates an external attacker
TARGET   = "192.168.1.1"   # gateway – forces traffic through the physical NIC


def _send(pkt):
    send(pkt, iface=IFACE, verbose=False)


def scenario_a_ssh():
    print("[A] Sending SSH brute force – 7 SYN packets to port 22...")
    for i in range(7):
        pkt = IP(src=ATTACKER, dst=TARGET) / TCP(dport=22, flags="S")
        _send(pkt)
        print(f"  SYN #{i + 1} sent")
        time.sleep(0.5)
    print("[A] Done – expect BRUTE_FORCE HIGH alert (service=SSH).\n")


def scenario_b_http():
    print("[B] Sending HTTP login brute force – 22 POST /login requests to port 80...")
    payload = b"POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n"
    for i in range(22):
        pkt = IP(src=ATTACKER, dst=TARGET) / TCP(dport=80, flags="PA") / Raw(load=payload)
        _send(pkt)
        print(f"  POST #{i + 1} sent")
        time.sleep(0.2)
    print("[B] Done – expect BRUTE_FORCE HIGH alert (service=HTTP).\n")


if __name__ == "__main__":
    print("=== Brute Force Simulation ===\n")
    scenario_a_ssh()
    time.sleep(3)
    scenario_b_http()
    print("=== Simulation complete ===")