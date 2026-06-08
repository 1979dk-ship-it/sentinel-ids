"""Simulates a SYN port scan on loopback to trigger the PortScanDetector."""
from scapy.all import IP, TCP, send
import time

ATTACKER = "10.0.0.99"    # fake source IP – simulates an external attacker
TARGET   = "192.168.1.1"  # gateway – forces traffic through the physical NIC
PORTS  = range(1, 25)   # 24 ports – above the threshold of 15

print(f"[*] Sending SYN scan to {TARGET} ({len(PORTS)} ports)...")
for port in PORTS:
    send(IP(src=ATTACKER, dst=TARGET)/TCP(dport=port, flags="S"), verbose=0)
    time.sleep(0.1)
print("[*] Done")
