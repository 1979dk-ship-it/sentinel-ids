import time                                             # used to timestamp packets when Scapy doesn't provide one
from typing import Optional                             # allows return type hint of dict | None

from scapy.layers.inet import IP, TCP, UDP, ICMP       # L3/L4 layer classes used to check and extract fields
from scapy.layers.l2 import Ether, ARP                 # L2 layer classes for Ethernet and ARP packets


class PacketParser:
    """
    Converts a raw Scapy packet into a clean, flat dictionary.
    Detectors never interact with Scapy directly – they only see the output of this class.
    """

    def parse(self, packet) -> Optional[dict]:          # entry point – called once per captured packet
        """
        Parse a raw Scapy packet into a flat dictionary.
        Returns None if the packet is not relevant to any detector.
        """
        result = self._base(packet)                     # start with fields that exist in every packet
        self._extract_ethernet(packet, result)          # add L2 fields if Ethernet layer is present
        self._extract_ip(packet, result)                # add L3 fields if IP layer is present
        self._extract_transport(packet, result)         # add L4 fields if TCP/UDP/ICMP layer is present
        self._extract_arp(packet, result)               # add ARP fields if this is an ARP packet
        return result                                   # return the complete flat dictionary to the queue

    # ------------------------------------------------------------------
    # private helpers – each one handles exactly one network layer
    # ------------------------------------------------------------------

    def _base(self, packet) -> dict:                    # builds the skeleton dict that all packets share
        return {
            "timestamp": getattr(packet, "time", time.time()),  # packet capture time; fallback to now
            "size":      len(packet),                   # total packet size in bytes
            "src_mac":   None,                          # filled by _extract_ethernet if Ether layer exists
            "dst_mac":   None,
            "src_ip":    None,                          # filled by _extract_ip if IP layer exists
            "dst_ip":    None,
            "ttl":       None,                          # Time To Live – decremented at each router hop
            "protocol":  None,                          # string: "TCP", "UDP", "ICMP", "ARP", or "OTHER"
            "src_port":  None,                          # filled by _extract_transport if TCP/UDP exists
            "dst_port":  None,
            "flags":     None,                          # TCP flags string e.g. "S", "SA", "F" – None for UDP
            "seq":       None,                          # TCP sequence number – used by SYN flood detector
            "payload":   b"",                           # raw bytes after transport header
        }

    def _extract_ethernet(self, packet, result: dict) -> None:   # handles L2 – Data Link layer
        if not packet.haslayer(Ether):                  # skip if no Ethernet header (e.g. loopback packets)
            return
        eth = packet[Ether]                             # access the Ethernet layer object
        result["src_mac"] = eth.src                     # source MAC address e.g. "00:0c:29:1a:2b:3c"
        result["dst_mac"] = eth.dst                     # destination MAC address

    def _extract_ip(self, packet, result: dict) -> None:         # handles L3 – Network layer
        if not packet.haslayer(IP):                     # skip ARP and other non-IP packets
            return
        ip = packet[IP]                                 # access the IP layer object
        result["src_ip"]   = ip.src                     # source IP address e.g. "192.168.1.5"
        result["dst_ip"]   = ip.dst                     # destination IP address
        result["ttl"]      = ip.ttl                     # TTL value – reveals OS fingerprint and routing hops
        result["protocol"] = self._protocol_name(ip.proto)  # convert protocol number to readable string

    def _extract_transport(self, packet, result: dict) -> None:  # handles L4 – Transport layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]                           # access the TCP layer object
            result["src_port"] = tcp.sport              # source port number (0–65535)
            result["dst_port"] = tcp.dport              # destination port number
            result["flags"]    = str(tcp.flags)         # e.g. "S" = SYN, "SA" = SYN-ACK, "F" = FIN
            result["seq"]      = tcp.seq                # sequence number – tracks byte order in stream
            result["payload"]  = bytes(tcp.payload)     # raw bytes after TCP header

        elif packet.haslayer(UDP):
            udp = packet[UDP]                           # access the UDP layer object
            result["src_port"] = udp.sport              # UDP has ports but no flags or sequence numbers
            result["dst_port"] = udp.dport
            result["payload"]  = bytes(udp.payload)     # raw bytes after UDP header – contains DNS data etc.

        elif packet.haslayer(ICMP):
            result["protocol"] = "ICMP"                 # override – IP proto field says ICMP, be explicit

    def _extract_arp(self, packet, result: dict) -> None:        # handles ARP – lives at L2, has no IP layer
        if not packet.haslayer(ARP):                    # skip all non-ARP packets
            return
        arp = packet[ARP]                               # access the ARP layer object
        result["protocol"] = "ARP"                     # mark this packet clearly for the ARP spoof detector
        result["src_ip"]   = arp.psrc                  # sender IP (psrc = protocol source)
        result["dst_ip"]   = arp.pdst                  # target IP
        result["src_mac"]  = arp.hwsrc                 # sender MAC (hwsrc = hardware source)
        result["dst_mac"]  = arp.hwdst                 # target MAC

    @staticmethod
    def _protocol_name(proto_number: int) -> str:      # converts IP protocol number to a readable string
        mapping = {
            6:   "TCP",                                 # proto 6 = TCP (defined in IANA protocol numbers)
            17:  "UDP",                                 # proto 17 = UDP
            1:   "ICMP",                                # proto 1 = ICMP
        }
        return mapping.get(proto_number, "OTHER")       # unknown protocol – label as OTHER, don't discard
