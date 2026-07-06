"""Unit tests for PacketParser.

Each test builds a real Scapy packet, round-trips it through bytes (`_wire`) so
its fields are in wire form - exactly as a sniffed packet arrives - and then
checks the flat dict the parser produces.
"""
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from core.capture.parser import PacketParser


def _wire(pkt):
    """Serialize then re-parse, so fields hold their on-the-wire values."""
    return pkt.__class__(bytes(pkt))


def test_parse_tcp_packet():
    parser = PacketParser()
    pkt = IP(src="10.0.0.5", dst="10.0.0.1", ttl=64) / TCP(
        sport=1234, dport=80, flags="S", seq=1000)

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "TCP"
    assert result["src_ip"] == "10.0.0.5"
    assert result["dst_ip"] == "10.0.0.1"
    assert result["ttl"] == 64
    assert result["src_port"] == 1234
    assert result["dst_port"] == 80
    assert result["flags"] == "S"
    assert result["seq"] == 1000


def test_parse_tcp_payload():
    parser = PacketParser()
    pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="PA") / b"POST /login HTTP/1.1"

    result = parser.parse(_wire(pkt))

    assert result["payload"] == b"POST /login HTTP/1.1"


def test_parse_dns_query():
    parser = PacketParser()
    pkt = (IP(src="10.0.0.5", dst="8.8.8.8")
           / UDP(sport=5000, dport=53)
           / DNS(qr=0, rd=1, qd=DNSQR(qname="tunnel.evil.com", qtype="A")))

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "UDP"
    assert result["dst_port"] == 53
    assert result["dns_qname"] == "tunnel.evil.com"   # trailing dot stripped
    assert result["dns_qtype"] == 1                   # A record


def test_parse_arp_packet():
    parser = PacketParser()
    pkt = Ether(src="aa:aa:aa:aa:aa:aa") / ARP(
        op=2, psrc="10.0.0.5", pdst="10.0.0.1",
        hwsrc="aa:aa:aa:aa:aa:aa", hwdst="bb:bb:bb:bb:bb:bb")

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "ARP"
    assert result["src_ip"] == "10.0.0.5"
    assert result["dst_ip"] == "10.0.0.1"
    assert result["src_mac"] == "aa:aa:aa:aa:aa:aa"
    assert result["arp_op"] == 2


def test_parse_extracts_ethernet_macs():
    parser = PacketParser()
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP() / TCP()

    result = parser.parse(_wire(pkt))

    assert result["src_mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["dst_mac"] == "11:22:33:44:55:66"


def test_unsupported_packet_returns_dict_not_none():
    parser = PacketParser()
    pkt = IP(proto=99) / b"unknown-l4"

    result = parser.parse(_wire(pkt))

    # parse() always returns a dict, even for protocols it does not decode.
    assert result is not None
    assert result["protocol"] == "OTHER"
