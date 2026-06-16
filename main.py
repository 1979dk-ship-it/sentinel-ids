import queue
import signal
import sys
import threading
import yaml

from core.alerts.alert import Alert
from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.brute_force import BruteForceDetector
from core.detectors.dns_anomaly import DnsAnomalyDetector
from core.detectors.port_scan import PortScanDetector


def _load_config(path: str = "config/config.yaml") -> dict:
    """Loads runtime configuration parameters."""
    with open(path) as f:
        return yaml.safe_load(f)


def _print_packet(p: dict) -> None:
    """Formats packet dictionary fields into a standardized stdout string."""
    proto = p.get("protocol") or "OTHER"
    src   = p.get("src_ip")  or p.get("src_mac") or "?"
    dst   = p.get("dst_ip")  or p.get("dst_mac") or "?"
    size  = p.get("size", 0)

    line = f"[{proto:<5}] {src:<18} → {dst:<18}  {size}b"

    if p.get("src_port"):
        line += f"  {p['src_port']} → {p['dst_port']}"
    if p.get("flags"):
        line += f"  flags:{p['flags']}"

    print(line)


def _print_alert(a: Alert) -> None:
    """Formats an Alert into a colored stdout line."""
    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
    reset  = "\033[0m"
    color  = colors.get(a.severity, "")
    print(f"{color}[ALERT] [{a.severity:<6}] {a.type:<12}  src={a.src_ip}  {a.details}{reset}")


def _alert_loop(alert_queue: queue.Queue) -> None:
    """Runs on a background thread – prints alerts as they arrive."""
    while True:
        try:
            alert = alert_queue.get(timeout=1)
            _print_alert(alert)
        except queue.Empty:
            continue


def _log_loop(consumer: queue.Queue) -> None:
    """
    Main execution loop. Consumes events from the packet queue
    and handles output until interrupted.
    """
    while True:
        try:
            packet = consumer.get(timeout=1)
            _print_packet(packet)
        except queue.Empty:
            continue


def main() -> None:
    config    = _load_config()
    interface = config["network"]["interface"]
    if interface == "auto":
        interface = None

    # Dependency Injection & Pipeline Assembly
    parser      = PacketParser()
    pkt_queue   = PacketQueue()
    alert_queue = queue.Queue()

    consumer    = pkt_queue.subscribe()
    capture     = PacketCapture(interface=interface, parser=parser, queue=pkt_queue)
    ps_cfg      = config["detectors"]["port_scan"]
    ps_detector = PortScanDetector(
        pkt_queue.subscribe(),
        alert_queue,
        threshold_ports = ps_cfg["threshold_ports"],
        window_seconds  = ps_cfg["window_seconds"],
    )

    arp_cfg      = config["detectors"]["arp_spoof"]
    arp_detector = ArpSpoofDetector(
        pkt_queue.subscribe(),
        alert_queue,
        gratuitous_threshold      = arp_cfg["gratuitous_threshold"],
        gratuitous_window_seconds = arp_cfg["gratuitous_window_seconds"],
    )

    bf_cfg      = config["detectors"]["brute_force"]
    bf_detector = BruteForceDetector(
        pkt_queue.subscribe(),
        alert_queue,
        ssh_threshold        = bf_cfg["ssh_threshold"],
        ssh_window_seconds   = bf_cfg["ssh_window_seconds"],
        http_threshold       = bf_cfg["http_threshold"],
        http_window_seconds  = bf_cfg["http_window_seconds"],
        https_threshold      = bf_cfg["https_threshold"],
        https_window_seconds = bf_cfg["https_window_seconds"],
        cooldown_seconds     = bf_cfg.get("cooldown_seconds", 60),
    )

    dns_cfg      = config["detectors"]["dns_anomaly"]
    dns_detector = DnsAnomalyDetector(
        pkt_queue.subscribe(),
        alert_queue,
        query_threshold      = dns_cfg["query_threshold"],
        query_window_seconds = dns_cfg["query_window_seconds"],
        subdomain_max_length = dns_cfg["subdomain_max_length"],
        entropy_threshold    = dns_cfg["entropy_threshold"],
        cooldown_seconds     = dns_cfg["cooldown_seconds"],
    )

    def _shutdown(sig, frame):
        """Ensures resources are freed correctly on SIGINT."""
        print("\n[*] Stopping capture...")
        capture.stop()
        ps_detector.stop()
        arp_detector.stop()
        bf_detector.stop()
        dns_detector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)

    print(f"[*] SENTINEL IDS – starting on interface: {interface or 'default'}")
    print("[*] Press Ctrl+C to stop\n")

    capture.start()
    ps_detector.start()
    arp_detector.start()
    bf_detector.start()
    dns_detector.start()

    threading.Thread(target=_alert_loop, args=(alert_queue,), daemon=True).start()
    _log_loop(consumer)


if __name__ == "__main__":
    main()