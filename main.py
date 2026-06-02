import queue
import signal
import sys
import yaml

from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue


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
    parser    = PacketParser()
    pkt_queue = PacketQueue()
    consumer  = pkt_queue.subscribe()
    capture   = PacketCapture(interface=interface, parser=parser, queue=pkt_queue)

    def _shutdown(sig, frame):
        """Ensures resources are freed correctly on SIGINT."""
        print("\n[*] Stopping capture...")
        capture.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)

    print(f"[*] SENTINEL IDS – starting on interface: {interface or 'default'}")
    print("[*] Press Ctrl+C to stop\n")

    capture.start()
    _log_loop(consumer)


if __name__ == "__main__":
    main()