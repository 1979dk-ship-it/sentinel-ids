import queue
import threading
import time

from core.alerts.alert import Alert
from core.utils.sliding_window import SlidingWindow


# Flag combinations that indicate stealth scans
_NULL_FLAGS = ""
_FIN_FLAGS  = "F"
_XMAS_FLAGS = "FPU"


class PortScanDetector:
    """
    Detects port scan activity by tracking unique destination ports
    per source IP within a sliding time window.

    Handles four scan types:
    - SYN scan:  more than threshold_ports unique ports in window_seconds
    - NULL scan: packet with no TCP flags
    - FIN scan:  packet with only the FIN flag
    - XMAS scan: packet with FIN + PSH + URG flags
    """

    def __init__(
        self,
        packet_queue:    queue.Queue,
        alert_queue:     queue.Queue,
        threshold_ports: int = 15,
        window_seconds:  int = 5,
    ):
        self._packets         = packet_queue
        self._alerts          = alert_queue
        self._threshold_ports = threshold_ports
        self._window_seconds  = window_seconds

        # src_ip → SlidingWindow keyed by dst_port
        self._windows: dict[str, SlidingWindow] = {}

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the detector on a background daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-port-scan"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the detection loop to stop and wait for the thread to finish."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        """Main loop: read packets from queue and process each one."""
        while not self._stop_event.is_set():
            try:
                packet = self._packets.get(timeout=1)
                self._process(packet)
            except queue.Empty:
                continue

    def _process(self, packet: dict) -> None:
        """Evaluate a single packet for port scan indicators."""
        src_ip   = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        flags    = packet.get("flags", "")
        now      = packet.get("timestamp") or time.time()

        # stealth scan detection – flag-based, no window needed
        if flags is not None and packet.get("protocol") == "TCP":
            if flags == _NULL_FLAGS:
                self._emit(src_ip, "LOW", {"scan_type": "NULL"})
                return
            if flags == _FIN_FLAGS:
                self._emit(src_ip, "LOW", {"scan_type": "FIN"})
                return
            if flags == _XMAS_FLAGS:
                self._emit(src_ip, "LOW", {"scan_type": "XMAS"})
                return

        # sliding window – only track packets with a destination port
        if not src_ip or not dst_port:
            return

        window = self._windows.get(src_ip)
        if window is None:
            window = SlidingWindow(self._window_seconds)
            self._windows[src_ip] = window

        window.add(now, dst_port)

        if window.distinct() > self._threshold_ports:
            self._emit(src_ip, "HIGH", {
                "scan_type":   "SYN",
                "port_count":  window.distinct(),
                "ports":       sorted(window.keys()),
            })
            window.clear()   # reset so we don't re-alert on same burst

    def _emit(self, src_ip: str, severity: str, details: dict) -> None:
        """Push an Alert onto the alert queue."""
        if not src_ip:
            return
        alert = Alert(
            type      = "PORT_SCAN",
            severity  = severity,
            src_ip    = src_ip,
            timestamp = time.time(),
            details   = details,
        )
        self._alerts.put(alert)
