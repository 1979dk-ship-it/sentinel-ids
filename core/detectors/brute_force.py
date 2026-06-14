import queue
import threading
import time
from collections import defaultdict, deque

from core.alerts.alert import Alert

_SSH_PORT   = 22
_HTTP_PORT  = 80
_HTTPS_PORT = 443


class BruteForceDetector:
    """
    Detects brute force login attempts on three services:

    - SSH  (port 22):  counts TCP SYN packets per (src_ip, dst_ip, port).
                       Low threshold – no legitimate reason for rapid reconnects.
    - HTTP (port 80):  counts packets whose payload contains POST + /login.
                       Payload is readable, so the signal is precise.
    - HTTPS (port 443): counts TCP SYN packets only – payload is TLS-encrypted.
                        High threshold to absorb NAT and parallel browser connections.

    A per-key cooldown prevents alert storms after the threshold is crossed.
    """

    def __init__(
        self,
        packet_queue:        queue.Queue,
        alert_queue:         queue.Queue,
        ssh_threshold:       int = 5,
        ssh_window_seconds:  int = 30,
        http_threshold:      int = 20,
        http_window_seconds: int = 60,
        https_threshold:     int = 100,
        https_window_seconds: int = 60,
        cooldown_seconds:    int = 60,
    ):
        self._packets             = packet_queue
        self._alerts              = alert_queue
        self._ssh_threshold       = ssh_threshold
        self._ssh_window          = ssh_window_seconds
        self._http_threshold      = http_threshold
        self._http_window         = http_window_seconds
        self._https_threshold     = https_threshold
        self._https_window        = https_window_seconds
        self._cooldown_seconds    = cooldown_seconds

        # (src_ip, dst_ip, dst_port) → deque of event timestamps
        self._window: dict[tuple, deque] = defaultdict(deque)

        # (src_ip, dst_ip, dst_port) → timestamp of last alert
        self._cooldown: dict[tuple, float] = {}

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-brute-force",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                packet = self._packets.get(timeout=1)
                self._process(packet)
            except queue.Empty:
                continue

    def _process(self, packet: dict) -> None:
        if packet.get("protocol") != "TCP":
            return

        src_ip   = packet.get("src_ip")
        dst_ip   = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        flags    = packet.get("flags", "")
        now      = packet.get("timestamp") or time.time()

        if not src_ip or not dst_ip or not dst_port:
            return

        if dst_port == _SSH_PORT:
            if flags == "S":
                self._record(src_ip, dst_ip, dst_port, now,
                             self._ssh_threshold, self._ssh_window, "SSH")

        elif dst_port == _HTTPS_PORT:
            if flags == "S":
                self._record(src_ip, dst_ip, dst_port, now,
                             self._https_threshold, self._https_window, "HTTPS")

        elif dst_port == _HTTP_PORT:
            payload = packet.get("payload", b"")
            if b"POST" in payload and b"/login" in payload:
                self._record(src_ip, dst_ip, dst_port, now,
                             self._http_threshold, self._http_window, "HTTP")

    def _record(
        self,
        src_ip:   str,
        dst_ip:   str,
        dst_port: int,
        now:      float,
        threshold: int,
        window:   int,
        service:  str,
    ) -> None:
        key = (src_ip, dst_ip, dst_port)

        last_alert = self._cooldown.get(key, 0.0)
        if now - last_alert < self._cooldown_seconds:
            return

        log = self._window[key]
        log.append(now)

        while log and (now - log[0]) > window:
            log.popleft()

        if len(log) >= threshold:
            self._emit(src_ip, dst_port, service, len(log))
            self._cooldown[key] = now
            log.clear()

    def _emit(self, src_ip: str, dst_port: int, service: str, count: int) -> None:
        self._alerts.put(Alert(
            type      = "BRUTE_FORCE",
            severity  = "HIGH",
            src_ip    = src_ip,
            timestamp = time.time(),
            details   = {
                "service":       service,
                "dst_port":      dst_port,
                "attempt_count": count,
            },
        ))
