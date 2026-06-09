import queue
import threading
import time
from collections import defaultdict, deque

from core.alerts.alert import Alert


class ArpSpoofDetector:
    """
    Detects ARP-based attacks by monitoring two indicators:

    1. MAC Conflict – a known IP suddenly appears with a different MAC,
       which is the fingerprint of ARP cache poisoning.

    2. Gratuitous ARP Flood – unsolicited ARP Replies (op=2, src_ip==dst_ip)
       sent at high frequency from the same MAC, which is how arpspoof
       continuously overwrites victim caches.
    """

    def __init__(
        self,
        packet_queue:              queue.Queue,
        alert_queue:               queue.Queue,
        gratuitous_threshold:      int = 3,
        gratuitous_window_seconds: int = 60,
    ):
        self._packets                   = packet_queue
        self._alerts                    = alert_queue
        self._gratuitous_threshold      = gratuitous_threshold
        self._gratuitous_window_seconds = gratuitous_window_seconds

        self._arp_table: dict[str, str]          = {}
        self._gratuitous_log: dict[str, deque]   = defaultdict(deque)

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-arp-spoof",
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
        if packet.get("protocol") != "ARP":
            return

        src_ip  = packet.get("src_ip")
        src_mac = packet.get("src_mac")
        dst_ip  = packet.get("dst_ip")
        arp_op  = packet.get("arp_op")
        now     = packet.get("timestamp") or time.time()

        if not src_ip or not src_mac:
            return

        self._check_mac_conflict(src_ip, src_mac)
        self._check_gratuitous_flood(src_ip, src_mac, dst_ip, arp_op, now)

    def _check_mac_conflict(self, src_ip: str, src_mac: str) -> None:
        known_mac = self._arp_table.get(src_ip)

        if known_mac is None:
            self._arp_table[src_ip] = src_mac
            return

        if known_mac != src_mac:
            self._emit(
                src_ip   = src_ip,
                severity = "HIGH",
                details  = {
                    "reason":    "mac_conflict",
                    "known_mac": known_mac,
                    "new_mac":   src_mac,
                },
            )
            self._arp_table[src_ip] = src_mac

    def _check_gratuitous_flood(
        self,
        src_ip:  str,
        src_mac: str,
        dst_ip:  str | None,
        arp_op:  int | None,
        now:     float,
    ) -> None:
        if arp_op != 2 or src_ip != dst_ip:
            return

        log = self._gratuitous_log[src_mac]
        log.append(now)

        while log and (now - log[0]) > self._gratuitous_window_seconds:
            log.popleft()

        if len(log) > self._gratuitous_threshold:
            self._emit(
                src_ip   = src_ip,
                severity = "MEDIUM",
                details  = {
                    "reason":  "gratuitous_arp_flood",
                    "src_mac": src_mac,
                    "count":   len(log),
                },
            )
            log.clear()

    def _emit(self, src_ip: str, severity: str, details: dict) -> None:
        self._alerts.put(Alert(
            type      = "ARP_SPOOF",
            severity  = severity,
            src_ip    = src_ip,
            timestamp = time.time(),
            details   = details,
        ))
