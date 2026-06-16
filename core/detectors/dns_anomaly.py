import math
import queue
import threading
import time

from core.alerts.alert import Alert
from core.utils.cooldown import CooldownTracker
from core.utils.sliding_window import SlidingWindow

_DNS_PORT = 53


def _shannon_entropy(name: str) -> float:
    """
    Calculates Shannon entropy for a domain name string.
    High-entropy names (> ~3.5) suggest Base32/Base64-encoded tunnel data.
    """
    if not name:
        return 0.0
    length = len(name)
    freq = {}
    for ch in name:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _leftmost_label(qname: str) -> str:
    """Returns the first DNS label (the subdomain part closest to the data)."""
    return qname.split(".")[0] if qname else ""


class DnsAnomalyDetector:
    """
    Detects DNS-based attacks by inspecting query names on UDP/53.

    Three detection signals:
    - Long subdomain  (> subdomain_max_length chars): HIGH  – likely tunneling payload
    - High entropy    (> entropy_threshold):          HIGH  – Base32/64-encoded data
    - Query flood     (> query_threshold per window): MEDIUM – exfiltration loop or DGA

    Each (src_ip, qname) pair is silenced for cooldown_seconds after an alert
    to prevent storms from a single active tunnel session.
    """

    def __init__(
        self,
        packet_queue:        queue.Queue,
        alert_queue:         queue.Queue,
        query_threshold:     int   = 50,
        query_window_seconds: int  = 60,
        subdomain_max_length: int  = 50,
        entropy_threshold:   float = 3.5,
        cooldown_seconds:    int   = 60,
    ):
        self._packets              = packet_queue
        self._alerts               = alert_queue
        self._query_threshold      = query_threshold
        self._query_window         = query_window_seconds
        self._subdomain_max_length = subdomain_max_length
        self._entropy_threshold    = entropy_threshold

        # src_ip → SlidingWindow keyed by qname
        self._windows:  dict[str, SlidingWindow] = {}
        self._cooldown: CooldownTracker          = CooldownTracker(cooldown_seconds)

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-dns-anomaly",
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
        if packet.get("protocol") != "UDP":
            return
        if packet.get("dst_port") != _DNS_PORT:
            return

        qname = packet.get("dns_qname")
        if not qname:
            return

        src_ip    = packet.get("src_ip")
        qtype     = packet.get("dns_qtype")
        now       = packet.get("timestamp") or time.time()
        subdomain = _leftmost_label(qname)

        if not src_ip:
            return

        cooldown_key = (src_ip, qname)
        if self._cooldown.is_cooling(cooldown_key, now):
            return

        # Signal 1 – subdomain too long (tunneling payload)
        if len(subdomain) > self._subdomain_max_length:
            self._emit(src_ip, qname, qtype, "LONG_SUBDOMAIN",
                       "HIGH", len(subdomain), now)
            self._cooldown.mark(cooldown_key, now)
            return

        # Signal 2 – high Shannon entropy (encoded data)
        entropy = _shannon_entropy(subdomain)
        if entropy > self._entropy_threshold:
            self._emit(src_ip, qname, qtype, "HIGH_ENTROPY",
                       "HIGH", entropy, now)
            self._cooldown.mark(cooldown_key, now)
            return

        # Signal 3 – query flood to the same domain (O(1) via SlidingWindow)
        window = self._windows.get(src_ip)
        if window is None:
            window = SlidingWindow(self._query_window)
            self._windows[src_ip] = window

        count = window.add(now, qname)
        if count >= self._query_threshold:
            self._emit(src_ip, qname, qtype, "QUERY_FLOOD",
                       "MEDIUM", count, now)
            self._cooldown.mark(cooldown_key, now)

    def _emit(
        self,
        src_ip:   str,
        qname:    str,
        qtype:    int | None,
        reason:   str,
        severity: str,
        value,
        now:      float,
    ) -> None:
        self._alerts.put(Alert(
            type      = "DNS_ANOMALY",
            severity  = severity,
            src_ip    = src_ip,
            timestamp = now,
            details   = {
                "reason":  reason,
                "qname":   qname,
                "qtype":   qtype,
                "value":   round(value, 3) if isinstance(value, float) else value,
            },
        ))
