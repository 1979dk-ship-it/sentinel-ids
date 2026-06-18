import queue
import threading
import time

from core.alerts.alert import Alert
from core.utils.cooldown import CooldownTracker
from core.utils.sliding_window import SlidingWindow

_SYN = "S"   # pure SYN  – a connection attempt
_ACK = "A"   # pure ACK  – the packet that completes a healthy handshake


class SynFloodDetector:
    """
    Detects SYN flood attacks by tracking the SYN-to-ACK ratio per destination IP.

    In a healthy network handshakes balance out: every SYN is eventually followed
    by a completing ACK, so the SYN and ACK counts track each other. In a flood
    the attacker fires SYNs and never finishes the handshake, so the ratio blows up.

    We count per *destination* IP on purpose. SYN flood sources are routinely
    spoofed – the attacker never needs the SYN-ACK reply – so src_ip is worthless
    as a key. The destination is the real, fixed target, which makes a stable key
    and is also why blocking by source IP does not help against this attack.

    Severity scales with the ratio:
      - SYN > ACK * ratio_medium  -> MEDIUM
      - SYN > ACK * ratio_high    -> HIGH

    A min_syn floor avoids alerting on tiny bursts, and max(ack, 1) keeps the
    ratio finite when no ACKs arrive at all – the typical flood case.
    """

    def __init__(
        self,
        packet_queue:     queue.Queue,
        alert_queue:      queue.Queue,
        ratio_medium:     int = 10,
        ratio_high:       int = 50,
        window_seconds:   int = 5,
        min_syn:          int = 20,
        cooldown_seconds: int = 60,
    ):
        self._packets      = packet_queue
        self._alerts       = alert_queue
        self._ratio_medium = ratio_medium
        self._ratio_high   = ratio_high
        self._window       = window_seconds
        self._min_syn      = min_syn

        # dst_ip -> SlidingWindow keyed by flag type (_SYN / _ACK)
        self._windows:  dict[str, SlidingWindow] = {}
        self._cooldown: CooldownTracker          = CooldownTracker(cooldown_seconds)

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-syn-flood",
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

        dst_ip = packet.get("dst_ip")
        flags  = packet.get("flags")
        now    = packet.get("timestamp") or time.time()

        if not dst_ip or flags is None:
            return

        # We only track pure SYN and pure ACK. Mixed flags (SA, PA, ...) are
        # noise for this ratio and are deliberately ignored.
        if flags == _SYN:
            self._record(dst_ip, _SYN, now)
        elif flags == _ACK:
            self._record(dst_ip, _ACK, now)

    def _record(self, dst_ip: str, flag: str, now: float) -> None:
        window = self._windows.get(dst_ip)
        if window is None:
            window = SlidingWindow(self._window)
            self._windows[dst_ip] = window

        window.add(now, key=flag)

        # Only a new SYN can push the ratio over the edge; no need to re-check
        # the threshold when an ACK arrives (it can only lower the ratio).
        if flag == _SYN:
            self._evaluate(dst_ip, window, now)

    def _evaluate(self, dst_ip: str, window: SlidingWindow, now: float) -> None:
        if self._cooldown.is_cooling(dst_ip, now):
            return

        syn = window.count(_SYN)
        if syn < self._min_syn:
            return

        ack   = window.count(_ACK)
        ratio = syn / max(ack, 1)

        severity = None
        if ratio > self._ratio_high:
            severity = "HIGH"
        elif ratio > self._ratio_medium:
            severity = "MEDIUM"

        if severity:
            self._emit(dst_ip, severity, syn, ack, ratio)
            self._cooldown.mark(dst_ip, now)
            window.clear()

    def _emit(self, dst_ip: str, severity: str, syn: int, ack: int, ratio: float) -> None:
        self._alerts.put(Alert(
            type      = "SYN_FLOOD",
            severity  = severity,
            src_ip    = None,   # source is spoofed in a SYN flood – the target is what matters
            timestamp = time.time(),
            details   = {
                "dst_ip":    dst_ip,
                "syn_count": syn,
                "ack_count": ack,
                "ratio":     round(ratio, 1),
            },
        ))
