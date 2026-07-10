import queue
import threading
import time

from core.alerts.alert import Alert
from core.utils.welford import Welford
from db.queries import load_baselines, save_baselines


class BaselineDetector:
    """Per-IP statistical anomaly detector.

    Counts each source's packets into fixed time-interval buckets; a completed
    bucket's count is one sample. Once an IP has min_samples of history, a new
    sample far above its own learned mean (z-score over z_medium) raises an alert.
    Anomalous samples are excluded from the baseline so a slow ramp cannot poison
    it, and idle IPs are evicted so a spoofed source cannot grow memory unbounded.
    """

    def __init__(
        self,
        packet_queue:       queue.Queue,
        alert_queue:        queue.Queue,
        interval_seconds:   int   = 10,
        min_samples:        int   = 30,
        z_medium:           float = 3.0,
        z_high:             float = 5.0,
        idle_evict_seconds: int   = 3600,
        session_factory           = None,
    ):
        self._packets     = packet_queue
        self._alerts      = alert_queue
        self._interval    = interval_seconds
        self._min_samples = min_samples
        self._z_medium    = z_medium
        self._z_high      = z_high
        self._idle_evict  = idle_evict_seconds
        self._session_factory = session_factory

        self._stats:     dict[str, Welford] = {}
        self._current:   dict[str, list]    = {}   # src_ip -> [interval_index, count]
        self._last_seen: dict[str, float]   = {}
        self._last_sweep: float = 0.0

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._session_factory is not None:
            self._restore()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-baseline",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._session_factory is not None:
            self._flush(time.time())

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                packet = self._packets.get(timeout=1)
                self._process(packet)
            except queue.Empty:
                continue

    def _process(self, packet: dict) -> None:
        src_ip = packet.get("src_ip")
        if not src_ip:
            return
        now = packet.get("timestamp") or time.time()

        self._maybe_sweep(now)
        self._last_seen[src_ip] = now

        interval = int(now // self._interval)
        cur      = self._current.get(src_ip)
        if cur is None:
            self._current[src_ip] = [interval, 1]
        elif interval > cur[0]:
            self._finalize(src_ip, cur[1], now)   # the previous bucket is complete
            self._current[src_ip] = [interval, 1]
        else:
            cur[1] += 1

    def _finalize(self, src_ip: str, sample: int, now: float) -> None:
        w = self._stats.get(src_ip)
        if w is None:
            w = Welford()
            self._stats[src_ip] = w

        if w.n >= self._min_samples and w.std > 0:
            z = (sample - w.mean) / w.std
            if z >= self._z_medium:
                severity = "HIGH" if z >= self._z_high else "MEDIUM"
                self._emit(src_ip, severity, sample, w, z, now)
                return   # anomalous -> excluded from the baseline (poison resistance)

        w.update(sample)

    def _emit(self, src_ip: str, severity: str, sample: int, w: Welford, z: float, now: float) -> None:
        self._alerts.put(Alert(
            type      = "BASELINE_ANOMALY",
            severity  = severity,
            src_ip    = src_ip,
            timestamp = now,
            details   = {
                "metric":   "packet_rate",
                "observed": sample,
                "mean":     round(w.mean, 1),
                "std":      round(w.std, 1),
                "z_score":  round(z, 1),
            },
        ))

    def _maybe_sweep(self, now: float) -> None:
        """Evict IPs idle past idle_evict_seconds, at most once per interval."""
        if now - self._last_sweep < self._interval:
            return
        cutoff = now - self._idle_evict
        stale  = [ip for ip, seen in self._last_seen.items() if seen < cutoff]
        for ip in stale:
            self._stats.pop(ip, None)
            self._current.pop(ip, None)
            del self._last_seen[ip]
        self._last_sweep = now
        if self._session_factory is not None:
            self._flush(now)

    def _restore(self) -> None:
        for ip, (n, mean, m2) in load_baselines(self._session_factory).items():
            self._stats[ip]     = Welford.from_state(n, mean, m2)
            self._last_seen[ip] = time.time()

    def _flush(self, now: float) -> None:
        if not self._stats:
            return
        save_baselines(
            self._session_factory,
            {ip: w.state() for ip, w in self._stats.items()},
            now,
        )
