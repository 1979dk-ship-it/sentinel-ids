import queue
import signal
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
from core.detectors.syn_flood import SynFloodDetector
from core.response.engine import ResponseEngine
from core.response.firewall import FirewallManager
from db.database import init_db
from db.queries import save_alert
from ui.tui.app import SentinelApp


def _load_config(path: str = "config/config.yaml") -> dict:
    """Loads runtime configuration parameters."""
    with open(path) as f:
        return yaml.safe_load(f)


def _alert_loop(alert_queue: queue.Queue, session_factory, app: SentinelApp) -> None:
    """Persists alerts to DB and pushes them to the TUI via call_from_thread.

    Each alert is handled in isolation: a failure on one alert (a transient DB
    error, an unexpected payload) is reported and skipped, never allowed to kill
    the loop – otherwise the first bad alert would silence persistence and the
    live feed for every alert that follows.
    """
    while True:
        try:
            alert = alert_queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            save_alert(session_factory, alert)
            app.call_from_thread(app.push_alert, alert)
        except Exception as exc:
            try:
                app.call_from_thread(app.notify, f"Alert error: {exc}", severity="error")
            except Exception:
                pass


def main() -> None:
    config    = _load_config()
    interface = config["network"]["interface"]
    if interface == "auto":
        interface = None

    # Persistence – build the DB and a session factory from config
    db_path      = config["database"]["path"]
    SessionLocal = init_db(db_path)

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
        threshold_ports  = ps_cfg["threshold_ports"],
        window_seconds   = ps_cfg["window_seconds"],
        cooldown_seconds = ps_cfg["cooldown_seconds"],
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

    syn_cfg      = config["detectors"]["syn_flood"]
    syn_detector = SynFloodDetector(
        pkt_queue.subscribe(),
        alert_queue,
        ratio_medium     = syn_cfg["ratio_medium"],
        ratio_high       = syn_cfg["ratio_high"],
        window_seconds   = syn_cfg["window_seconds"],
        min_syn          = syn_cfg["min_syn"],
        cooldown_seconds = syn_cfg["cooldown_seconds"],
    )

    resp_cfg        = config["response"]
    firewall        = FirewallManager(direction=resp_cfg["direction"])
    response_engine = ResponseEngine(firewall, SessionLocal, whitelist=resp_cfg["whitelist"])

    app = SentinelApp(
        packet_queue=consumer,
        session_factory=SessionLocal,
        response_engine=response_engine,
    )

    def _shutdown(sig, frame):
        capture.stop()
        ps_detector.stop()
        arp_detector.stop()
        bf_detector.stop()
        dns_detector.stop()
        syn_detector.stop()
        app.exit()

    signal.signal(signal.SIGINT, _shutdown)

    capture.start()
    ps_detector.start()
    arp_detector.start()
    bf_detector.start()
    dns_detector.start()
    syn_detector.start()

    threading.Thread(
        target=_alert_loop,
        args=(alert_queue, SessionLocal, app),
        daemon=True,
    ).start()

    app.run()


if __name__ == "__main__":
    main()