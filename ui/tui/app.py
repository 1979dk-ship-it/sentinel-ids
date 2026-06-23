import queue

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Header, Footer

from core.alerts.alert import Alert
from ui.tui.widgets.stats_bar import StatsBar
from ui.tui.widgets.packet_log import PacketLog
from ui.tui.widgets.alert_panel import AlertPanel


class SentinelApp(App):
    CSS_PATH = "sentinel.tcss"
    TITLE = "SENTINEL IDS"

    BINDINGS = [
        ("q", "quit",          "Quit"),
        ("p", "toggle_pause",  "Pause log"),
        ("f", "toggle_filter", "Filter"),
    ]

    def __init__(self, packet_queue: queue.Queue, session_factory):
        super().__init__()
        self._packet_queue   = packet_queue
        self._session_factory = session_factory
        self._packet_count   = 0
        self._alert_count    = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatsBar(id="stats-bar")
        with Horizontal(id="main-panel"):
            yield PacketLog(id="packet-log")
            yield AlertPanel(id="alert-panel")
        yield Footer()

    def on_mount(self) -> None:
        # Drain the packet queue every 500 ms from the async event loop.
        # No call_from_thread needed here – set_interval runs in the event loop.
        self.set_interval(0.5, self._drain_packet_queue)

    async def _drain_packet_queue(self) -> None:
        packet_log = self.query_one(PacketLog)
        stats_bar  = self.query_one(StatsBar)
        drained    = 0
        while drained < 50:   # cap per tick to avoid starving the event loop
            try:
                packet = self._packet_queue.get_nowait()
            except queue.Empty:
                break
            self._packet_count += 1
            packet_log.add_packet(packet)
            drained += 1
        if drained:
            stats_bar.update_packets(self._packet_count)

    def push_alert(self, alert: Alert) -> None:
        # Called via app.call_from_thread() from the alert_loop thread.
        self._alert_count += 1
        self.query_one(AlertPanel).add_alert(alert)
        self.query_one(StatsBar).update_alerts(self._alert_count)

    def action_toggle_pause(self) -> None:
        self.query_one(PacketLog).toggle_pause()

    def action_toggle_filter(self) -> None:
        self.query_one(PacketLog).toggle_filter()

    def action_quit(self) -> None:
        self.exit()
