from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static


class StatsBar(Horizontal):
    """Top status bar – shows live packet count and alert count."""

    def compose(self) -> ComposeResult:
        yield Static("Packets: 0",  id="stat-packets")
        yield Static("Alerts:  0",  id="stat-alerts")
        yield Static("SENTINEL IDS", id="stat-title")

    def update_packets(self, count: int) -> None:
        self.query_one("#stat-packets", Static).update(f"Packets: {count:,}")

    def update_alerts(self, count: int) -> None:
        self.query_one("#stat-alerts", Static).update(f"Alerts:  {count}")
