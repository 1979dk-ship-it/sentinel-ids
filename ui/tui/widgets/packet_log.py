from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog

SENTINEL_PROTOCOLS = {"TCP", "UDP", "ARP", "DNS"}


class PacketLog(Widget):
    """Scrolling live packet feed with pause and protocol-filter toggles."""

    BORDER_TITLE = "Packet Log"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._paused          = False
        self._filter_sentinel = False

    def compose(self) -> ComposeResult:
        yield RichLog(highlight=True, markup=True, max_lines=200, id="pkt-richlog")

    def add_packet(self, packet: dict) -> None:
        if self._paused:
            return

        proto = (packet.get("protocol") or "OTHER").upper()
        if self._filter_sentinel and proto not in SENTINEL_PROTOCOLS:
            return

        src  = packet.get("src_ip") or packet.get("src_mac") or "?"
        dst  = packet.get("dst_ip") or packet.get("dst_mac") or "?"
        size = packet.get("size", 0)

        color = {
            "TCP": "cyan", "UDP": "blue",
            "ARP": "yellow", "DNS": "green",
        }.get(proto, "white")

        line = f"[{color}]{proto:<5}[/{color}]  {src:<18} → {dst:<18}  {size}b"

        if packet.get("src_port") is not None:
            line += f"  :{packet['src_port']} → :{packet['dst_port']}"
        if packet.get("flags"):
            line += f"  [{packet['flags']}]"

        self.query_one(RichLog).write(line)

    def toggle_pause(self) -> None:
        self._paused = not self._paused
        status = "[yellow]PAUSED[/yellow]" if self._paused else "[green]LIVE[/green]"
        self.query_one(RichLog).write(f"── {status} ──")

    def toggle_filter(self) -> None:
        self._filter_sentinel = not self._filter_sentinel
        mode = "[cyan]SENTINEL[/cyan] (TCP/UDP/ARP/DNS)" if self._filter_sentinel else "[white]ALL[/white]"
        self.query_one(RichLog).write(f"── Filter: {mode} ──")
