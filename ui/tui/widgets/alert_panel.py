from datetime import datetime

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog

from core.alerts.alert import Alert

_SEVERITY_COLOR = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def format_alert_line(alert: Alert, count: int) -> str:
    color = _SEVERITY_COLOR.get(alert.severity, "white")
    ts    = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
    line  = (
        f"[{color}][{alert.severity:<6}][/{color}] "
        f"{ts}  [{color}]{alert.type:<14}[/{color}] "
        f"src={alert.src_ip}"
    )
    if alert.details:
        extra = "  ".join(f"{k}={v}" for k, v in list(alert.details.items())[:2])
        line += f"  {extra}"
    if count > 1:
        line += f"  [bold]×{count}[/bold]"
    return line


class AlertPanel(Widget):
    """Right-side panel showing active alerts by severity, each with a repeat count."""

    BORDER_TITLE = "Active Alerts"

    def compose(self) -> ComposeResult:
        yield RichLog(highlight=True, markup=True, max_lines=100, id="alert-richlog")

    def render_episodes(self, episodes) -> None:
        log = self.query_one(RichLog)
        log.clear()
        for alert, count in episodes:
            log.write(format_alert_line(alert, count))
