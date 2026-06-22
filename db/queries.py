"""Database operations – the read/write functions the app calls.

Keeping these here (instead of inline in main.py) means the persistence
logic has one home and main.py stays a thin assembly layer.
"""
import time

from sqlalchemy import select

from core.alerts.alert import Alert
from db.models import AlertRecord


def save_alert(session_factory, alert: Alert) -> None:
    """Persists a single Alert as a row in the alerts table.

    A fresh session per alert is fine: alerts are rare events, not per-packet,
    so the open/commit/close overhead is negligible.
    """
    with session_factory() as session:
        record = AlertRecord(
            timestamp = alert.timestamp,
            type      = alert.type,
            severity  = alert.severity,
            src_ip    = alert.src_ip,
            details   = alert.details,
        )
        session.add(record)
        session.commit()


def alerts_since(session_factory, seconds: int = 3600, now: float | None = None) -> list[AlertRecord]:
    """Returns alerts from the last `seconds` (default: the past hour), newest first.

    `now` is injectable so the query can be tested against a fixed clock
    instead of depending on the real wall-clock time. The timestamp filter
    rides the index on AlertRecord.timestamp.
    """
    if now is None:
        now = time.time()
    cutoff = now - seconds
    with session_factory() as session:
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.timestamp >= cutoff)
            .order_by(AlertRecord.timestamp.desc())
        )
        return list(session.scalars(stmt).all())
