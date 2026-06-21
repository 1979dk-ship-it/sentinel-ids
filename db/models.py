"""ORM models – the persistence shape of the data.

AlertRecord is the stored counterpart of the in-memory Alert dataclass
(core/alerts/alert.py). The dataclass is the message passed on the queue;
this is the row written to disk.
"""
from typing import Any

from sqlalchemy import JSON, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


class AlertRecord(Base):
    """One persisted detection event. Maps to the `alerts` table."""
    __tablename__ = "alerts"

    id:        Mapped[int]            = mapped_column(primary_key=True)
    timestamp: Mapped[float]          = mapped_column(Float, index=True)
    type:      Mapped[str]            = mapped_column(String, index=True)
    severity:  Mapped[str]            = mapped_column(String)
    src_ip:    Mapped[str]            = mapped_column(String, index=True)
    details:   Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
