from dataclasses import dataclass, field
from typing import Any


@dataclass
class Alert:
    """Represents a single detection event produced by any detector."""
    type:      str
    severity:  str
    src_ip:    str | None
    timestamp: float
    details:   dict[str, Any] = field(default_factory=dict)
