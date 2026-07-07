from dataclasses import dataclass, field
from typing import Any


@dataclass
class Alert:
    """Represents a single detection event produced by any detector."""
    type:      str
    severity:  str
    # None when the source is spoofed and unusable – a SYN flood forges its
    # source, so the target (in details) is what matters, not src_ip.
    src_ip:    str | None
    timestamp: float
    details:   dict[str, Any] = field(default_factory=dict)
