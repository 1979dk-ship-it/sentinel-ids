"""ResponseEngine – the policy 'brain' of the response layer.

It decides whether an IP may be blocked (is there a source? whitelisted?
already blocked?) and then coordinates the two sides that do the real work:
the FirewallManager (the OS rule) and the blocked_ips table (the record).
It never touches netsh or SQL directly – it composes the pieces built for
those jobs, so the policy lives in exactly one place.
"""
from dataclasses import dataclass

from core.response.firewall import FirewallManager
from db.queries import is_blocked, record_block, record_unblock


@dataclass
class ActionResult:
    """Outcome of a block/unblock so the UI can report it in a single line."""
    ok: bool
    message: str


class ResponseEngine:
    """Blocks/unblocks IPs under a whitelist and current-state safety net."""

    def __init__(self, firewall: FirewallManager, session_factory, whitelist=None):
        self._firewall  = firewall
        self._sf        = session_factory
        self._whitelist = set(whitelist or [])

    def block(self, ip: str | None, reason: str, blocked_by: str = "user") -> ActionResult:
        """Block `ip` after the safety checks. If any check fails, nothing happens."""
        if not ip:
            # SYN flood and other spoofed-source attacks carry no real src_ip;
            # blocking a forged address would only punish an innocent host.
            return ActionResult(False, "No source IP to block (spoofed source?)")
        if ip in self._whitelist:
            return ActionResult(False, f"{ip} is whitelisted - refusing to block")
        if is_blocked(self._sf, ip):
            return ActionResult(False, f"{ip} is already blocked")
        if not self._firewall.block(ip):
            return ActionResult(False, f"Firewall rejected block for {ip} (run as admin?)")

        # Only record after the firewall actually accepted the rule, so the DB
        # never claims an IP is blocked when it isn't.
        record_block(self._sf, ip, reason, blocked_by)
        return ActionResult(True, f"Blocked {ip}")

    def unblock(self, ip: str) -> ActionResult:
        """Lift an existing block on `ip`."""
        if not is_blocked(self._sf, ip):
            return ActionResult(False, f"{ip} is not blocked")
        self._firewall.unblock(ip)
        record_unblock(self._sf, ip)
        return ActionResult(True, f"Unblocked {ip}")
