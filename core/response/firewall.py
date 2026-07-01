"""FirewallManager – the OS-level 'hands' of the Response Engine.

Wraps Windows Firewall (`netsh advfirewall`) behind two methods, block() and
unblock(). It holds no policy: no whitelist, no database, no notion of an alert.
It only turns "block this IP" into a firewall rule and back. Isolating netsh
here means nothing else in the app shells out directly — the same way
PacketParser isolates Scapy from the detectors.
"""
import subprocess

# Every rule we create is named with this prefix + the IP, so unblock() can
# find and delete exactly what block() added, and our rules are easy to spot.
_RULE_PREFIX = "SENTINEL_block_"


class FirewallManager:
    """Adds/removes Windows Firewall rules that drop traffic for a single IP."""

    def __init__(self, direction: str = "in"):
        # "in"  – drop their packets arriving at us (the usual defensive move)
        # "out" – drop our packets going to them
        # "both"– two rules, one each way
        self._direction = direction

    def block(self, ip: str) -> bool:
        """Add a rule dropping traffic for `ip`. Returns True if netsh succeeded."""
        name = self._rule_name(ip)
        directions = ["in", "out"] if self._direction == "both" else [self._direction]
        ok = True
        for d in directions:
            ok = self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", f"dir={d}", "action=block", f"remoteip={ip}",
            ]) and ok
        return ok

    def unblock(self, ip: str) -> bool:
        """Delete the rule(s) previously added for `ip`. Returns True on success.

        `delete rule name=X` removes every rule with that name, so a single call
        clears both the inbound and outbound rules when direction was "both".
        """
        return self._run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={self._rule_name(ip)}",
        ])

    def _rule_name(self, ip: str) -> str:
        return f"{_RULE_PREFIX}{ip}"

    def _run(self, args: list[str]) -> bool:
        """Run a netsh command. args is a LIST, so no shell parses the IP — this
        is what closes the command-injection door on an attacker-controlled IP.
        Returns False (instead of raising) when netsh is missing or the command
        fails, e.g. when not running as Administrator, so callers can degrade.
        """
        try:
            result = subprocess.run(args, capture_output=True, text=True)
        except FileNotFoundError:
            return False  # netsh not present (e.g. not Windows)
        return result.returncode == 0
