"""Unit tests for FirewallManager.

FirewallManager shells out to `netsh` via subprocess.run, so every test
monkeypatches subprocess.run with a fake that records the command it was asked
to run and returns a chosen exit code - no real firewall is ever touched.
"""
import subprocess
from types import SimpleNamespace

from core.response.firewall import FirewallManager


class _FakeRun:
    """Stand-in for subprocess.run: records each args list and returns a fake
    CompletedProcess with a configurable return code."""

    def __init__(self, returncode=0):
        self.returncode = returncode
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        return SimpleNamespace(returncode=self.returncode)


def test_block_builds_injection_safe_netsh_command(monkeypatch):
    fake = _FakeRun(returncode=0)
    monkeypatch.setattr(subprocess, "run", fake)

    ok = FirewallManager(direction="in").block("1.2.3.4")

    assert ok is True
    # The command is a LIST, so no shell parses the IP - this is what closes
    # the command-injection door on an attacker-controlled address.
    assert fake.calls == [[
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=SENTINEL_block_1.2.3.4", "dir=in", "action=block", "remoteip=1.2.3.4",
    ]]


def test_block_both_directions_issues_two_rules(monkeypatch):
    fake = _FakeRun(returncode=0)
    monkeypatch.setattr(subprocess, "run", fake)

    ok = FirewallManager(direction="both").block("1.2.3.4")

    assert ok is True
    assert len(fake.calls) == 2
    assert fake.calls[0][6] == "dir=in"
    assert fake.calls[1][6] == "dir=out"


def test_block_both_directions_false_if_one_rule_fails(monkeypatch):
    codes = iter([0, 1])   # inbound rule succeeds, outbound fails
    monkeypatch.setattr(subprocess, "run",
                        lambda args, **kw: SimpleNamespace(returncode=next(codes)))

    assert FirewallManager(direction="both").block("1.2.3.4") is False


def test_unblock_builds_delete_command(monkeypatch):
    fake = _FakeRun(returncode=0)
    monkeypatch.setattr(subprocess, "run", fake)

    ok = FirewallManager().unblock("1.2.3.4")

    assert ok is True
    assert fake.calls == [[
        "netsh", "advfirewall", "firewall", "delete", "rule",
        "name=SENTINEL_block_1.2.3.4",
    ]]


def test_block_returns_false_when_netsh_fails(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _FakeRun(returncode=1))   # e.g. not admin

    assert FirewallManager().block("1.2.3.4") is False


def test_block_returns_false_when_netsh_missing(monkeypatch):
    def raise_fnf(args, **kwargs):
        raise FileNotFoundError()   # netsh not present (e.g. not Windows)

    monkeypatch.setattr(subprocess, "run", raise_fnf)

    assert FirewallManager().block("1.2.3.4") is False


def test_block_returns_false_when_netsh_hangs(monkeypatch):
    def raise_timeout(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=5)   # netsh wedged, timed out

    monkeypatch.setattr(subprocess, "run", raise_timeout)

    assert FirewallManager().block("1.2.3.4") is False
