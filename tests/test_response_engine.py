"""Unit tests for ResponseEngine - the block/unblock policy brain.

This combines both isolation styles: a fake firewall is injected through the
constructor (dependency injection), while the database is the real, file-backed
`session_factory` fixture from conftest. The engine composes the two, so we can
watch both what it told the firewall and what it wrote to the DB.
"""
from core.response.engine import ResponseEngine
from db.queries import is_blocked, record_block


class _FakeFirewall:
    """Records block/unblock calls; each returns a configurable success flag."""

    def __init__(self, block_ok=True, unblock_ok=True):
        self.block_ok = block_ok
        self.unblock_ok = unblock_ok
        self.blocked = []
        self.unblocked = []

    def block(self, ip):
        self.blocked.append(ip)
        return self.block_ok

    def unblock(self, ip):
        self.unblocked.append(ip)
        return self.unblock_ok


def test_block_succeeds_and_records(session_factory):
    fw = _FakeFirewall(block_ok=True)
    engine = ResponseEngine(fw, session_factory)

    result = engine.block("1.2.3.4", reason="port scan")

    assert result.ok is True
    assert fw.blocked == ["1.2.3.4"]                        # firewall was told to block
    assert is_blocked(session_factory, "1.2.3.4") is True   # and it was recorded


def test_block_with_no_ip_refuses(session_factory):
    fw = _FakeFirewall()
    engine = ResponseEngine(fw, session_factory)

    result = engine.block(None, reason="spoofed source")

    assert result.ok is False
    assert fw.blocked == []   # firewall never touched


def test_block_whitelisted_ip_refuses(session_factory):
    fw = _FakeFirewall()
    engine = ResponseEngine(fw, session_factory, whitelist=["10.0.0.1"])

    result = engine.block("10.0.0.1", reason="gateway")

    assert result.ok is False
    assert fw.blocked == []
    assert is_blocked(session_factory, "10.0.0.1") is False


def test_block_already_blocked_refuses(session_factory):
    fw = _FakeFirewall()
    engine = ResponseEngine(fw, session_factory)
    record_block(session_factory, "1.2.3.4", "earlier", "user", now=1000.0)

    result = engine.block("1.2.3.4", reason="again")

    assert result.ok is False
    assert fw.blocked == []   # the guard fires before the firewall is called


def test_block_when_firewall_fails_records_nothing(session_factory):
    fw = _FakeFirewall(block_ok=False)   # firewall rejects, e.g. not admin
    engine = ResponseEngine(fw, session_factory)

    result = engine.block("1.2.3.4", reason="scan")

    assert result.ok is False
    assert fw.blocked == ["1.2.3.4"]                         # the firewall WAS attempted
    assert is_blocked(session_factory, "1.2.3.4") is False   # but nothing was recorded


def test_unblock_when_not_blocked_refuses(session_factory):
    fw = _FakeFirewall()
    engine = ResponseEngine(fw, session_factory)

    result = engine.unblock("9.9.9.9")

    assert result.ok is False
    assert fw.unblocked == []


def test_unblock_succeeds(session_factory):
    fw = _FakeFirewall(block_ok=True)
    engine = ResponseEngine(fw, session_factory)
    engine.block("1.2.3.4", reason="scan")

    result = engine.unblock("1.2.3.4")

    assert result.ok is True
    assert fw.unblocked == ["1.2.3.4"]
    assert is_blocked(session_factory, "1.2.3.4") is False


def test_unblock_when_firewall_fails_keeps_block(session_factory):
    fw = _FakeFirewall(block_ok=True, unblock_ok=False)   # netsh delete fails, e.g. not admin
    engine = ResponseEngine(fw, session_factory)
    engine.block("1.2.3.4", reason="scan")

    result = engine.unblock("1.2.3.4")

    assert result.ok is False
    assert fw.unblocked == ["1.2.3.4"]                      # the firewall WAS attempted
    assert is_blocked(session_factory, "1.2.3.4") is True   # still blocked - the DB was not changed


def test_unblock_with_no_ip_refuses(session_factory):
    fw = _FakeFirewall()
    engine = ResponseEngine(fw, session_factory)

    result = engine.unblock(None)

    assert result.ok is False
    assert fw.unblocked == []   # firewall never touched
