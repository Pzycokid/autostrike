import pytest

from autostrike.scope import Scope, ScopeError
from autostrike.transport import LiveTransport


def test_private_ranges_allowed():
    s = Scope(["10.0.0.0/30", "192.168.56.10"])
    assert s.contains("10.0.0.1")
    assert s.contains("192.168.56.10")
    assert not s.contains("192.168.56.11")


def test_public_range_rejected_by_default():
    with pytest.raises(ScopeError, match="public"):
        Scope(["8.8.8.0/30"])


def test_public_range_allowed_only_with_flag():
    assert Scope(["8.8.8.8/32"], allow_public=True).contains("8.8.8.8")


def test_oversized_scope_rejected():
    with pytest.raises(ScopeError, match="limit"):
        Scope(["10.0.0.0/16"])


def test_empty_and_comments():
    with pytest.raises(ScopeError, match="empty"):
        Scope(["# only a comment", ""])
    assert Scope(["127.0.0.1  # loopback"]).contains("127.0.0.1")


def test_addresses_handles_single_host_and_subnet():
    assert list(Scope(["10.1.1.7/32"]).addresses()) == ["10.1.1.7"]
    assert list(Scope(["10.1.1.0/30"]).addresses()) == ["10.1.1.1", "10.1.1.2"]


def test_live_transport_refuses_out_of_scope_targets():
    t = LiveTransport(Scope(["127.0.0.1/32"]))
    with pytest.raises(ScopeError):
        t.probe("10.9.9.9", 22)
    with pytest.raises(ScopeError):
        t.banner("10.9.9.9", 22)
