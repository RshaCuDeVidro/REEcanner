"""ScannerConfig / Scanner constructor tests (offline: network discovery is stubbed)."""
import pytest

import reecanner.scanner as scanner_mod
from reecanner.scanner import Scanner, ScannerConfig
from reecanner.utils import BlacklistManager, InclusionManager


@pytest.fixture
def offline(monkeypatch):
    """Stub out network discovery so Scanner() can be constructed anywhere."""
    monkeypatch.setattr(scanner_mod, "get_net_info", lambda: (None, None, None))
    monkeypatch.setattr(Scanner, "_get_local_ip", lambda self: "127.0.0.1")


@pytest.fixture
def managers():
    inc = InclusionManager(["203.0.113.0/24"], seed=42)
    bl = BlacklistManager(include_recommended=False, allow_private=True)
    return inc, bl


def test_defaults():
    cfg = ScannerConfig()
    assert cfg.ports == [80]
    assert cfg.rate_limit == 1000
    assert cfg.workers is None
    assert cfg.limit == 0
    assert cfg.wait == 3.0
    assert cfg.adaptive_grace == 10.0
    assert cfg.udp_payload == "auto"
    assert cfg.user_agent == "reecanner/1.0"
    assert cfg.ping_sweep is False
    assert cfg.status_json is None
    assert cfg.blacklist_manager is None
    assert cfg.inclusion_manager is None


def test_unknown_kwargs_raise_typeerror(offline, managers):
    with pytest.raises(TypeError, match="unknown Scanner arguments"):
        Scanner(bogus_argument=1)


def test_kwargs_override(offline, managers):
    inc, bl = managers
    s = Scanner(ports=[80, 443], rate_limit=4321, inclusion_manager=inc,
                blacklist_manager=bl, quiet=True)
    assert s.ports == [80, 443]
    assert s.rate_limit == 4321
    assert s.quiet is True
    assert s.seed == 42


def test_config_object(offline, managers):
    inc, bl = managers
    cfg = ScannerConfig(ports=[22], rate_limit=99, inclusion_manager=inc,
                        blacklist_manager=bl)
    s = Scanner(cfg)
    assert s.ports == [22]
    assert s.rate_limit == 99


def test_udp_payload_resolution(offline, managers):
    from reecanner.scanner import UDP_PAYLOAD_ORDER, UDP_PAYLOADS
    inc, bl = managers
    s = Scanner(inclusion_manager=inc, blacklist_manager=bl, udp=True,
                udp_payload="auto")
    assert s.udp_payloads == [UDP_PAYLOADS[k] for k in UDP_PAYLOAD_ORDER]
    s2 = Scanner(inclusion_manager=inc, blacklist_manager=bl, udp=True,
                 udp_payload="ntp")
    assert s2.udp_payloads == [UDP_PAYLOADS["ntp"]]


def test_ping_sweep_forces_zero_port(offline, managers):
    inc, bl = managers
    s = Scanner(inclusion_manager=inc, blacklist_manager=bl, ping_sweep=True,
                ports=[80, 443])
    assert s.ports == [0]
    assert s.ping_sweep is True
