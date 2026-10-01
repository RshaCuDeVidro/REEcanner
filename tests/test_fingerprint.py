"""guess_os() p0f-style heuristic tests."""
from reecanner.fingerprint import guess_os


def test_linux3_with_options():
    assert "Linux" in guess_os(60, 29200, mss=1460, wscale=7, has_ts=True)


def test_windows10_signature():
    # Windows 10 and 11 share nearly identical TCP signatures (TTL ~128,
    # window 64240, MSS 1460, wscale 8, no timestamps), so either guess is valid
    result = guess_os(120, 64240, mss=1460, wscale=8, has_ts=False)
    assert "Windows 10" in result or "Windows 11" in result


def test_macos_signature():
    assert "macOS" in guess_os(60, 65535, mss=1460, wscale=5, has_ts=True)


def test_cisco_signature():
    assert "Cisco" in guess_os(250, 4128, mss=1460)


def test_legacy_ttl_window_only():
    # old two-argument behavior still works
    assert "Linux" in guess_os(64, 5840)
    assert "Windows" in guess_os(128, 8192)


def test_printer_signature():
    assert "printer" in guess_os(255, 8760).lower() or "printer" in guess_os(64, 8760, mss=1460).lower()


def test_unknown_falls_back():
    assert guess_os(64, 12345) in ("Linux", "Linux/Unix")
    assert guess_os(200, 9999) == "Network device"
