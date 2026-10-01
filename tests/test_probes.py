"""vulns.parse_banner tests with real-world banner fixtures."""
import pytest

from reecanner import vulns


@pytest.fixture(autouse=True)
def no_nmap_parser(monkeypatch):
    """Disable the nmap-probes parser so generic regex results are deterministic."""
    monkeypatch.setattr(vulns, "get_nmap_parser", lambda: None)
    yield


def test_apache_banner():
    assert vulns.parse_banner("Apache/2.4.41 (Ubuntu)") == "Apache 2.4.41"


def test_apache_longer_version():
    assert vulns.parse_banner("Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips") == "Apache 2.4.6"


def test_nginx_banner():
    assert vulns.parse_banner("nginx/1.18.0") == "nginx 1.18.0"


def test_nginx_space_variant():
    assert vulns.parse_banner("nginx 1.24.0") == "nginx 1.24.0"


def test_vsftpd_banner():
    assert vulns.parse_banner("220 (vsFTPd 3.0.3)") == "vsFTPd 3.0.3"


def test_openssh_banner_generic():
    # the generic regex cannot parse OpenSSH_x.y style banners
    assert vulns.parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1") is None


def test_microsoft_iis():
    assert vulns.parse_banner("Microsoft-IIS/10.0") == "Microsoft-IIS 10.0"


def test_empty_and_none():
    assert vulns.parse_banner("") is None
    assert vulns.parse_banner(None) is None


def test_protocol_strings_skipped():
    # bare protocol tokens like HTTP/1.1 must not be reported as software
    assert vulns.parse_banner("HTTP/1.1") is None


def test_openssh_with_nmap_parser():
    """With the real nmap probes file, OpenSSH banners should be identified."""
    # load the data file directly: the autouse fixture stubs out
    # vulns.get_nmap_parser, so go through NmapProbes itself.
    from reecanner.nmap_probes import NmapProbes
    parser = NmapProbes()
    assert parser.patterns, "nmap-service-probes data file must ship with the package"
    result = parser.parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n\r\n")
    assert result is not None and "OpenSSH" in result
