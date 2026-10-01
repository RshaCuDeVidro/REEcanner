"""lookup_vulns with a mocked searchsploit subprocess."""
import json
import types

import pytest

from reecanner import vulns


@pytest.fixture(autouse=True)
def fake_searchsploit(monkeypatch):
    monkeypatch.setattr(vulns, "has_searchsploit", lambda: True)
    monkeypatch.setattr(vulns, "parse_banner",
                        lambda raw, port=None: "apache 2.4.49")
    # searchsploit_query is lru_cached: clear between tests so the mocked
    # subprocess results never leak across cases
    vulns.searchsploit_query.cache_clear()
    yield
    vulns.searchsploit_query.cache_clear()


def _fake_run(payload, returncode=0):
    def run(cmd, capture_output, text, timeout):
        assert cmd[:3] == ["searchsploit", "--json", "-t"]
        return types.SimpleNamespace(returncode=returncode, stdout=payload)
    return run


EXPLOITS = json.dumps({"RESULTS_EXPLOIT": [
    {"EDB-ID": "50123",
     "Title": "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
     "Path": "linux/remote/50123.py"},
    {"EDB-ID": "50124",
     "Title": "Apache 2.4.49 RCE",
     "Path": "linux/remote/50124.py"},
]})


def test_lookup_vulns_parses_results(monkeypatch):
    monkeypatch.setattr("subprocess.run", _fake_run(EXPLOITS))
    out = vulns.lookup_vulns("Apache/2.4.49 (Ubuntu)", port=80)
    assert [e["id"] for e in out] == ["EDB-50123", "EDB-50124"]
    assert out[0]["cve"] == "CVE-2021-41773"
    assert out[1]["path"] == "linux/remote/50124.py"


def test_lookup_vulns_dedupes_queries(monkeypatch):
    monkeypatch.setattr("subprocess.run", _fake_run(EXPLOITS))
    # banner and server parse to the same query: results must not duplicate
    out = vulns.lookup_vulns("Apache/2.4.49", port=80, server="Apache/2.4.49")
    assert [e["id"] for e in out] == ["EDB-50123", "EDB-50124"]


def test_lookup_vulns_searchsploit_failure(monkeypatch):
    monkeypatch.setattr("subprocess.run", _fake_run("", returncode=1))
    assert vulns.lookup_vulns("Apache/2.4.49", port=80) == []


def test_lookup_vulns_bad_json(monkeypatch):
    monkeypatch.setattr("subprocess.run", _fake_run("not json"))
    assert vulns.lookup_vulns("Apache/2.4.49", port=80) == []


def test_lookup_vulns_without_binary(monkeypatch):
    monkeypatch.setattr(vulns, "has_searchsploit", lambda: False)
    assert vulns.lookup_vulns("Apache/2.4.49", port=80) == []


def test_lookup_vulns_no_identifiable_software(monkeypatch):
    monkeypatch.setattr(vulns, "parse_banner", lambda raw, port=None: None)
    calls = []

    def run(*a, **k):
        calls.append(a)
        return types.SimpleNamespace(returncode=0, stdout="{}")

    monkeypatch.setattr("subprocess.run", run)
    assert vulns.lookup_vulns("random garbage banner", port=12345) == []
    assert calls == []
