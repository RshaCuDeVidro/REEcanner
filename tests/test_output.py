"""Output writer tests: JsonWriter, XmlWriter, GrepWriter, SqliteWriter."""
import json
import sqlite3
import xml.etree.ElementTree as ET

from reecanner.output import GrepWriter, JsonWriter, SqliteWriter, XmlWriter


def test_json_lines_valid(tmp_path, sample_results):
    path = tmp_path / "out.jsonl"
    JsonWriter.write_lines(str(path), sample_results)
    lines = path.read_text().strip().split("\n")
    assert len(lines) == len(sample_results)
    for line, orig in zip(lines, sample_results):
        rec = json.loads(line)
        assert rec["ip"] == orig["ip"]
        assert rec["port"] == orig["port"]


def test_json_document_valid(tmp_path, sample_results):
    path = tmp_path / "out.json"
    meta = JsonWriter.default_meta(1.5, [80, 443], len(sample_results))
    JsonWriter.write_document(str(path), sample_results, meta)
    doc = json.loads(path.read_text())
    assert doc["scan"]["total_found"] == len(sample_results)
    assert doc["scan"]["ports"] == [80, 443]
    assert len(doc["hosts"]) == len(sample_results)


def test_xml_escaping(tmp_path):
    """Remote-sourced strings with XML metacharacters must be escaped and parse back."""
    nasty = [
        {"ip": "203.0.113.9", "port": 80, "proto": "tcp",
         "banner": "<script>alert('x')</script> & \"quotes\""},
    ]
    path = tmp_path / "out.xml"
    meta = JsonWriter.default_meta(0.5, [80], 1)
    XmlWriter.write(str(path), nasty, meta)
    raw = path.read_bytes().decode("utf-8")
    assert "<script>" not in raw  # raw tag injection must not survive
    tree = ET.parse(str(path))
    host = tree.getroot().find("host")
    assert host.get("banner") == "<script>alert('x')</script> & \"quotes\""
    assert host.get("ip") == "203.0.113.9"


def test_xml_structure(tmp_path, sample_results):
    path = tmp_path / "out.xml"
    meta = JsonWriter.default_meta(0.5, [443], len(sample_results))
    XmlWriter.write(str(path), sample_results, meta)
    tree = ET.parse(str(path))
    root = tree.getroot()
    assert root.tag == "reecanner"
    assert root.find("scan").get("found") == str(len(sample_results))
    assert len(root.findall("host")) == len(sample_results)


def test_grep_format(tmp_path, sample_results):
    path = tmp_path / "out.grep"
    GrepWriter.write(str(path), sample_results)
    lines = path.read_text().splitlines()
    assert lines[0].startswith("# reecanner scan")
    body = lines[1:]
    assert len(body) == len(sample_results)
    for line, orig in zip(body, sample_results):
        assert f"Host: {orig['ip']}" in line
        assert f"Port: {orig['port']}/open/{orig['proto']}" in line
    assert "OpenSSH" in body[1]  # banner survives in the extras column


def test_sqlite_schema_and_rows(tmp_path, sample_results):
    path = tmp_path / "out.sqlite"
    SqliteWriter.write(str(path), sample_results)
    conn = sqlite3.connect(str(path))
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(hosts)")]
        for expected in ("ip", "port", "proto", "service", "hostname", "os",
                         "banner", "title", "status", "server", "redirect",
                         "vulnerabilities", "tls_domains"):
            assert expected in cols
        rows = conn.execute("SELECT ip, port, proto, service FROM hosts ORDER BY port").fetchall()
        assert len(rows) == len(sample_results)
        assert rows[0][0] == "203.0.113.8"  # port 22 sorts first
        assert rows[0][1] == 22
        assert rows[1][2] == "tcp"
    finally:
        conn.close()
