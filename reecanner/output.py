"""Output writers: JSON/JSONL, XML, grepable, SQLite and the rich summary table."""
from __future__ import annotations

import json
import logging
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def _flatten_result(r: dict) -> dict:
    """Return a copy of a result dict with nested structures flattened to scalars."""
    out = {}
    for k, v in r.items():
        if k == 'exploits':
            out['vulns_count'] = len(v)
        elif isinstance(v, (list, dict)):
            out[k] = json.dumps(v)
        elif isinstance(v, (str, int, float)):
            out[k] = v
    return out


class JsonWriter:
    """Writes results as JSON lines or as a single JSON document."""

    @staticmethod
    def write_lines(path: str, results: list) -> None:
        with open(path, 'w') as f:
            for r in results:
                f.write(json.dumps(r) + "\n")

    @staticmethod
    def write_document(path: str, results: list, meta: dict) -> None:
        with open(path, 'w') as f:
            json.dump({"scan": meta, "hosts": results}, f, indent=2)

    @staticmethod
    def default_meta(duration_s: float, ports: list, total_found: int) -> dict:
        return {
            "time": datetime.now(timezone.utc).isoformat(),
            "duration": f"{duration_s:.2f}s",
            "ports": ports,
            "total_found": total_found,
        }


class XmlWriter:
    """Writes results as XML. All remote-sourced data is properly escaped."""

    @staticmethod
    def write(path: str, results: list, meta: dict) -> None:
        root = ET.Element("reecanner")
        scan = ET.SubElement(root, "scan")
        for k in ("time", "duration"):
            scan.set(k, str(meta.get(k, "")))
        scan.set("ports", str(len(meta.get("ports", []))))
        scan.set("found", str(meta.get("total_found", 0)))
        for r in results:
            host = ET.SubElement(root, "host")
            for k, v in _flatten_result(r).items():
                # ElementTree escapes attribute values (& < > ") on serialize
                host.set(str(k), str(v))
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        with open(path, 'wb') as f:
            tree.write(f, encoding='utf-8', xml_declaration=True)


class GrepWriter:
    """Writes results in nmap-style grepable format."""

    @staticmethod
    def write(path: str, results: list) -> None:
        with open(path, 'w') as f:
            f.write(f"# reecanner scan {datetime.now(timezone.utc).isoformat()}\n")
            for r in results:
                os_info = r.get('os', '')
                svc = r.get('service', '')
                hostname = r.get('hostname', '')
                banner = r.get('banner', '')
                tls_doms = ','.join(r.get('tls_domains', [])) if r.get('tls_domains') else ''
                proto = r.get('proto', 'tcp')
                extra = [x for x in [os_info, svc, hostname, banner, tls_doms] if x]
                f.write(f"Host: {r['ip']} Port: {r['port']}/open/{proto} {' | '.join(extra)}\n")


class SqliteWriter:
    """Writes results to a SQLite database."""

    @staticmethod
    def write(path: str, results: list) -> None:
        conn = sqlite3.connect(path)
        try:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS hosts
                           (ip TEXT, port INTEGER, proto TEXT, service TEXT, hostname TEXT,
                            os TEXT, banner TEXT, title TEXT, status INTEGER, server TEXT,
                            redirect TEXT, vulnerabilities TEXT, tls_domains TEXT)''')
            for r in results:
                vulns_json = json.dumps(r.get('exploits', [])) if r.get('exploits') else None
                tls_json = json.dumps(r.get('tls_domains', [])) if r.get('tls_domains') else None
                cursor.execute("""INSERT INTO hosts (ip, port, proto, service, hostname, os, banner,
                                                      title, status, server, redirect, vulnerabilities, tls_domains)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (r.get('ip'), r.get('port'), r.get('proto'), r.get('service'),
                                r.get('hostname'), r.get('os'), r.get('banner'), r.get('title'),
                                r.get('status'), r.get('server'), r.get('redirect'),
                                vulns_json, tls_json))
            conn.commit()
        finally:
            conn.close()


class RichTableWriter:
    """Renders the end-of-scan rich summary tables (hosts + vulnerabilities)."""

    def __init__(self, console):
        self.console = console

    def write(self, results: list, probe_results: Optional[list] = None,
              show_vulns: bool = False) -> None:
        from rich.markup import escape
        from rich.table import Table

        probe_map = {}
        for pr in (probe_results or []):
            key = (pr.get('ip'), pr.get('port'))
            probe_map[key] = pr

        has_probes = bool(probe_map)
        has_domain = any('hostname' in pr or 'tls_domains' in pr for pr in probe_map.values())

        table = Table(title="scan results", border_style="dim", show_lines=False, pad_edge=False)
        table.add_column("IP", style="bold white", min_width=15)
        if has_domain:
            table.add_column("Domain", style="yellow")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service", style="green")
        if has_probes:
            table.add_column("Version", style="magenta")

        for r in results:
            ip = r.get('ip', '')
            port = str(r.get('port', ''))
            proto = r.get('proto', 'tcp')
            if proto == 'udp':
                port += '/udp'
            svc = r.get('service', '')

            row = [ip]

            key = (ip, r.get('port'))
            pr = probe_map.get(key, {})

            if has_domain:
                doms = []
                if 'hostname' in pr:
                    doms.append(pr['hostname'])
                if 'tls_domains' in pr:
                    doms.extend(pr['tls_domains'])
                unique_doms = []
                for d in doms:
                    if d not in unique_doms:
                        unique_doms.append(d)

                dom_str = ", ".join(unique_doms)
                if len(dom_str) > 40:
                    dom_str = dom_str[:37] + "..."
                # remote-sourced: escape so bracketed values are not parsed as
                # rich markup (a hostile banner/cert would otherwise crash here)
                row.append(escape(dom_str))

            row.extend([port, escape(svc)])

            if has_probes:
                version = pr.get('server', '')
                if not version and 'banner' in pr:
                    version = pr['banner'][:50]
                row.append(escape(version))

            table.add_row(*row)

        self.console.print()
        self.console.print(table)

        if not has_probes:
            return

        vuln_hosts = []
        for r in results:
            key = (r.get('ip'), r.get('port'))
            pr = probe_map.get(key, {})
            exploits = pr.get('exploits', [])
            if exploits:
                vuln_hosts.append((r, exploits))

        if vuln_hosts:
            self.console.print()
            vtable = Table(title="vulnerabilities", border_style="red", pad_edge=False)
            vtable.add_column("Host", style="bold white")
            vtable.add_column("ID", style="red")
            vtable.add_column("CVE", style="yellow")
            vtable.add_column("Title", style="dim")

            for r, exploits in vuln_hosts:
                host = f"{r.get('ip')}:{r.get('port')}"
                for ex in exploits:
                    vtable.add_row(
                        host,
                        escape(ex.get('id', '')),
                        escape(ex.get('cve', '')),
                        escape(ex.get('title', '')[:70])
                    )

            self.console.print(vtable)
        elif show_vulns:
            self.console.print("\n[bold yellow][*][/bold yellow] no known vulnerabilities found for captured banners")
