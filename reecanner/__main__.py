#!/usr/bin/env python3
"""reecanner command line interface."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sqlite3
import sys
import time

from rich.console import Console

from reecanner.output import GrepWriter, JsonWriter, SqliteWriter, XmlWriter
from reecanner.ports import get_top_ports
from reecanner.scanner import (
    UDP_PAYLOAD_ORDER,
    Scanner,
    ScannerConfig,
    ensure_raw_permissions,
    get_iface_net_info,
)
from reecanner.utils import BlacklistManager, InclusionManager, parse_ports_list, resolve_asn

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="reecanner - fast ip/port scout")
    parser.add_argument("target", nargs="?", help="target cidr (e.g., 45.0.0.0/8). use - for stdin")
    parser.add_argument("-b", "--blacklist-file", type=argparse.FileType('r'))
    parser.add_argument("-s", "--source-port", type=int, default=0)
    parser.add_argument("-p", "--ports", default="80")
    parser.add_argument("-r", "--rate-limit", type=int, default=1000)
    parser.add_argument("-d", "--disable-recommended", action="store_true")
    parser.add_argument("-w", "--workers", type=int)
    parser.add_argument("-l", "--limit", type=int, default=0)
    parser.add_argument("-i", "--include")
    parser.add_argument("--include-file", type=argparse.FileType('r'))
    parser.add_argument("--scan-private", action="store_true", help="allow scanning private/local networks (e.g., 192.168.0.0/16)")
    parser.add_argument("-o", "--output")
    parser.add_argument("--output-append", metavar="FILE", help="stream results as JSON lines while scanning (append mode)")
    parser.add_argument("--seed", type=int, help="seed for the shuffler")
    parser.add_argument("--index", type=int, default=0, help="start index for the scan")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity (-v info, -vv debug)")
    parser.add_argument("--simple", action="store_true", help="bare IP or IP:PORT output for piping (no OS, no service)")
    parser.add_argument("--no-port", action="store_true", help="omit port from output (just show IP)")
    parser.add_argument("--override-safety", action="store_true", help="acknowledge risks and allow rate limits > 10000 pps")
    parser.add_argument("--shards", type=int, default=1, help="total number of shards for distributed scanning")
    parser.add_argument("--shard-id", type=int, default=0, help="id of this shard (0 to shards-1)")
    parser.add_argument("--checkpoint", help="path to checkpoint file to resume scan")
    parser.add_argument("--batch-size", type=int, default=4096, help="number of IPs to scan in each batch")
    parser.add_argument("--exclude", help="exclude IPs/CIDRs from scan (comma-separated)")
    parser.add_argument("--top-ports", type=int, metavar="N", help="scan top N most common ports (nmap-style)")
    parser.add_argument("--retries", type=int, default=1, help="number of times to retransmit each probe (default: 1)")
    parser.add_argument("--wait", type=float, default=3.0, help="seconds to wait for late responses after sending finishes (default: 3)")
    parser.add_argument("--resolve", action="store_true", help="reverse DNS resolve found IPs")
    parser.add_argument("--banners", action="store_true", help="grab banners from discovered services")
    parser.add_argument("--http-probe", action="store_true", help="HTTP probe open web ports (title, status, server)")
    parser.add_argument("--vulns", action="store_true", help="search exploits via searchsploit for discovered services")
    parser.add_argument("--udp", action="store_true", help="UDP scan mode instead of TCP SYN")
    parser.add_argument("--udp-payload", choices=["auto"] + list(UDP_PAYLOAD_ORDER), default="auto",
                        help="UDP probe payload to send (default: auto = rotate all)")
    parser.add_argument("--ping-sweep", action="store_true", help="ICMP echo (ping) host discovery instead of TCP SYN")
    parser.add_argument("--adaptive", action="store_true", help="adaptive rate limiting based on send success")
    parser.add_argument("--adaptive-grace", type=float, default=10.0, metavar="SECONDS",
                        help="startup grace period before adaptive rate decisions (default: 10)")
    parser.add_argument("--interface", metavar="IFACE", help="send packets through this interface (bypass auto-detection)")
    parser.add_argument("--no-afpacket", action="store_true",
                        help="use SOCK_RAW instead of AF_PACKET (workaround when a stateful firewall drops replies)")
    parser.add_argument("--no-preflight", action="store_true",
                        help="skip the startup reachability probe (see Troubleshooting in the README)")
    parser.add_argument("--preflight-target", metavar="IP:PORT",
                        help="override the preflight probe target (default: 1.1.1.1:443, 8.8.8.8:443)")
    parser.add_argument("--user-agent", metavar="UA", default="reecanner/1.0",
                        help="User-Agent header for HTTP probes (default: reecanner/1.0)")
    parser.add_argument("--bandwidth", type=float, metavar="BITS",
                        help="target bandwidth in bits/s; converted to pps and overrides --rate-limit")
    parser.add_argument("--status-json", metavar="FILE",
                        help="write scan status as JSON every 10s (for external monitoring)")
    parser.add_argument("-oJ", "--output-json", metavar="FILE", help="output results as JSON")
    parser.add_argument("-oX", "--output-xml", metavar="FILE", help="output results as XML")
    parser.add_argument("-oG", "--output-grep", metavar="FILE", help="output results as grepable format")
    parser.add_argument("-oS", "--output-sqlite", metavar="FILE", help="output results as a SQLite database")
    parser.add_argument("--redis", metavar="URL", help="push discovered IP:PORT to a redis queue (e.g., redis://localhost:6379/0)")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose >= 2 else (logging.INFO if args.verbose >= 1 else logging.WARNING)
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    console = Console(no_color=args.no_color, stderr=args.simple)

    # port selection: --top-ports overrides -p; ping sweep needs no ports
    if args.ping_sweep:
        ports = [0]
    elif args.top_ports:
        ports = get_top_ports(args.top_ports)
        if not ports:
            console.print("[bold red]error:[/bold red] no top ports available")
            sys.exit(1)
    else:
        try:
            ports = parse_ports_list(args.ports)
        except ValueError as e:
            console.print(f"[bold red]error:[/bold red] {e}")
            sys.exit(1)

    # --bandwidth: convert bits/s to packets/s and override --rate-limit.
    # Approximate packet sizes on the wire (eth + ip + l4 + payload).
    bandwidth_pps = None
    if args.bandwidth and args.bandwidth > 0:
        if args.ping_sweep:
            pkt_size = 14 + 20 + 8 + 16        # eth + ip + icmp + payload
        elif args.udp:
            pkt_size = 14 + 20 + 8 + 64        # eth + ip + udp + ~64B payload
        else:
            pkt_size = 14 + 20 + 20            # eth + ip + tcp (SYN)
        bandwidth_pps = max(1, int(args.bandwidth / (pkt_size * 8)))
        args.rate_limit = bandwidth_pps

    if (args.rate_limit > 10000 or args.rate_limit == 0) and not args.override_safety:
        console.print("[bold red][!] error: scanning above 10,000 pps (or unlimited) requires explicit approval[/bold red]")
        console.print("[bold red][!] please use the --override-safety flag to acknowledge the risks[/bold red]")
        sys.exit(1)

    # argument sanity checks (fail fast with clear errors)
    def _arg_error(msg: str) -> None:
        console.print(f"[bold red]error:[/bold red] {msg}")
        sys.exit(1)

    if args.rate_limit < 0:
        _arg_error("--rate-limit must be >= 0")
    if args.workers is not None and args.workers < 1:
        _arg_error("--workers must be >= 1")
    if args.shards < 1:
        _arg_error("--shards must be >= 1")
    if not (0 <= args.shard_id < args.shards):
        _arg_error("--shard-id must be between 0 and shards-1")
    if args.retries < 1:
        _arg_error("--retries must be >= 1")
    if not (1 <= args.batch_size <= (1 << 20)):
        _arg_error("--batch-size must be between 1 and 1048576")
    if not ports:
        _arg_error("no ports selected (check -p/--ports or --top-ports)")

    inc_networks = []
    # stdin support: target="-" or piped stdin
    if args.target == "-" or (args.target is None and not sys.stdin.isatty()):
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#'):
                inc_networks.append(line)
    elif args.target:
        if args.target == "random":
            pass  # compatibility with old syntax
        else:
            inc_networks.extend(args.target.split(","))

    if args.include:
        inc_networks.extend(args.include.split(","))
    if args.include_file:
        for line in args.include_file:
            line = line.strip()
            if line:
                inc_networks.append(line)

    # Process ASN targets (e.g. AS14061) -> Resolve to CIDRs
    final_inc_networks = []
    for net in inc_networks:
        if net.upper().startswith("AS") and net[2:].isdigit():
            console.print(f"[bold blue][*][/bold blue] resolving ASN [cyan]{net.upper()}[/cyan]...")
            cidrs = resolve_asn(net)
            if cidrs:
                console.print(f"    -> resolved to [cyan]{len(cidrs)}[/cyan] prefixes")
                final_inc_networks.extend(cidrs)
            else:
                console.print(f"[bold yellow][!][/bold yellow] could not resolve {net.upper()} or no IPv4 prefixes found.")
        else:
            final_inc_networks.append(net)

    inc_networks = final_inc_networks

    bl_networks = []
    if args.blacklist_file:
        for line in args.blacklist_file:
            line = line.strip()
            if line:
                bl_networks.append(line)
    # inline exclude
    if args.exclude:
        bl_networks.extend(args.exclude.split(","))

    # checkpoint resume must happen BEFORE the InclusionManager is built:
    # the shuffler seed is baked into it at construction time
    start_index = args.index
    start_seed = args.seed
    if args.checkpoint and os.path.exists(args.checkpoint):
        try:
            with open(args.checkpoint, 'r') as f:
                ckpt_data = json.load(f)
                start_index = ckpt_data.get("index", start_index)
                if start_seed is None:
                    start_seed = ckpt_data.get("seed")
            console.print(f"[bold green][*][/bold green] resuming scan from index {start_index} via checkpoint")
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[bold yellow][*][/bold yellow] could not read checkpoint file: {e}")

    inc_mgr = InclusionManager(inc_networks if inc_networks else None, seed=start_seed)
    bl_mgr = BlacklistManager(include_recommended=not args.disable_recommended, allow_private=args.scan_private, custom_networks=bl_networks)

    if not args.scan_private:
        has_private = False
        for net in inc_networks:
            try:
                # try as network
                if ipaddress.ip_network(net, strict=False).is_private:
                    has_private = True
                    break
            except ValueError:
                try:
                    # try as individual IP
                    if ipaddress.ip_address(net).is_private:
                        has_private = True
                        break
                except ValueError:
                    logger.debug("unparseable target %r skipped in private check", net)
        if has_private:
            print("\033[93m[!] warning: private network targets detected. use --scan-private to include them.\033[0m")

    # --vulns needs banners to work
    if args.vulns and not args.banners and not args.http_probe:
        args.banners = True

    # --interface: bypass auto-detection and use the requested interface
    net_info = None
    if args.interface:
        net_info = get_iface_net_info(args.interface)
        if not net_info[1]:
            console.print(f"[bold yellow][!][/bold yellow] could not read MAC for interface {args.interface}; "
                          "falling back to auto-detection")
            net_info = None

    # raw sockets are mandatory; fail fast with a clear message
    try:
        ensure_raw_permissions()
    except PermissionError as e:
        console.print(f"[bold red][!] error:[/bold red] {e}")
        sys.exit(1)

    config = ScannerConfig(
        ports=ports, rate_limit=args.rate_limit, blacklist_manager=bl_mgr,
        inclusion_manager=inc_mgr, source_port=args.source_port if args.source_port > 0 else None,
        workers=args.workers, limit=args.limit, quiet=args.quiet,
        start_index=start_index, shards=args.shards, shard_id=args.shard_id,
        checkpoint_file=args.checkpoint, simple=args.simple,
        batch_size=args.batch_size, retries=args.retries, resolve=args.resolve,
        banners=args.banners, http_probe=args.http_probe, vulns=args.vulns,
        udp=args.udp, adaptive=args.adaptive, adaptive_grace=args.adaptive_grace,
        udp_payload=args.udp_payload, ping_sweep=args.ping_sweep, net_info=net_info,
        force_raw_ip=args.no_afpacket, preflight=not args.no_preflight,
        preflight_target=args.preflight_target,
        user_agent=args.user_agent, no_port=args.no_port, redis_url=args.redis,
        wait=args.wait, output_append=args.output_append, status_json=args.status_json,
    )
    scanner = Scanner(config)

    mode = "ICMP" if args.ping_sweep else ("UDP" if args.udp else "SYN")
    console.print(f"[bold green][*][/bold green] reecanner initialized. targeting [cyan]{len(ports)}[/cyan] ports. mode: [cyan]{mode}[/cyan]")
    console.print(f"[bold green][*][/bold green] workers: [cyan]{scanner.workers_count}[/cyan] | rate: [cyan]{args.rate_limit}[/cyan] pps | seed: [cyan]{scanner.seed}[/cyan]")
    if args.retries > 1:
        console.print(f"[bold green][*][/bold green] retries: [cyan]{args.retries}[/cyan]")
    if args.wait != 3.0:
        console.print(f"[bold green][*][/bold green] response wait: [cyan]{args.wait:.1f}s[/cyan]")
    if args.output_append:
        console.print(f"[bold green][*][/bold green] streaming results to: [italic]{args.output_append}[/italic]")
    if args.banners or args.http_probe:
        features = []
        if args.banners:
            features.append("banners")
        if args.http_probe:
            features.append("http-probe")
        if args.vulns:
            features.append("vulns")
        console.print(f"[bold green][*][/bold green] probes: [cyan]{', '.join(features)}[/cyan]")
    if args.adaptive:
        console.print(f"[bold green][*][/bold green] adaptive rate limiting [cyan]enabled[/cyan] (grace: {args.adaptive_grace:.0f}s)")
    if bandwidth_pps is not None:
        console.print(f"[bold green][*][/bold green] bandwidth target: [cyan]{args.bandwidth:,.0f}[/cyan] bits/s → [cyan]{bandwidth_pps}[/cyan] pps")
    if args.udp and args.udp_payload != "auto":
        console.print(f"[bold green][*][/bold green] udp payload: [cyan]{args.udp_payload}[/cyan]")
    if args.interface and net_info:
        console.print(f"[bold green][*][/bold green] interface: [cyan]{args.interface}[/cyan]")
    if args.no_afpacket:
        console.print("[bold green][*][/bold green] send path: [cyan]SOCK_RAW[/cyan] (--no-afpacket)")
    if args.user_agent != "reecanner/1.0":
        console.print(f"[bold green][*][/bold green] user-agent: [cyan]{args.user_agent}[/cyan]")
    if args.status_json:
        console.print(f"[bold green][*][/bold green] status file: [italic]{args.status_json}[/italic]")
    if args.shards > 1:
        console.print(f"[bold green][*][/bold green] sharding enabled: node [cyan]{args.shard_id}[/cyan] of [cyan]{args.shards}[/cyan]")

    start_t = time.perf_counter()
    try:
        scanner.run(console=console)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            duration = time.perf_counter() - start_t
            console.print("\n[bold yellow]scan stats[/bold yellow]")
            console.print(f"  time elapsed: [cyan]{duration:.2f}s[/cyan]")
            console.print(f"  hosts found:  [green]{scanner.found_total}[/green]")
            # Backstop: packets went out but nothing came back -- likely the
            # same stateful-firewall drop the preflight looks for.
            if scanner.found_total == 0 and scanner.sent_total > 0 and not args.ping_sweep:
                try:
                    from reecanner.preflight import firewall_hint, format_zero_hits_hint
                    console.print(format_zero_hits_hint(scanner.src_port, firewall_hint()),
                                  markup=False)
                except Exception:
                    pass
            # output formats
            results = scanner.get_results()
            meta = JsonWriter.default_meta(duration, ports, scanner.found_total)
            if args.output:
                JsonWriter.write_lines(args.output, results)
                console.print(f"  results saved to (json lines): [italic]{args.output}[/italic]")
            if args.output_json:
                JsonWriter.write_document(args.output_json, results, meta)
                console.print(f"  json saved to: [italic]{args.output_json}[/italic]")
            if args.output_xml:
                XmlWriter.write(args.output_xml, results, meta)
                console.print(f"  xml saved to: [italic]{args.output_xml}[/italic]")
            if args.output_grep:
                GrepWriter.write(args.output_grep, results)
                console.print(f"  grepable saved to: [italic]{args.output_grep}[/italic]")
            if args.output_sqlite:
                try:
                    SqliteWriter.write(args.output_sqlite, results)
                    console.print(f"  sqlite database saved to: [italic]{args.output_sqlite}[/italic]")
                except (sqlite3.Error, OSError) as e:
                    console.print(f"[bold red]error saving sqlite:[/bold red] {e}")
                    logger.exception("failed to write sqlite output %s", args.output_sqlite)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
