#!/usr/bin/env python3
import argparse
import sys
import time
import json
import os
from datetime import datetime
from rich.console import Console
from REEcanner.utils import parse_ports_list, BlacklistManager, InclusionManager
from REEcanner.ports import get_top_ports
from REEcanner.scanner import Scanner

def main():
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
    parser.add_argument("--seed", type=int, help="seed for the shuffler")
    parser.add_argument("--index", type=int, default=0, help="start index for the scan")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
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
    parser.add_argument("--resolve", action="store_true", help="reverse DNS resolve found IPs")
    parser.add_argument("--banners", action="store_true", help="grab banners from discovered services")
    parser.add_argument("--http-probe", action="store_true", help="HTTP probe open web ports (title, status, server)")
    parser.add_argument("--vulns", action="store_true", help="search exploits via searchsploit for discovered services")
    parser.add_argument("--udp", action="store_true", help="UDP scan mode instead of TCP SYN")
    parser.add_argument("--adaptive", action="store_true", help="adaptive rate limiting based on send success")
    parser.add_argument("-oJ", "--output-json", metavar="FILE", help="output results as JSON")
    parser.add_argument("-oX", "--output-xml", metavar="FILE", help="output results as XML")
    parser.add_argument("-oG", "--output-grep", metavar="FILE", help="output results as grepable format")
    parser.add_argument("-oS", "--output-sqlite", metavar="FILE", help="output results as a SQLite database")

    args = parser.parse_args()

    console = Console(no_color=args.no_color, stderr=args.simple)

    # port selection: --top-ports overrides -p
    if args.top_ports:
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

    if (args.rate_limit > 10000 or args.rate_limit == 0) and not args.override_safety:
        console.print("[bold red][!] error: scanning above 10,000 pps (or unlimited) requires explicit approval[/bold red]")
        console.print("[bold red][!] please use the --override-safety flag to acknowledge the risks[/bold red]")
        sys.exit(1)

    inc_networks = []
    # stdin support: target="-" or piped stdin
    if args.target == "-" or (args.target is None and not sys.stdin.isatty()):
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#'):
                inc_networks.append(line)
    elif args.target:
        if args.target == "random": pass # compatibility with old syntax
        else: inc_networks.extend(args.target.split(","))
        
    if args.include: inc_networks.extend(args.include.split(","))
    if args.include_file:
        for line in args.include_file:
            line = line.strip()
            if line: inc_networks.append(line)
    
    bl_networks = []
    if args.blacklist_file:
        for line in args.blacklist_file:
            line = line.strip()
            if line: bl_networks.append(line)
    # inline exclude
    if args.exclude:
        bl_networks.extend(args.exclude.split(","))

    inc_mgr = InclusionManager(inc_networks if inc_networks else None, seed=args.seed)
    bl_mgr = BlacklistManager(include_recommended=not args.disable_recommended, allow_private=args.scan_private, custom_networks=bl_networks)
    
    if not args.scan_private:
        has_private = False
        for net in inc_networks:
            try:
                # try as network
                if ipaddress.ip_network(net, strict=False).is_private:
                    has_private = True
                    break
            except:
                try:
                    # try as individual IP
                    if ipaddress.ip_address(net).is_private:
                        has_private = True
                        break
                except: pass
        if has_private:
            print("\033[93m[!] warning: private network targets detected. use --scan-private to include them.\033[0m")

    start_index = args.index
    if args.checkpoint and os.path.exists(args.checkpoint):
        try:
            with open(args.checkpoint, 'r') as f:
                start_index = json.load(f).get("index", start_index)
            console.print(f"[bold green][*][/bold green] resuming scan from index {start_index} via checkpoint")
        except Exception as e:
            console.print(f"[bold yellow][*][/bold yellow] could not read checkpoint file: {e}")
    # --vulns precisa de banners pra funcionar
    if args.vulns and not args.banners and not args.http_probe:
        args.banners = True

    scanner = Scanner(
        ports=ports, rate_limit=args.rate_limit, blacklist_manager=bl_mgr,
        inclusion_manager=inc_mgr, source_port=args.source_port if args.source_port > 0 else None,
        workers=args.workers, limit=args.limit, output_file=args.output, quiet=args.quiet,
        seed=args.seed, start_index=start_index, shards=args.shards, shard_id=args.shard_id,
        checkpoint_file=args.checkpoint, simple=args.simple,
        batch_size=args.batch_size, retries=args.retries, resolve=args.resolve,
        banners=args.banners, http_probe=args.http_probe, vulns=args.vulns,
        udp=args.udp, adaptive=args.adaptive, no_port=args.no_port
    )

    mode = "UDP" if args.udp else "SYN"
    console.print(f"[bold green][*][/bold green] reecanner initialized. targeting [cyan]{len(ports)}[/cyan] ports. mode: [cyan]{mode}[/cyan]")
    console.print(f"[bold green][*][/bold green] workers: [cyan]{scanner.workers_count}[/cyan] | rate: [cyan]{args.rate_limit}[/cyan] pps | seed: [cyan]{scanner.seed}[/cyan]")
    if args.retries > 1:
        console.print(f"[bold green][*][/bold green] retries: [cyan]{args.retries}[/cyan]")
    if args.banners or args.http_probe:
        features = []
        if args.banners: features.append("banners")
        if args.http_probe: features.append("http-probe")
        if args.vulns: features.append("vulns")
        console.print(f"[bold green][*][/bold green] probes: [cyan]{', '.join(features)}[/cyan]")
    if args.adaptive:
        console.print(f"[bold green][*][/bold green] adaptive rate limiting [cyan]enabled[/cyan]")
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
            console.print(f"\n[bold yellow]scan stats[/bold yellow]")
            console.print(f"  time elapsed: [cyan]{duration:.2f}s[/cyan]")
            console.print(f"  hosts found:  [green]{scanner.found_total}[/green]")
            if args.output:
                console.print(f"  results saved to: [italic]{args.output}[/italic]")
            # output formats
            results = scanner.get_results()
            if args.output_json:
                with open(args.output_json, 'w') as f:
                    json.dump({"scan": {"time": datetime.now().isoformat(), "duration": f"{duration:.2f}s", "ports": ports, "total_found": scanner.found_total}, "hosts": results}, f, indent=2)
                console.print(f"  json saved to: [italic]{args.output_json}[/italic]")
            if args.output_xml:
                with open(args.output_xml, 'w') as f:
                    f.write('<?xml version="1.0"?>\n<reecanner>\n')
                    f.write(f'  <scan time="{datetime.now().isoformat()}" duration="{duration:.2f}s" ports="{len(ports)}" found="{scanner.found_total}"/>\n')
                    for r in results:
                        attrs = ' '.join(f'{k}="{v}"' for k, v in r.items() if isinstance(v, (str, int)))
                        f.write(f'  <host {attrs}/>\n')
                    f.write('</reecanner>\n')
                console.print(f"  xml saved to: [italic]{args.output_xml}[/italic]")
            if args.output_grep:
                with open(args.output_grep, 'w') as f:
                    f.write(f"# reecanner scan {datetime.now().isoformat()}\n")
                    for r in results:
                        os_info = r.get('os', '')
                        svc = r.get('service', '')
                        hostname = r.get('hostname', '')
                        extra = [x for x in [os_info, svc, hostname] if x]
                        f.write(f"Host: {r['ip']} Port: {r['port']}/open/tcp {' '.join(extra)}\n")
                console.print(f"  grepable saved to: [italic]{args.output_grep}[/italic]")
            if args.output_sqlite:
                try:
                    import sqlite3
                    import json as json_mod
                    conn = sqlite3.connect(args.output_sqlite)
                    cursor = conn.cursor()
                    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts 
                                   (ip TEXT, port INTEGER, proto TEXT, service TEXT, hostname TEXT, 
                                    os TEXT, banner TEXT, title TEXT, status INTEGER, server TEXT,
                                    redirect TEXT, vulnerabilities TEXT)''')
                    for r in results:
                        vulns_json = json_mod.dumps(r.get('exploits', [])) if r.get('exploits') else None
                        cursor.execute("""INSERT INTO hosts (ip, port, proto, service, hostname, os, banner, 
                                                              title, status, server, redirect, vulnerabilities) 
                                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                                       (r.get('ip'), r.get('port'), r.get('proto'), r.get('service'), 
                                        r.get('hostname'), r.get('os'), r.get('banner'), r.get('title'), 
                                        r.get('status'), r.get('server'), r.get('redirect'), vulns_json))
                    conn.commit()
                    conn.close()
                    console.print(f"  sqlite database saved to: [italic]{args.output_sqlite}[/italic]")
                except Exception as e:
                    console.print(f"[bold red]error saving sqlite:[/bold red] {e}")
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
