#!/usr/bin/env python3
import argparse
import sys
import time
import json
import os
from rich.console import Console
from REEcanner.utils import parse_ports_list, BlacklistManager, InclusionManager
from REEcanner.scanner import Scanner

def main():
    parser = argparse.ArgumentParser(description="reecanner - fast ip/port scout")
    parser.add_argument("target", nargs="?", help="target cidr (e.g., 45.0.0.0/8)")
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
    parser.add_argument("--simple", action="store_true", help="output only IP:PORT to stdout (useful for piping)")
    parser.add_argument("--override-safety", action="store_true", help="acknowledge risks and allow rate limits > 10000 pps")
    parser.add_argument("--shards", type=int, default=1, help="total number of shards for distributed scanning")
    parser.add_argument("--shard-id", type=int, default=0, help="id of this shard (0 to shards-1)")
    parser.add_argument("--checkpoint", help="path to checkpoint file to resume scan")
    parser.add_argument("--batch-size", type=int, default=4096, help="number of IPs to scan in each batch")

    args = parser.parse_args()

    console = Console(no_color=args.no_color)
    try:
        ports = parse_ports_list(args.ports)
    except ValueError as e:
        console.print(f"[bold red]error:[/bold red] {e}")
        sys.exit(1)

    if args.rate_limit > 10000 and not args.override_safety:
        console.print("[bold red][!] error: scanning above 10,000 pps requires explicit approval[/bold red]")
        console.print("[bold red][!] please use the --override-safety flag to acknowledge the risks[/bold red]")
        sys.exit(1)

    inc_networks = []
    if args.target: 
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

    inc_mgr = InclusionManager(inc_networks if inc_networks else None, seed=args.seed)
    bl_mgr = BlacklistManager(include_recommended=not args.disable_recommended, allow_private=args.scan_private, custom_networks=bl_networks)
    
    start_index = args.index
    if args.checkpoint and os.path.exists(args.checkpoint):
        try:
            with open(args.checkpoint, 'r') as f:
                start_index = json.load(f).get("index", start_index)
            console.print(f"[bold green][*][/bold green] resuming scan from index {start_index} via checkpoint")
        except Exception as e:
            console.print(f"[bold yellow][*][/bold yellow] could not read checkpoint file: {e}")

    scanner = Scanner(
        ports=ports, rate_limit=args.rate_limit, blacklist_manager=bl_mgr,
        inclusion_manager=inc_mgr, source_port=args.source_port if args.source_port > 0 else None,
        workers=args.workers, limit=args.limit, output_file=args.output, quiet=args.quiet,
        seed=args.seed, start_index=start_index, shards=args.shards, shard_id=args.shard_id,
        checkpoint_file=args.checkpoint, simple=args.simple,
        batch_size=args.batch_size
    )

    console.print(f"[bold green][*][/bold green] reecanner initialized. targeting [cyan]{len(ports)}[/cyan] ports.")
    console.print(f"[bold green][*][/bold green] workers: [cyan]{scanner.workers_count}[/cyan] | rate: [cyan]{args.rate_limit}[/cyan] pps | seed: [cyan]{scanner.seed}[/cyan]")
    if args.shards > 1:
        console.print(f"[bold green][*][/bold green] sharding enabled: node [cyan]{args.shard_id}[/cyan] of [cyan]{args.shards}[/cyan]")

    start_t = time.perf_counter()
    try:
        scanner.run(console=console)
    except KeyboardInterrupt:
        pass
    finally:
        duration = time.perf_counter() - start_t
        console.print(f"\n[bold yellow]scan stats[/bold yellow]")
        console.print(f"  time elapsed: [cyan]{duration:.2f}s[/cyan]")
        console.print(f"  hosts found:  [green]{scanner.found_total}[/green]")
        if args.output:
            console.print(f"  results saved to: [italic]{args.output}[/italic]")

if __name__ == "__main__":
    main()
