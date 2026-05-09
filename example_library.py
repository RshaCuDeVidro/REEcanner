import json
from rich.console import Console
from reecanner.scanner import Scanner
from reecanner.utils import BlacklistManager, InclusionManager, resolve_asn

if __name__ == '__main__':
    console = Console()
    console.print("[bold cyan][*] REEcanner Library Example: Advanced Web & Vuln Hunter[/bold cyan]")

    # 1. Resolve an ASN to CIDR ranges (Example: DigitalOcean)
    asn = "AS14061"
    console.print(f"[*] Resolving ASN {asn} via RIPE Stat...")
    cidrs = resolve_asn(asn)
    
    if not cidrs:
        console.print("[red][!] Could not resolve ASN[/red]")
        exit(1)
        
    console.print(f"[bold green][+][/bold green] Found {len(cidrs)} prefixes for {asn}")
    
    # 2. Setup Targets
    # We will scan only the first 3 prefixes here just so the example runs quickly
    target_prefixes = cidrs[:3]
    console.print(f"[*] Limiting scan to first 3 prefixes: {', '.join(target_prefixes)}")
    
    inc = InclusionManager(target_prefixes)
    bl = BlacklistManager(include_recommended=True, allow_private=False)

    # 3. Initialize Scanner
    scanner = Scanner(
        ports=[80, 443],            # Web ports
        rate_limit=5000,            # 5,000 Packets Per Second
        blacklist_manager=bl,
        inclusion_manager=inc,
        banners=True,               # Grab service banners
        http_probe=True,            # Extract HTML titles and Server headers
        vulns=True,                 # Check SearchSploit for CVEs based on banners
        quiet=False                 # Show internal progress bars (stderr)
    )

    # 4. Run the scan
    console.print("\n[bold yellow][*] Launching High-Speed Packet Engine...[/bold yellow]")
    scanner.run(console=console)

    # 5. Process and Save Results
    results = scanner.get_results()
    
    vulnerable_hosts = [h for h in results if h.get('exploits')]
    
    console.print(f"\n[bold green][+] Scan Complete![/bold green] Found {len(results)} active web servers.")
    if vulnerable_hosts:
        console.print(f"[bold red][!] Found {len(vulnerable_hosts)} potentially vulnerable servers.[/bold red]")
    else:
        console.print("[green][*] No obvious vulnerabilities found via banners.[/green]")
    
    # Save a beautiful report
    report_file = "vuln_report.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=4)
        
    console.print(f"[bold blue][*][/bold blue] Full scan report saved to: [italic]{report_file}[/italic]")
