# REEcanner

REEcanner is a TCP SYN / UDP / ICMP scanner for large-scale network
research. It sends raw packets at up to 1M+ packets per second using a
native C engine, `AF_PACKET` raw sockets, and `sendmmsg` batching. IP addresses are visited
in a pseudo-random but deterministic order using a Feistel cipher, which
allows reproducible scans and trivial sharding across multiple machines
without any coordination.

It is designed for scanning large portions of the IPv4 address space.

```
$ sudo reecanner 0.0.0.0/0 -p 80 -r 0 --override-safety -q
[*] reecanner initialized. targeting 1 ports. mode: SYN
[*] workers: 4 | rate: 0 pps | seed: 3848841034

[*] sent: 23.261.184 | rate: 1.075.453 pps | found: 1101 | next index: 23261184

scan stats
  time elapsed: 21.86s
  hosts found:  1101
```

## Installation

Requires Linux, root privileges, Python 3.9+, GCC, and the `rich` module.

### Arch Linux (AUR)

If you are using Arch Linux, you can install REEcanner directly from the AUR using your favorite helper:

```
$ yay -S reecanner-git
```

### Global Installation (Pipx)

To install globally so it is available in your PATH for `sudo`, we recommend using `pipx` with the `--global` flag. The build backend compiles the C worker automatically (`setup.py` runs `make` before assembling the wheel); without `worker.so` you silently get the slower pure-Python engine.

```
$ git clone https://github.com/RshaCuDeVidro/REEcanner.git
$ cd REEcanner
$ sudo pipx install --global .
```

### From Source (Manual)

If you just want to run it from the folder without installing it to your system:

```
$ pip install rich redis
$ make
$ sudo python3 -m reecanner [options]
```

Running `make` compiles the high-performance C packet engine (`worker.so`). Without it, the scanner falls back to a pure Python implementation at roughly 5x lower throughput.

## Usage

```
$ sudo reecanner <target> [options]
# OR
$ sudo python3 -m reecanner <target> [options]
```

The target is a CIDR block or comma-separated list of CIDR blocks. If
omitted, defaults to the entire IPv4 space (`0.0.0.0/0`).

### Options

```
TARGET SELECTION
  target                      CIDR(s), IP(s), or ASN(s) to scan (e.g. 45.0.0.0/8, AS14061)
                              use '-' for targets from stdin
  -i, --include CIDR[,CIDR]   additional CIDRs to include
  --include-file FILE         include CIDRs from file, one per line
  --exclude CIDR[,CIDR]       exclude IPs/CIDRs from scan (comma-separated)

PORT SELECTION
  -p, --ports PORTS           ports to scan (default: 80)
                              accepts ranges: 80,443,8000-9000
  --top-ports N               scan top N most common ports (nmap-style)

RATE CONTROL
  -r, --rate-limit PPS        packets per second (default: 1000, 0=unlimited)
  --bandwidth BITS            target bandwidth in bits/s; converted to pps,
                              overrides --rate-limit
  --adaptive                  adaptive rate limiting based on send success
  --adaptive-grace SECONDS    startup grace period before adaptive rate
                              decisions (default: 10)
  --override-safety           required for rates above 10,000 pps
  --batch-size N              packets per sendmmsg call (default: 4096)
  --retries N                 number of times to retransmit each probe (default: 1)

SCAN CONTROL
  -w, --workers N             worker processes (default: cpu count)
  -l, --limit N               stop after N hosts found
  -s, --source-port PORT      fixed source port for SYN packets
  --seed N                    feistel seed for deterministic ordering
  --index N                   start from this permutation index
  --wait SECONDS              wait for late responses after sending finishes
                              (default: 3)
  --interface IFACE           send packets through this interface
                              (bypass auto-detection)
  --no-afpacket               force SOCK_RAW instead of AF_PACKET. Use when a
                              stateful firewall drops AF_PACKET replies (see
                              Troubleshooting). Lower throughput.
  --no-preflight              skip the startup reachability probe
  --preflight-target IP:PORT  override the preflight probe target
                              (default: 1.1.1.1:443, 8.8.8.8:443)
  --udp                       UDP scan mode instead of TCP SYN
  --udp-payload PAYLOAD       UDP probe payload: auto, dns, ntp, snmp, ssdp,
                              memcached (default: auto = rotate all)
  --ping-sweep                ICMP echo (ping) host discovery instead of TCP SYN

EXCLUSIONS
  -b, --blacklist-file FILE   CIDRs to exclude, one per line
  -d, --disable-recommended   remove built-in blacklist (military, etc)
  --scan-private              include RFC1918 and reserved ranges

PROBING & RESOLUTION
  --http-probe                HTTP probe open web ports (title, status, server)
  --user-agent UA             User-Agent header for HTTP probes
                              (default: reecanner/1.0)
  --banners                   grab banners from discovered services
  --vulns                     search exploits via searchsploit for discovered services
  --resolve                   reverse DNS resolve found IPs and extract TLS domains

OUTPUT
  -o, --output FILE           write results as JSON lines
  --output-append FILE        stream results as JSON lines while scanning
                              (append mode)
  -oJ, --output-json FILE     output results as JSON
  -oX, --output-xml FILE      output results as XML
  -oG, --output-grep FILE     output results as grepable format
  -oS, --output-sqlite FILE   output results as a SQLite database
  --status-json FILE          write scan status as JSON every 10s
                              (for external monitoring)
  -q, --quiet                 suppress per-host output, show only stats
  -v, --verbose               increase log verbosity (-v info, -vv debug)
  --simple                    output IP or IP:PORT to stdout (for piping)
  --no-port                   omit port from output (just show IP)
  --no-color                  disable ANSI color codes

INTEGRATION
  --redis URL                 push discovered hosts to Redis queue
                              (e.g., redis://localhost:6379/0)
                              Useful for distributed pipelines or crawlers.

DISTRIBUTED SCANNING
  --shards N                  total number of nodes (default: 1)
  --shard-id ID               this node's ID, 0 to shards-1 (default: 0)

CHECKPOINTING
  --checkpoint FILE           save/resume scan state (writes every 10s)
```

Checkpoint files are small JSON documents (`{"index": N, "seed": S}`).
Resume is intentionally conservative: the restart index is the *minimum*
index across workers, so a bounded window of IPs near the checkpoint may
be re-sent (harmless — results are deduplicated). The checkpoint stores
the Feistel seed, so resume restores the exact same permutation; do not
pass a different `--seed` when resuming.

## Examples

Scan a local subnet for common services:

```
$ sudo reecanner 192.168.1.0/24 -p 22,80,443,3306,8080 --scan-private
```

Scan a /8 block for web servers at 50k pps and save results:

```
$ sudo reecanner 104.0.0.0/8 -p 80,443 -r 50000 --override-safety -o results.json
```

Scan the entire internet for SSH, stop after 500 hits:

```
$ sudo reecanner 0.0.0.0/0 -p 22 -r 100000 --override-safety -l 500
```

Unlimited rate, maximum throughput:

```
$ sudo reecanner 0.0.0.0/0 -p 80 -r 0 --override-safety --batch-size 8192 -w 4 -q
```

Scan with checkpoint — interrupt with Ctrl+C and resume later:

```
$ sudo reecanner 0.0.0.0/0 -p 443 -r 50000 --override-safety \
    --checkpoint scan.ckpt -o hits.json
[*] resuming scan from index 18432000 via checkpoint
```

Pipe results into other tools:

```
$ sudo reecanner 0.0.0.0/0 -p 443 --simple -q | httpx -silent
$ sudo reecanner 0.0.0.0/0 -p 80 --simple -q | nuclei -t cves/
$ sudo reecanner 0.0.0.0/0 -p 22 --simple -q > ssh_hosts.txt
```

Scan specific ports on multiple ranges:

```
$ sudo reecanner 104.0.0.0/8,45.0.0.0/8 -p 80,443,8443
```

Include targets from a file:

```
$ cat targets.txt
104.16.0.0/12
172.64.0.0/13
198.41.128.0/17

$ sudo reecanner --include-file targets.txt -p 443 -r 10000
```

Custom blacklist to avoid specific networks:

```
$ cat exclude.txt
203.0.113.0/24
198.51.100.0/24

$ sudo reecanner 0.0.0.0/0 -p 80 -b exclude.txt -r 50000 --override-safety
```

Reproducible scan — same seed produces the same IP order:

```
$ sudo reecanner 0.0.0.0/0 -p 80 --seed 42 -l 100 --simple -q > run1.txt
$ sudo reecanner 0.0.0.0/0 -p 80 --seed 42 -l 100 --simple -q > run2.txt
$ diff run1.txt run2.txt    # identical
```

Find the first N open hosts on a specific port:

```
$ sudo reecanner 0.0.0.0/0 -p 3389 -l 50 --simple -q
```

Scan all common ports on a single target range:

```
$ sudo reecanner 10.0.0.0/16 -p 21-25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443 \
    --scan-private -r 5000
```

UDP scan for DNS servers (using `--top-ports` or `-p 53`):

```
$ sudo reecanner 0.0.0.0/0 -p 53 --udp -r 100000 --override-safety
```

Send a specific UDP probe payload instead of rotating through all of them
(`dns`, `ntp`, `snmp`, `ssdp`, `memcached`):

```
$ sudo reecanner 0.0.0.0/0 -p 161 --udp --udp-payload snmp -r 10000
```

Ping sweep — discover live hosts with ICMP echo instead of TCP SYN:

```
$ sudo reecanner 192.168.1.0/24 --ping-sweep --scan-private
```

> [!NOTE]
> UDP scans report a port as open only when the target *responds* to the
> probe (e.g. a DNS reply for `--udp-payload dns`). ICMP port-unreachable
> messages are not processed, so there is no "closed vs. filtered"
> distinction: a silent port is simply not reported. This is the classic
> `open|filtered` limitation of stateless UDP scanning — only responsive
> services are detected, and the built-in payloads (dns, ntp, snmp, ssdp,
> memcached) cover the most common ones.

Wait longer for late responses on lossy or high-latency networks:

```
$ sudo reecanner 0.0.0.0/0 -p 443 -r 20000 --override-safety --wait 10
```

Adaptive rate limiting — automatically backs off when the NIC or kernel
starts dropping packets, ramps up when sends succeed. `--adaptive-grace`
sets how long to run at the requested rate before making decisions:

```
$ sudo reecanner 0.0.0.0/0 -p 80 -r 50000 --override-safety \
    --adaptive --adaptive-grace 5
```

Cap by link bandwidth instead of packet rate — `--bandwidth` takes bits/s
and converts it to pps based on the scan type's packet size:

```
# 10 Mbps SYN scan
$ sudo reecanner 0.0.0.0/0 -p 80 --bandwidth 10000000 --override-safety
```

Pin the scan to a specific network interface (skips gateway auto-detection):

```
$ sudo reecanner 10.0.0.0/8 -p 443 --interface eth1 --scan-private
```

Stream results to a file as they are found (append mode, survives crashes):

```
$ sudo reecanner 0.0.0.0/0 -p 22 -r 50000 --override-safety \
    --output-append live_hits.jsonl
```

Monitor scan progress from another tool — writes a JSON status snapshot
(sent count, current rate, hosts found, index) every 10 seconds:

```
$ sudo reecanner 0.0.0.0/0 -p 443 --status-json /tmp/scan_status.json -q
$ watch -n5 cat /tmp/scan_status.json
```

Identify as a browser during HTTP probing instead of the default
`reecanner/1.0` User-Agent:

```
$ sudo reecanner 104.0.0.0/8 -p 80,443 --http-probe \
    --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

Verbose logging for debugging — `-v` shows info messages, `-vv` shows full
debug output (worker errors, probe failures, queue drops):

```
$ sudo reecanner 192.168.1.0/24 -p 80 --scan-private -vv
```

Scan an entire ASN (automatically resolves to CIDRs):

```
$ sudo reecanner AS14061 -p 80,443
```

Read targets from stdin (e.g. results from other tools):

```
$ subfinder -d example.com -silent | sudo reecanner - -p 443
```

Push results to a Redis queue for external processing (e.g. a separate crawler):

```
$ sudo reecanner 0.0.0.0/0 -p 6379 --redis redis://localhost:6379/0
```

Service Discovery and Vulnerability Scanning:

```
$ sudo reecanner 192.168.1.0/24 -p 80,443,22 --banners --http-probe --vulns --resolve
```

> [!TIP]
> When using `--http-probe` or `--resolve` on port 443, REEcanner automatically extracts all DNS names from the SSL certificate's Subject Alternative Name (SAN) field.

## Distributed Scanning

Split a scan across multiple machines using `--shards` and `--shard-id`.
All nodes must use the same `--seed` value. Each node scans a disjoint
subset of IPs.

```
node0$ sudo reecanner 0.0.0.0/0 -p 80 --shards 3 --shard-id 0 --seed 1337 -r 0 --override-safety
node1$ sudo reecanner 0.0.0.0/0 -p 80 --shards 3 --shard-id 1 --seed 1337 -r 0 --override-safety
node2$ sudo reecanner 0.0.0.0/0 -p 80 --shards 3 --shard-id 2 --seed 1337 -r 0 --override-safety
```

The Feistel cipher generates a deterministic permutation. With N shards,
node K processes only indices where `index % N == K`. No coordination
protocol is needed — each node runs independently.

To combine results:

```
$ cat results-node*.json | sort -u > combined.json
```

## Performance

Benchmarks on a 4-core machine, scanning `0.0.0.0/0` port 80, unlimited rate:

```
ENGINE              WORKERS   BATCH    RATE
Python (CPython)    16        1024     ~227,000 pps
Python (PyPy3)      16        1024     ~652,000 pps
C worker (CPython)  4         8192     ~1,075,000 pps
C worker (PyPy3)    4         8192     ~1,196,000 pps
```

### Kernel Tuning

At high rates, the Linux kernel becomes the bottleneck. These settings
can significantly improve throughput:

```
# disable connection tracking — biggest single improvement
$ sudo modprobe -r nf_conntrack

# increase socket send buffers
$ sudo sysctl -w net.core.wmem_max=67108864
$ sudo sysctl -w net.core.wmem_default=67108864

# increase TX queue length
$ sudo ip link set eth0 txqueuelen 10000
```

Disabling `nf_conntrack` alone can yield 30-50% higher throughput. The
connection tracking subsystem attempts to track every outgoing SYN,
which creates significant overhead at scale.

### Tuning Tips

- Set `-w` to the number of physical cores, not logical. Hyperthreading
  does not help for this workload.
- Batch sizes of 4096-8192 are optimal. Larger batches mean fewer syscalls
  but higher per-batch latency.
- Use `-q` to avoid printing each host — this removes overhead in the
  sniffer process.
- `AF_PACKET` is used automatically when the default gateway is reachable.
  If it falls back to `SOCK_RAW`, throughput will be lower.

## Troubleshooting

### The scan finishes but finds 0 hosts

On a host with a stateful firewall this is usually not a scanner bug. The
fast `AF_PACKET` transmit path bypasses the kernel connection tracker, so
incoming SYN-ACKs have no conntrack entry. A firewall such as

```
-P INPUT DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j REJECT
```

then drops every reply, and the scan silently reports nothing.

REEcanner signals this in two ways:

- **Startup preflight** — it sends one SYN to `1.1.1.1:443` (and `8.8.8.8:443`)
  through the same path the scan will use and watches for the SYN-ACK. If none
  arrives it retries over `SOCK_RAW`; when that succeeds it reports that the
  drop is specific to `AF_PACKET`. On failure it prints the fix below.
  Disable with `--no-preflight`, override the target with `--preflight-target`.
- **End-of-scan hint** — if packets were sent and 0 hosts were found it prints
  a short reminder.

Fixes, in order of preference:

```
# 1. skip AF_PACKET for this run (SOCK_RAW creates conntrack state)
sudo reecanner <target> -p 22,80 --no-afpacket

# 2. keep AF_PACKET and let the replies through (source-port range is 10000-38999)
sudo iptables -I INPUT -p tcp -m tcp --dport 10000:38999 \
     --tcp-flags SYN,ACK SYN,ACK -j ACCEPT

# 3. on cloud hosts, allow inbound TCP SYN-ACK to the source-port range in the
#    security list / security group
```

The preflight probe costs a single SYN per target and is safe to leave on; use
`--no-preflight` on air-gapped or internal-only hosts where no public canary is
reachable.

## How It Works

REEcanner uses a transmit/receive split architecture. Worker processes
generate and send SYN packets. A separate sniffer process captures
SYN-ACK responses.

### Transmit Path

1. A Feistel cipher maps sequential indices to pseudo-random 32-bit
   values, producing a permutation of the IP space. This means every
   address is visited exactly once without storing any state.

2. Each generated IP is checked against a merged, sorted blacklist
   using binary search. Private, reserved, multicast, and certain
   government ranges are excluded by default.

3. SYN packets are constructed directly in a contiguous buffer with
   inline IP and TCP checksum calculation. No memory allocation
   happens in the hot loop.

4. Batches of packets are flushed to the NIC via `sendmmsg()` over
   an `AF_PACKET` socket, bypassing the kernel IP stack.

The entire transmit loop — IP generation, blacklist check, packet
construction, checksum, and batching — runs in compiled C.

### Receive Path

A sniffer process opens a raw TCP socket and captures incoming packets.
It filters for SYN-ACK responses matching the scanner's source port,
deduplicates by (IP, port) pair, and writes results to stdout and/or
a JSON file.

### Sharding

The Feistel permutation is deterministic for a given seed. With sharding
enabled, each node processes only indices where `index % shards == shard_id`.
Since the permutation is fixed, all nodes with the same seed collectively
cover the entire address space without overlap or communication.

## Using as a Library

REEcanner is fully modular. You can import its engines into your own Python scripts for custom workflows (like pushing to databases, correlating with other tools, or building your own scanners).

Check out the **[Advanced Library Example (example_library.py)](example_library.py)** to see how to:
- Resolve ASNs to CIDRs automatically.
- Initialize the high-speed packet engine.
- Enable HTTP probing and Vulnerability scanning (SearchSploit).
- Generate a structured JSON report.

Here is a quick overview of how simple it is:

```python
from reecanner.scanner import Scanner, ScannerConfig
from reecanner.utils import BlacklistManager, InclusionManager

if __name__ == '__main__':
    inc = InclusionManager(["192.168.1.0/24"])
    bl = BlacklistManager(allow_private=True)

    config = ScannerConfig(
        ports=[80, 443],
        rate_limit=5000,
        blacklist_manager=bl,
        inclusion_manager=inc,
        banners=True,
        http_probe=True
    )
    scanner = Scanner(config)

    scanner.run(console=None)

    for host in scanner.get_results():
        print(f"Found {host['ip']}:{host['port']} - {host.get('title')}")
```

## Project Structure

```
pyproject.toml       Package configuration (build, ruff, mypy)
makefile             Compiles C engine
reecanner/
  __main__.py        CLI entry point (python -m reecanner)
  worker.c           C transmit engine
  scanner.py         Core scanner logic & process management
  utils.py           Feistel shuffler & network managers
  packet.py          Raw packet construction
  ports.py           Service name & top-ports mapping
  probes.py          Banner grabbing & HTTP probing
  nmap_probes.py     nmap-service-probes banner matching
  fingerprint.py     OS & Service fingerprinting
  vulns.py           Searchsploit integration
  output.py          JSON/XML/grepable/SQLite result writers
  data/              Bundled probe data (nmap-service-probes)
tests/               pytest suite
```

## Performance / vantage

If a cloud VPS finds far fewer hosts than a home connection for the same seed
and code, the bottleneck is usually the network path, not the scanner. The
guest can be completely lossless (0 drops, idle CPU, all NIC-visible SYN-ACKs
captured) and still receive few replies because the datacenter network throttles
high-rate scan traffic.

- Diagnose and tune a vantage with `sudo tools/vantage_bench.sh`.
- Full write-up (method, evidence, options): [`docs/vantage.md`](docs/vantage.md).

Rule of thumb: if hosts/second is flat across rates, the vantage is the
bottleneck — sending faster does not find more.

## Legal

This tool is intended for authorized security research and network
measurement. Unauthorized scanning may violate applicable laws and
terms of service. Ensure you have proper authorization before scanning
any network you do not own or have explicit permission to test.
