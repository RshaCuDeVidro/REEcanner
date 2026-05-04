# REEcanner

REEcanner is a TCP SYN scanner for large-scale network research. It sends
raw SYN packets at up to 1M+ packets per second using a native C engine,
`AF_PACKET` raw sockets, and `sendmmsg` batching. IP addresses are visited
in a pseudo-random but deterministic order using a Feistel cipher, which
allows reproducible scans and trivial sharding across multiple machines
without any coordination.

It is designed for scanning large portions of the IPv4 address space.

```
$ sudo python3 main.py 0.0.0.0/0 -p 80 -r 0 --override-safety -q
[*] reecanner initialized. targeting 1 ports.
[*] workers: 4 | rate: 0 pps | seed: 3848841034
[*] using C worker (worker.so)

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

To install globally so it is available in your PATH for `sudo`, we recommend using `pipx` with the `--global` flag. This automatically compiles the C worker and sets up the tool.

```
$ git clone https://github.com/RshaCuDeVidro/REEcanner.git
$ cd REEcanner
$ sudo pipx install --global .
```

### From Source (Manual)

If you just want to run it from the folder without installing it to your system:

```
$ pip install rich
$ make
$ sudo python3 main.py [options]
```

Running `make` compiles the high-performance C packet engine (`worker.so`). Without it, the scanner falls back to a pure Python implementation at roughly 5x lower throughput.

## Usage

```
sudo python3 main.py <target> [options]
```

The target is a CIDR block or comma-separated list of CIDR blocks. If
omitted, defaults to the entire IPv4 space (`0.0.0.0/0`).

### Options

```
TARGET SELECTION
  target                      CIDR(s) to scan (e.g. 45.0.0.0/8)
  -i, --include CIDR[,CIDR]  additional CIDRs to include
  --include-file FILE         include CIDRs from file, one per line
  --exclude CIDR[,CIDR]       exclude IPs/CIDRs from scan (comma-separated)

PORT SELECTION
  -p, --ports PORTS           ports to scan (default: 80)
                              accepts ranges: 80,443,8000-9000
  --top-ports N               scan top N most common ports (nmap-style)

RATE CONTROL
  -r, --rate-limit PPS        packets per second (default: 1000, 0=unlimited)
  --adaptive                  adaptive rate limiting based on send success
  --override-safety           required for rates above 10,000 pps
  --batch-size N              packets per sendmmsg call (default: 4096)
  --retries N                 number of times to retransmit each probe (default: 1)

SCAN CONTROL
  -w, --workers N             worker processes (default: cpu count)
  -l, --limit N               stop after N hosts found
  -s, --source-port PORT      fixed source port for SYN packets
  --seed N                    feistel seed for deterministic ordering
  --index N                   start from this permutation index
  --udp                       UDP scan mode instead of TCP SYN

EXCLUSIONS
  -b, --blacklist-file FILE   CIDRs to exclude, one per line
  -d, --disable-recommended   remove built-in blacklist (military, etc)
  --scan-private              include RFC1918 and reserved ranges

PROBING & RESOLUTION
  --resolve                   reverse DNS resolve found IPs
  --banners                   grab banners from discovered services
  --http-probe                HTTP probe open web ports (title, status, server)
  --vulns                     search exploits via searchsploit for discovered services

OUTPUT
  -o, --output FILE           write results as JSON lines
  -oJ, --output-json FILE     output results as JSON
  -oX, --output-xml FILE      output results as XML
  -oG, --output-grep FILE     output results as grepable format
  -q, --quiet                 suppress per-host output, show only stats
  --simple                    output IP or IP:PORT to stdout (for piping)
  --no-port                   omit port from output (just show IP)
  --no-color                  disable ANSI color codes

DISTRIBUTED SCANNING
  --shards N                  total number of nodes (default: 1)
  --shard-id ID               this node's ID, 0 to shards-1 (default: 0)

CHECKPOINTING
  --checkpoint FILE           save/resume scan state (writes every 10s)
```

## Examples

Scan a local subnet for common services:

```
$ sudo python3 main.py 192.168.1.0/24 -p 22,80,443,3306,8080 --scan-private
```

Scan a /8 block for web servers at 50k pps and save results:

```
$ sudo python3 main.py 104.0.0.0/8 -p 80,443 -r 50000 --override-safety -o results.json
```

Scan the entire internet for SSH, stop after 500 hits:

```
$ sudo python3 main.py 0.0.0.0/0 -p 22 -r 100000 --override-safety -l 500
```

Unlimited rate, maximum throughput:

```
$ sudo python3 main.py 0.0.0.0/0 -p 80 -r 0 --override-safety --batch-size 8192 -w 4 -q
```

Scan with checkpoint — interrupt with Ctrl+C and resume later:

```
$ sudo python3 main.py 0.0.0.0/0 -p 443 -r 50000 --override-safety \
    --checkpoint scan.ckpt -o hits.json
^C

$ sudo python3 main.py 0.0.0.0/0 -p 443 -r 50000 --override-safety \
    --checkpoint scan.ckpt -o hits.json
[*] resuming scan from index 18432000 via checkpoint
```

Pipe results into other tools:

```
$ sudo python3 main.py 0.0.0.0/0 -p 443 --simple -q | httpx -silent
$ sudo python3 main.py 0.0.0.0/0 -p 80 --simple -q | nuclei -t cves/
$ sudo python3 main.py 0.0.0.0/0 -p 22 --simple -q > ssh_hosts.txt
```

Scan specific ports on multiple ranges:

```
$ sudo python3 main.py 104.0.0.0/8,45.0.0.0/8 -p 80,443,8443
```

Include targets from a file:

```
$ cat targets.txt
104.16.0.0/12
172.64.0.0/13
198.41.128.0/17

$ sudo python3 main.py --include-file targets.txt -p 443 -r 10000
```

Custom blacklist to avoid specific networks:

```
$ cat exclude.txt
203.0.113.0/24
198.51.100.0/24

$ sudo python3 main.py 0.0.0.0/0 -p 80 -b exclude.txt -r 50000 --override-safety
```

Reproducible scan — same seed produces the same IP order:

```
$ sudo python3 main.py 0.0.0.0/0 -p 80 --seed 42 -l 100 --simple -q > run1.txt
$ sudo python3 main.py 0.0.0.0/0 -p 80 --seed 42 -l 100 --simple -q > run2.txt
$ diff run1.txt run2.txt    # identical
```

Find the first N open hosts on a specific port:

```
$ sudo python3 main.py 0.0.0.0/0 -p 3389 -l 50 --simple -q
```

Scan all common ports on a single target range:

```
$ sudo python3 main.py 10.0.0.0/16 -p 21-25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443 \
    --scan-private -r 5000
```

UDP scan for DNS servers (using `--top-ports` or `-p 53`):

```
$ sudo python3 main.py 0.0.0.0/0 -p 53 --udp -r 100000 --override-safety
```

Service Discovery and Vulnerability Scanning (Requires `--banners` or `--vulns`):

```
$ sudo python3 main.py 192.168.1.0/24 -p 80,443,22 --banners --http-probe --vulns --resolve
```

## Distributed Scanning

Split a scan across multiple machines using `--shards` and `--shard-id`.
All nodes must use the same `--seed` value. Each node scans a disjoint
subset of IPs.

```
node0$ sudo python3 main.py 0.0.0.0/0 -p 80 --shards 3 --shard-id 0 --seed 1337 -r 0 --override-safety
node1$ sudo python3 main.py 0.0.0.0/0 -p 80 --shards 3 --shard-id 1 --seed 1337 -r 0 --override-safety
node2$ sudo python3 main.py 0.0.0.0/0 -p 80 --shards 3 --shard-id 2 --seed 1337 -r 0 --override-safety
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

## Project Structure

```
main.py              CLI entry point
makefile             compiles worker.c
REEcanner/
  worker.c           C transmit engine
  scanner.py         Scanner class, sniffer, process management
  utils.py           FeistelShuffler, BlacklistManager, InclusionManager
  packet.py          packet parsing utilities
  ports.py           Top ports definitions
  probes.py          Service banners and HTTP probes
  fingerprint.py     Service detection and vulnerabilty lookups
  vulns.py           Vulnerability checking against searchsploit
```

## Legal

This tool is intended for authorized security research and network
measurement. Unauthorized scanning may violate applicable laws and
terms of service. Ensure you have proper authorization before scanning
any network you do not own or have explicit permission to test.
