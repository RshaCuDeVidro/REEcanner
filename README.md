# reecanner

a fast and minimalist ip/port scout designed for network research and discovery. built for speed using raw sockets and feistel-based shuffling for non-sequential scanning.

## usage

requires root privileges for raw socket access.

```bash
sudo python3 main.py 192.168.1.0/24 -p 80,443,8080
```

## features

- **raw sockets**: high-performance packet generation.
- **shuffling**: uses a feistel cipher to scan addresses in a random-looking but reproducible order.
- **sharding**: split a scan across multiple machines easily.
- **resume**: native checkpoint support to continue long scans.
- **flexible targets**: supports cidrs, inclusion files, and blacklists.

## options

- `target`: target cidr (e.g., 45.0.0.0/8).
- `-p, --ports`: ports to scan (e.g., 80 or 80,443,1000-2000).
- `-r, --rate-limit`: packets per second (default: 1000).
- `-o, --output`: save results to a json file.
- `--simple`: output only ip:port to stdout (clean for piping).
- `--checkpoint`: path to save/resume scan state.
- `--shards / --shard-id`: distribute scan across multiple nodes.
- `--scan-private`: allow scanning private/local networks.
- `--override-safety`: allow rate limits above 10,000 pps.

## examples

### distributed scanning (2 nodes)

node 1:
```bash
sudo python3 main.py 45.0.0.0/8 -p 80 --shards 2 --shard-id 0
```

node 2:
```bash
sudo python3 main.py 45.0.0.0/8 -p 80 --shards 2 --shard-id 1
```

### pipe to other tools

```bash
sudo python3 main.py 104.0.0.0/8 -p 443 --simple | httpx
```

## installation

```bash
pip install -r requirements.txt
```
