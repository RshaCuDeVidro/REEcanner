# Vantage: why a cloud VPS finds fewer hosts than a home connection

When the same scan (`--seed` identical, same code, same ports) finds far fewer
hosts on a cloud VPS than on a residential machine, the usual suspect is the
**network path**, not the scanner and not the guest kernel.

This document records the diagnosis method and the conclusion.

## Symptom

Same seed, same commit, same target space, but the VPS needs many more probes
per hit than the home connection:

| vantage | packets to find 10 |
|---|---|
| home (10k pps) | ~29,000 |
| Oracle Cloud VPS (10k pps) | ~104,000–185,000 |

## Diagnosis (in order)

1. **Local stack is idle and lossless during the scan**
   - `top` shows ~97% idle; the scanner is not CPU bound.
   - `ip -s link` / `/proc/net/softnet_stat`: 0 dropped on RX and TX.
   - `nstat`/`netstat -s`: no receive-buffer or softnet drops.

2. **The firewall already accepts the replies**
   - `iptables -S INPUT` has `-p tcp --dport 10000:38999 --tcp-flags SYN,ACK SYN,ACK -j ACCEPT`
     (the scanner picks its source port in `10000:38999`), before the final `-j REJECT`.

3. **The scanner receives *everything* the NIC sees** (decisive test)
   - Capture SYN-ACKs on the wire and cross-check against the tool's hits:

     ```bash
     sudo tcpdump -ni ens3 -w /tmp/cap.pcap 'tcp port 25565' &
     sudo reecanner -p 25565 -r 10000 --seed 321 --no-color --no-preflight --simple > /tmp/tool.txt
     tcpdump -nr /tmp/cap.pcap 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)' \
       | awk '{print $3}' | sed 's/\.[0-9]*$//' | sort -u   # NIC
     grep -E '^[0-9]' /tmp/tool.txt | sed 's/:25565//' | sort -u   # tool
     ```
   - Result: the NIC and the tool lists are **identical**. No local loss.

4. **hosts/second is flat across rates**
   - `sudo tools/vantage_bench.sh` shows ~same hosts/s at 2k, 4k, 6k, 8k, 10k pps.
   - Meaning: the path delivers a roughly constant number of probes/second
     regardless of how fast you send — the excess is dropped upstream.

## Conclusion

The loss happens **before the packet reaches the VPS**: the datacenter network
(and/or how targets treat a datacenter IP) throttles high-rate scan traffic.
Nothing in the guest fixes it:

- `modprobe -r nf_conntrack` — `nf_conntrack` is usually builtin, and the
  matching firewall rule already exists; no effect.
- `net.core.rmem_max/wmem_max`, `netdev_max_backlog`, `txqueuelen` — no effect
  (the guest already reports zero drops).

## What actually helps

1. **Pick the best rate, don't over-send.** If hosts/s is flat, scan at the
   lowest rate that reaches the plateau — sending more wastes packets and risks
   the IP being flagged. (`sudo tools/vantage_bench.sh`)
2. **Multiple source IPs.** If the cap is per source IP, distributing workers
   across several IPs (secondary IPs/VNICs on the instance) multiplies the
   delivered probe rate. *Not currently supported by reecanner — the send path
   uses a single `local_ip`.*
3. **Better vantage.** A VPS/residential host with better peering will simply
   deliver more probes/s.
4. **Retries.** `--retries 2` recovers sporadic loss at the cost of traffic.

## Quick reference: run the benchmark on a new vantage

```bash
sudo tools/vantage_bench.sh
```
