#!/usr/bin/env bash
#
# vantage_bench.sh — measure hosts/second at several scan rates.
#
# Some network paths (cloud providers, datacenter IPs) throttle scan traffic
# long before the guest stack does: the kernel reports zero drops and the
# sniffer receives every reply that reaches the NIC, yet far fewer replies
# arrive as the rate climbs. When that happens hosts/s plateaus and sending
# faster only wastes packets (and risks getting the IP flagged).
#
# Run this on each candidate vantage to pick the best rate / compare hosts.
#
# Usage:
#   sudo tools/vantage_bench.sh
#   PORTS=25565 SEED=321 LIMIT=20 RATES="2000 5000 10000" sudo -E tools/vantage_bench.sh
#
set -u

PORTS="${PORTS:-25565}"
SEED="${SEED:-321}"
LIMIT="${LIMIT:-20}"
RATES="${RATES:-2000 4000 6000 8000 10000}"
BIN="${REECANNER:-reecanner}"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (raw sockets): sudo $0" >&2
    exit 1
fi

echo "vantage benchmark  ports=$PORTS  seed=$SEED  limit=$LIMIT"
printf '%-8s %-12s %-14s %-8s\n' RATE SENT HOSTS_PER_SEC WALL

for R in $RATES; do
    start=$(date +%s.%N)
    out=$(timeout 90 "$BIN" -p "$PORTS" -r "$R" --seed "$SEED" -l "$LIMIT" \
          --no-color --no-preflight -q 2>&1)
    end=$(date +%s.%N)
    wall=$(awk "BEGIN{printf \"%.2f\", $end-$start}")
    sent=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g' \
           | grep -oE 'sent: [0-9,\.]+' | tail -1 | grep -oE '[0-9,\.]+')
    hps=$(awk "BEGIN{printf \"%.2f\", $LIMIT/$wall}")
    printf '%-8s %-12s %-14s %-8s\n' "$R" "${sent:-?}" "$hps" "$wall"
done

echo
echo "If hosts/s is flat across rates, this vantage is the bottleneck — scanning"
echo "faster will not find more. Options: use a different VPS/provider, scan from"
echo "a residential connection, or distribute across multiple source IPs."
