#!/usr/bin/env bash
#
# verify-udp-outcomes.sh — prove the UDP engine's `closed` and `open_filtered` from the
# kernel's own counters, without root.
#
# The claim under test: a UDP port is `closed` exactly when an ICMP port-unreachable came
# back for it, and `open_filtered` exactly when nothing did. A packet capture would settle
# that, and a capture needs root — `/dev/bpf*` is root-only, and the installed helper hands
# descriptors only to the signed app. So this settles it from the other side of the
# socket: the kernel counts every ICMP destination-unreachable it receives
# (`netstat -s -p icmp`, input histogram). Across one run, that count must rise by
# EXACTLY the number of ports the engine called `closed`.
#
#   rise > closed   an unreachable arrived and the engine did not report it — a port
#                   called `open_filtered` (or `open`) that the host had refused
#   rise < closed   the engine called a port `closed` with no ICMP behind it
#
# Either fails the run. The counter is system-wide, so unrelated traffic can push it up;
# a mismatch is worth re-running before believing, and a clean pass over many trials is
# not something unrelated traffic can manufacture.
#
# Usage: Scripts/verify-udp-outcomes.sh [host] [trials]
#   Defaults to the gateway and 10 trials. Uses .build/debug/zhen.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZHEN="$REPO/.build/debug/zhen"
HOST="${1:-$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')}"
TRIALS="${2:-10}"
# Ports nothing listens on, so every honest answer is `closed` or, when the host's ICMP
# budget is spent, `open_filtered`.
PORTS="U:9990,U:9991,U:9992,U:9993,U:9994,U:9995"

[ -x "$ZHEN" ] || { echo "verify-udp-outcomes: build first (swift build at the repository root)"; exit 2; }
[ -n "$HOST" ] || { echo "verify-udp-outcomes: no host given and no default route"; exit 2; }

unreachables() {
    netstat -s -p icmp 2>/dev/null \
        | awk '/Input histogram/ {inside=1; next} inside && /destination unreachable/ {print $3; found=1; exit} END {if (!found) print 0}'
}

echo "verify-udp-outcomes: $HOST, $TRIALS trials of $PORTS"
failures=0
total_closed=0; total_silent=0; total_rise=0
for trial in $(seq 1 "$TRIALS"); do
    before=$(unreachables)
    counts=$("$ZHEN" ports "$HOST" "$PORTS" --json | python3 -c '
import json, sys
ports = json.load(sys.stdin)["hosts"][0]["ports"]
states = [p["state"] for p in ports]
print(states.count("closed"), states.count("open_filtered"), states.count("filtered"), states.count("open"))')
    after=$(unreachables)
    read -r closed silent filtered open <<<"$counts"
    rise=$((after - before))
    verdict="ok"
    if [ "$rise" -ne "$closed" ]; then verdict="MISMATCH"; failures=$((failures + 1)); fi
    if [ "$filtered" -ne 0 ]; then verdict="SILENCE-AS-FILTERED"; failures=$((failures + 1)); fi
    printf '  trial %2d  closed %d  open_filtered %d  filtered %d  open %d  kernel saw %d unreachable  %s\n' \
        "$trial" "$closed" "$silent" "$filtered" "$open" "$rise" "$verdict"
    total_closed=$((total_closed + closed)); total_silent=$((total_silent + silent)); total_rise=$((total_rise + rise))
    sleep 2
done
echo "verify-udp-outcomes: closed $total_closed, open_filtered $total_silent, unreachables received $total_rise"
if [ "$failures" -eq 0 ]; then
    echo "verify-udp-outcomes: PASS — every closed port had an ICMP behind it, and no silent one did"
else
    echo "verify-udp-outcomes: FAIL — $failures trial(s) disagreed with the kernel"
fi
exit $((failures > 0))
