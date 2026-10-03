#!/usr/bin/env bash
#
# verify-syn-scan.sh — prove the half-open scan from the wire, not from the artifact.
#
# `Scripts/verify-privileged.sh` settles the ARP sweep by volume: running as root puts
# three times as many ARP requests on the wire, and nothing about `sudo` makes the
# kernel do that. The SYN scan can be settled far more sharply, because a half-open scan
# and a connect scan leave *structurally* different traces and neither can be mistaken
# for the other:
#
#   Connect scan (unprivileged). The kernel opens a socket per probe, so every SYN
#   leaves from a DIFFERENT ephemeral source port, and when a port is open the kernel
#   finishes the handshake — SYN, SYN-ACK, ACK. The ACK is the giveaway: it is the
#   thing a half-open scan never sends.
#
#   Half-open scan (privileged). Every SYN leaves from ONE source port, the one the BPF
#   filter is matched on, because the engine writes the frames itself. No ACK is ever
#   sent. What does come back out of this machine is a RST, from our own kernel, which
#   has received a SYN-ACK for a connection no socket knows about — that RST is what
#   tears the half-open connection down, and it is why the scan is half-open from our
#   side rather than from the network's.
#
# So: one source port and no ACKs is a half-open scan, and many source ports with ACKs
# is a connect scan. Neither of those is something an artifact can claim itself into.
#
# ── The --scan-type gate, added with stage 7 ──────────────────────────────────
#
# The comparison above varies TWO things at once: the privilege and, as a consequence,
# the mechanism. That was the only comparison available while the mechanism was chosen
# for you. `--scan-type` makes a sharper one possible — run BOTH scans as root and vary
# only the flag — which is what `--scan-type-gate` does. If forcing `connect` still
# produced a half-open scan, privilege would no longer be able to hide it.
#
# Usage:
#
#     sudo ./Scripts/verify-syn-scan.sh [interface]
#     sudo ./Scripts/verify-syn-scan.sh --scan-type-gate [interface]

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO/.build/release/zhen"
WORK="$(mktemp -d /tmp/zhen-syn.XXXXXX)"
PORTS="${PORTS:-22,80,443}"

say()  { printf '%s\n' "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────"; }
die()  { printf 'verify-syn-scan: %s\n' "$*" >&2; exit 1; }

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

[ "$(id -u)" = "0" ] || die "must run as root. Run: sudo $0"
[ -x "$BINARY" ] || die "no release binary at $BINARY
Build it: swift build -c release"
[ -n "${SUDO_USER:-}" ] || die "no SUDO_USER, so the unprivileged comparison cannot be
made as an ordinary user. Invoke through sudo rather than as a root login shell."

MODE=default
if [ "${1:-}" = "--scan-type-gate" ]; then MODE=scantype; shift; fi

IFACE="${1:-$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')}"
[ -n "$IFACE" ] || die "could not determine the default interface; pass one as \$1"
MAC="$(ifconfig "$IFACE" | awk '/ether/{print $2; exit}')"
[ -n "$MAC" ] || die "$IFACE has no hardware address"

say "interface     $IFACE"
say "hardware      $MAC"
say "ports         $PORTS"
rule

# Only what this machine emits. A reply is the far side's business; what is being
# established here is which frames WE put on the wire.
capture() {
    local out="$1"
    tcpdump -i "$IFACE" -n -p -w "$out" "tcp and ether src $MAC" \
        >/dev/null 2>"$out.log" &
    echo $!
}

if [ "$MODE" = scantype ]; then
    say "MODE: --scan-type gate. Both scans run AS ROOT, so privilege is constant and"
    say "      the only variable is the flag."
    rule
    say "[1/3] root, --scan-type connect, under capture"
    PID=$(capture "$WORK/unpriv.pcap"); sleep 2
    "$BINARY" scan --deep --ports "$PORTS" --scan-type connect --deadline 30s --json \
        > "$WORK/unpriv.json" 2>"$WORK/unpriv.err"
    sleep 2; kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

    say "[2/3] root, --scan-type syn, under capture"
    PID=$(capture "$WORK/priv.pcap"); sleep 2
    "$BINARY" scan --deep --ports "$PORTS" --scan-type syn --deadline 30s --json \
        > "$WORK/priv.json" 2>"$WORK/priv.err"
    sleep 2; kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
else

say "[1/3] unprivileged deep scan as $SUDO_USER, under capture"
PID=$(capture "$WORK/unpriv.pcap"); sleep 2
sudo -u "$SUDO_USER" "$BINARY" scan --deep --ports "$PORTS" --deadline 30s --json \
    > "$WORK/unpriv.json" 2>"$WORK/unpriv.err"
sleep 2; kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

say "[2/3] privileged deep scan as root, under capture"
PID=$(capture "$WORK/priv.pcap"); sleep 2
"$BINARY" scan --deep --ports "$PORTS" --deadline 30s --json \
    > "$WORK/priv.json" 2>"$WORK/priv.err"
sleep 2; kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
fi

rule
say "[3/3] what the wire says"

# A bare SYN: SYN set, ACK clear. The source port is field 2 of tcpdump's dotted
# address, which is why the sed pulls the last dotted component.
syn_source_ports() {
    tcpdump -r "$1" -n "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" \
        2>/dev/null | awk '{print $3}' | sed 's/.*\.//' | sort -u
}
count_flag() {
    tcpdump -r "$1" -n "$2" 2>/dev/null | wc -l | tr -d ' '
}

# A `tcp src port A or ... or Z` clause over a set of ports.
#
# Restricting to the scan's OWN source ports is not a nicety. This machine is online:
# the naming stage fetches UPnP description documents over HTTP, and the browser and
# everything else keep talking throughout. Counting every bare ACK this Mac emits
# measured the whole machine and reported 136 handshake completions during a scan that
# completed none of them — a real number, answering the wrong question.
port_clause() {
    local first=1 clause=""
    for port in $1; do
        [ -n "$port" ] || continue
        if [ $first = 1 ]; then clause="tcp src port $port"; first=0
        else clause="$clause or tcp src port $port"; fi
    done
    [ -n "$clause" ] && printf '(%s)' "$clause" || printf 'tcp src port 0'
}

for label in unpriv priv; do
    pcap="$WORK/$label.pcap"
    if [ "$MODE" = scantype ]; then
        name=$([ "$label" = priv ] && echo "root --scan-type syn    " || echo "root --scan-type connect")
    else
        name=$([ "$label" = priv ] && echo "privileged  " || echo "unprivileged")
    fi
    ports=$(syn_source_ports "$pcap")
    distinct=$(printf '%s\n' "$ports" | grep -c . )
    clause=$(port_clause "$ports")
    syns=$(count_flag "$pcap" "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0")
    # A bare ACK from a port the scan sent a SYN from: ACK set, SYN and RST and FIN
    # clear. This is the handshake completion a half-open scan never sends.
    acks=$(count_flag "$pcap" "$clause and tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & (tcp-syn|tcp-rst|tcp-fin) == 0")
    rsts=$(count_flag "$pcap" "$clause and tcp[tcpflags] & tcp-rst != 0")
    say ""
    say "  $name  SYNs sent $syns   distinct source ports $distinct   bare ACKs $acks   RSTs $rsts"
    say "                source ports: $(printf '%s ' $ports | cut -c1-60)"
done

# The stack-fingerprint probe, isolated by the SHAPE of its option block.
#
# The obvious test — "a SYN that carries options" — is wrong, and this script shipped it
# wrong. Every connect() the kernel makes carries options too, so that count measured the
# banner probe and the rest of the machine: it printed 27 for the unprivileged run while
# the line above it claimed only the privileged path emits them. A check whose own output
# contradicts its label is not evidence of anything.
#
# The real discriminator is the ORDER, because the two SYNs are built by different code:
#
#   ours    mss 1460, sackOK, TS, nop, wscale 7   — IPv4Packet.fingerprintOptions,
#                                                    Linux's order, offered deliberately
#   Darwin  mss 1460, nop, wscale, nop, nop, TS, sackOK, eol
#
# SACK-permitted immediately after the MSS is something this machine's own stack never
# emits, so `mss <n>,sackOK` in tcpdump's rendering is a frame we wrote by hand.
ours() {
    tcpdump -r "$1" -n \
        "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and tcp[12] >> 4 > 5" \
        2>/dev/null | grep -E 'options \[mss [0-9]+,sackOK'
}
say ""
say "  Hand-built SYNs carrying our option block (mss then sackOK, which this"
say "  machine's own stack never emits), so these are the fingerprint probes:"
for label in unpriv priv; do
    if [ "$MODE" = scantype ]; then
        name=$([ "$label" = priv ] && echo "root --scan-type syn    " || echo "root --scan-type connect")
    else
        name=$([ "$label" = priv ] && echo "privileged  " || echo "unprivileged")
    fi
    say "    $name  $(ours "$WORK/$label.pcap" | wc -l | tr -d ' ')"
done
ours "$WORK/priv.pcap" | head -2 | sed 's/^/    /'
say ""
say "  and for contrast, a kernel SYN from the same run — different order, so a"
say "  count of \"SYNs with options\" would have swept both up together:"
tcpdump -r "$WORK/priv.pcap" -n \
    "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and tcp[12] >> 4 > 5" \
    2>/dev/null | grep -vE 'options \[mss [0-9]+,sackOK' | head -1 | sed 's/^/    /'

say ""
say "  The first SYNs of the privileged run, with flags:"
tcpdump -r "$WORK/priv.pcap" -n -c 6 \
    "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null \
    | sed 's/^/    /'

rule

# The busiest source port, and whether it ever completed a handshake.
#
# Counting every SYN this machine sends stopped working once the banner probe existed:
# it opens genuine connections on BOTH paths, from kernel ephemeral ports, and those
# legitimately carry options and legitimately ACK. The half-open scan is not
# "the machine sent SYNs", it is "ONE port sent hundreds of SYNs and never finished a
# handshake" — which nothing the kernel does can imitate, because connect() takes a
# fresh port per socket.
busiest_port() {
    tcpdump -r "$1" -n "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" \
        2>/dev/null | awk '{print $3}' | sed 's/.*\.//' | sort | uniq -c | sort -rn \
        | head -1 | awk '{print $2, $1}'
}

read -r PRIV_PORT PRIV_COUNT <<<"$(busiest_port "$WORK/priv.pcap")"
read -r UNPRIV_PORT UNPRIV_COUNT <<<"$(busiest_port "$WORK/unpriv.pcap")"
PRIV_PORT_ACKS=$(count_flag "$WORK/priv.pcap" "tcp src port ${PRIV_PORT:-0} and tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & (tcp-syn|tcp-rst|tcp-fin) == 0")

say "  busiest single source port:"
say "    unprivileged   port ${UNPRIV_PORT:-none} sent ${UNPRIV_COUNT:-0} SYN(s)"
say "    privileged     port ${PRIV_PORT:-none} sent ${PRIV_COUNT:-0} SYN(s), and completed $PRIV_PORT_ACKS handshake(s)"
say ""

if [ "${PRIV_COUNT:-0}" -ge 5 ] && [ "$PRIV_PORT_ACKS" = "0" ] && [ "${UNPRIV_COUNT:-0}" -le 2 ]; then
    say "VERDICT: one port on the privileged run sent ${PRIV_COUNT} SYNs and finished no"
    say "handshake. connect() cannot do that — it takes a fresh ephemeral port per socket,"
    say "which is why the unprivileged run's busiest port managed ${UNPRIV_COUNT}. The"
    say "remaining connections on both runs are the banner probe, which is supposed to"
    say "complete handshakes and does."
else
    say "VERDICT: not the expected trace. The privileged run's busiest port sent"
    say "${PRIV_COUNT:-0} SYNs (want >= 5) and completed $PRIV_PORT_ACKS handshakes (want 0);"
    say "the unprivileged run's busiest sent ${UNPRIV_COUNT:-0} (want <= 2)."
fi

say ""
say "  capabilities each artifact reported:"
/usr/bin/python3 - "$WORK/unpriv.json" "$WORK/priv.json" <<'PY'
import json, sys
for label, path in (("unprivileged", sys.argv[1]), ("privileged", sys.argv[2])):
    try:
        report = json.load(open(path))
    except Exception as error:
        print(f"    {label:<13} unreadable: {error}")
        continue
    engine = report["run"]["engine"]
    print(f"    {label:<13} {engine['kind']:<12} {','.join(engine['capabilities'])}")
PY
