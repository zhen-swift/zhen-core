#!/usr/bin/env bash
#
# verify-privileged.sh — prove the layer-2 sweep from the wire, not from the artifact.
#
# The artifact says `"kind": "composite"` because the code put that string there. That
# is exactly the kind of evidence the measurement study threw out: `zhen-core`
# declared `EngineKind.privilegedBPF` and `EngineCapabilities.arpSweep` for months while
# constructing neither, and the claim was only settled by a packet capture — which
# showed the privileged and unprivileged runs emitting identical traffic, 253 ARP
# requests against 253, and led to hypothesis H3 being withdrawn on 2026-09-12.
#
# So this script asks the same question the same way, and it is the only acceptable
# answer to "does the privileged engine do anything".
#
# ── What separates our ARP from the kernel's ────────────────────────────────────
#
# They are structurally identical, and deliberately so: an ARP request with anything
# unusual in it is an ARP request some stack declines to answer. Both carry this
# machine's hardware address as the source and the broadcast address as the
# destination, because that is what RFC 826 says a request is.
#
# What separates them is volume, and the separation is not subtle. An unprivileged scan
# emits ARP only as a side-effect: the kernel resolving next-hop for the ICMP sweep's
# datagrams, roughly one request per address it has no cache entry for. A privileged
# scan emits that PLUS this engine's own sweep, which is `attempts` requests for every
# address in the target — three times 254 on a /24.
#
# There is no mechanism by which running the same command under `sudo` makes the KERNEL
# emit three to four times as many ARP requests for the same ICMP sweep. If the count
# jumps, the extra frames are ours.
#
# Usage:
#
#     sudo ./Scripts/verify-privileged.sh [interface]
#
# It needs root for two things and says which: the packet capture, and the scan whose
# privileged half is the thing under test. The unprivileged comparison run is executed
# back as the invoking user via $SUDO_USER, so it is a genuine unprivileged run rather
# than root pretending.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO/.build/release/zhen"
WORK="$(mktemp -d /tmp/zhen-verify.XXXXXX)"

say()  { printf '%s\n' "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────"; }
die()  { printf 'verify-privileged: %s\n' "$*" >&2; exit 1; }

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

[ "$(id -u)" = "0" ] || die "must run as root — it needs tcpdump and a /dev/bpf* node.
Run: sudo $0"
[ -x "$BINARY" ] || die "no release binary at $BINARY
Build it first: swift build -c release"
[ -n "${SUDO_USER:-}" ] || die "no SUDO_USER, so the unprivileged comparison run cannot
be made as an ordinary user. Invoke through sudo rather than as a root login shell."

# The interface the default route points out of, which is what the scanner picks too.
IFACE="${1:-$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')}"
[ -n "$IFACE" ] || die "could not determine the default interface; pass one as \$1"
MAC="$(ifconfig "$IFACE" | awk '/ether/{print $2; exit}')"
[ -n "$MAC" ] || die "$IFACE has no hardware address, so there is no ARP to sweep on it"

say "interface     $IFACE"
say "hardware      $MAC"
say "binary        $BINARY"
rule

# ── 1. The unprivileged baseline ────────────────────────────────────────────────
#
# Captured as well as the privileged run, because the count only means anything as a
# comparison. This is the run the study measured at 253 ARP requests.
say "[1/4] unprivileged scan as $SUDO_USER, under capture"
tcpdump -i "$IFACE" -n -p -w "$WORK/unpriv.pcap" "arp and ether src $MAC" \
    >/dev/null 2>"$WORK/unpriv.tcpdump.log" &
UNPRIV_TCPDUMP=$!
sleep 2
sudo -u "$SUDO_USER" "$BINARY" scan --discovery-only --json > "$WORK/unpriv.json" 2>"$WORK/unpriv.err"
UNPRIV_STATUS=$?
sleep 2
kill "$UNPRIV_TCPDUMP" 2>/dev/null; wait "$UNPRIV_TCPDUMP" 2>/dev/null

# ── 2. The privileged run ───────────────────────────────────────────────────────
say "[2/4] privileged scan as root, under capture"
tcpdump -i "$IFACE" -n -p -w "$WORK/priv.pcap" "arp and ether src $MAC" \
    >/dev/null 2>"$WORK/priv.tcpdump.log" &
PRIV_TCPDUMP=$!
sleep 2
"$BINARY" scan --discovery-only --json > "$WORK/priv.json" 2>"$WORK/priv.err"
PRIV_STATUS=$?
sleep 2
kill "$PRIV_TCPDUMP" 2>/dev/null; wait "$PRIV_TCPDUMP" 2>/dev/null

# ── 3. What each run said about itself ──────────────────────────────────────────
rule
say "[3/4] what the artifacts claim — NOT the evidence, just the claim"
/usr/bin/python3 - "$WORK/unpriv.json" "$WORK/priv.json" <<'PY'
import json, sys
for label, path in (("unprivileged", sys.argv[1]), ("privileged  ", sys.argv[2])):
    try:
        report = json.load(open(path))
    except Exception as error:
        print(f"  {label}: could not read report: {error}")
        continue
    engine = report["run"]["engine"]
    stages = report["run"]["timing"]["stages"]
    discovery = next((s for s in stages if s["stage"] == "discovery"), {})
    print(f"  {label}  kind={engine['kind']:<12} name={engine['name']:<18} "
          f"capabilities={','.join(engine['capabilities'])}")
    print(f"                devices={len(report['devices']):<4} "
          f"probes={discovery.get('probes_sent')} replies={discovery.get('replies_seen')} "
          f"elapsed={discovery.get('elapsed_millis', 0):.0f}ms "
          f"outcome={report['run']['outcome']}")
    for degradation in report["degradations"]:
        print(f"                degraded: {' '.join(degradation['reason'].split())[:100]}")

# "Root must never find fewer hosts" is the property the composite exists to hold, so it
# is checked on the address sets rather than on the counts. The two runs are seconds
# apart on a live network, so a host in one and not the other may simply have arrived or
# left; both directions are printed and the reader decides. A host only the privileged
# run found is what ARP bought.
import ipaddress
reports = {}
for label, path in (("unprivileged", sys.argv[1]), ("privileged", sys.argv[2])):
    try:
        reports[label] = json.load(open(path))
    except Exception:
        reports[label] = None

if all(reports.values()):
    sets = {label: {device["ip"] for device in report["devices"]}
            for label, report in reports.items()}
    def order(addresses):
        return " ".join(sorted(addresses, key=ipaddress.ip_address))
    only_privileged = sets["privileged"] - sets["unprivileged"]
    only_unprivileged = sets["unprivileged"] - sets["privileged"]
    print()
    print(f"  found by both              {len(sets['privileged'] & sets['unprivileged'])}")
    print(f"  privileged run only        {len(only_privileged)}  {order(only_privileged)}")
    print(f"  unprivileged run only      {len(only_unprivileged)}  {order(only_unprivileged)}")
    if only_unprivileged:
        print("    ^ worth a second look: either the host left between the two runs, or")
        print("      the composite lost something, which is the one thing it may not do.")
PY

# ── 4. What the wire says ───────────────────────────────────────────────────────
rule
say "[4/4] what the wire says — this is the evidence"
UNPRIV_ARP=$(tcpdump -r "$WORK/unpriv.pcap" -n "arp[6:2] = 1" 2>/dev/null | wc -l | tr -d ' ')
PRIV_ARP=$(tcpdump -r "$WORK/priv.pcap" -n "arp[6:2] = 1" 2>/dev/null | wc -l | tr -d ' ')

say ""
say "  ARP requests emitted by $MAC during the scan:"
say "    unprivileged   $UNPRIV_ARP   (the kernel resolving next-hop for the ICMP sweep)"
say "    privileged     $PRIV_ARP   (the same, plus this engine's own sweep)"
say ""
say "  The first twelve request frames of the privileged run:"
tcpdump -r "$WORK/priv.pcap" -n -e -t "arp[6:2] = 1" 2>/dev/null | head -12 | sed 's/^/    /'
say ""
say "  Their arrival, to the microsecond — our sweep is a burst, the kernel's retry"
say "  schedule is not:"
tcpdump -r "$WORK/priv.pcap" -n -tt "arp[6:2] = 1" 2>/dev/null | head -8 | sed 's/^/    /'

rule
# Three attempts across a /24 is ~762 frames of ours on top of the kernel's ~253, so
# anything under twice the baseline means the sweep did not reach the wire.
if [ "$UNPRIV_ARP" -gt 0 ] && [ "$PRIV_ARP" -ge $((UNPRIV_ARP * 2)) ]; then
    say "VERDICT: the privileged run put $((PRIV_ARP - UNPRIV_ARP)) more ARP requests on the wire"
    say "than the unprivileged run of the same command. Running as root does not make the"
    say "kernel ARP more; those frames are the layer-2 sweep."
else
    say "VERDICT: no additional ARP traffic under root. The layer-2 sweep did not reach"
    say "the wire — check the degradations above and the tcpdump stderr in the report."
fi
say ""
say "  exit status: unprivileged $UNPRIV_STATUS, privileged $PRIV_STATUS"
say "  reports kept? no — rerun with WORK=… if you want them; this directory is temporary."
