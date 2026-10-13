#!/usr/bin/env bash
#
# measure-arp-pacing.sh — what the ARP sweep's microburst actually costs on this link.
#
# The privileged sweep writes roughly one frame per address, back to back, as fast as
# the BPF device accepts them. On a wired segment that is free. On congested wifi a
# microburst can cause its own losses, and a dropped ARP request reads as a missing
# host — which lowers the recall the privileged engine exists to raise.
#
# ── Telling our ARP from the kernel's, which is the whole difficulty ───────────
#
# An unprivileged scan ALSO fills the air with ARP: the kernel has to resolve a MAC for
# every address the ICMP sweep pings. Those requests leave from this machine's hardware
# address, ask about the same addresses, and look exactly like ours to any filter
# written on source or target.
#
# The first version of this script did not account for that and reported a 57% loss
# figure that was measuring the kernel's traffic as much as the engine's. That is the
# identical mistake `verify-syn-scan.sh` made until e4d3760, where kernel SYNs were
# counted as the fingerprint probe's, and it is worth noticing that the mistake was
# available twice in the same week.
#
# So this does not filter. It runs the SAME scan twice — once unprivileged, where the
# BPF sweep cannot open a device and every ARP frame on the wire is therefore the
# kernel's, and once privileged, where the engine's frames are added to exactly that
# baseline. The engine's contribution is the difference, and nothing has to be asserted
# about what our frames look like in order to find it.
#
# It also prints the ARP request frame-length histogram for both runs, because our
# frames are built at 42 bytes and the kernel pads to the 60-byte Ethernet minimum. If
# that shows up as a clean split appearing only in the privileged run, the difference is
# visible directly rather than by subtraction, and the two methods check each other.
#
# ── What is measured ───────────────────────────────────────────────────────────
#
#   spacing     the real inter-frame gap between consecutive ARP requests, from the
#               capture's timestamps. The claim under test is about five microseconds.
#   responders  distinct hosts that sent an ARP reply.
#   answered    whether the responders needed more than one ask.
#
# Recall is deliberately NOT the metric: a host found is the composition's answer and
# the ICMP sweep is in that too.
#
# ── Usage ──────────────────────────────────────────────────────────────────────
#
#     sudo ./Scripts/measure-arp-pacing.sh [interface]
#
# Run it on wifi and again on a wired segment and compare the two reports.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO/.build/release/zhen"
WORK="$(mktemp -d /tmp/zhen-arp.XXXXXX)"

say()  { printf '%s\n' "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────"; }
die()  { printf 'measure-arp-pacing: %s\n' "$*" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

[ "$(id -u)" = "0" ] || die "must run as root, for the capture device. Run: sudo $0"
[ -x "$BINARY" ] || die "no release binary at $BINARY
Build it: swift build --package-path zhen -c release"
[ -n "${SUDO_USER:-}" ] || die "no SUDO_USER, so the unprivileged baseline cannot be run
as an ordinary user. Invoke through sudo rather than as a root login shell."

IFACE="${1:-$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')}"
[ -n "$IFACE" ] || die "could not determine an interface; pass one as \$1"
MAC="$(ifconfig "$IFACE" | awk '/ether/{print $2; exit}')"
[ -n "$MAC" ] || die "$IFACE has no hardware address"

# The link, in its own words. A loss number without the conditions it was taken under
# cannot be reproduced by anybody, including whoever ran it.
say "interface   $IFACE"
say "hardware    $MAC"
if system_profiler SPAirPortDataType 2>/dev/null | grep -q "^        ${IFACE}:"; then
    # From "Current Network Information" onward. Without that anchor this prints the
    # adapter's SUPPORTED modes and every channel it could theoretically use, which is
    # a specification rather than a measurement of the link the frames went over.
    system_profiler SPAirPortDataType 2>/dev/null \
        | sed -n "/^        ${IFACE}:/,/^        [a-z]/p" \
        | sed -n '/Current Network Information/,$p' \
        | grep -E "PHY Mode|Channel:|Signal / Noise|Transmit Rate" \
        | head -4 | sed 's/^ */link        /'
else
    say "link        not wifi ($(ifconfig "$IFACE" | awk '/media:/{$1="";print substr($0,2); exit}'))"
fi
rule

capture_run() {
    # Three statements, not one. Bash expands every word of a `local` before it
    # assigns any of them, so `pcap="$WORK/$label.pcap"` on the same line reads a
    # `label` that does not exist yet — which under `set -u` aborts the run.
    local label="$1"
    local privileged="$2"
    local pcap="$WORK/$label.pcap"
    tcpdump -i "$IFACE" -n -e -s 96 -w "$pcap" arp >/dev/null 2>"$pcap.log" &
    local pid=$!
    sleep 2
    if [ "$privileged" = yes ]; then
        "$BINARY" scan --discovery-only --quiet --json > "$WORK/$label.json" 2>"$WORK/$label.err"
    else
        sudo -u "$SUDO_USER" "$BINARY" scan --discovery-only --quiet --json \
            > "$WORK/$label.json" 2>"$WORK/$label.err"
    fi
    sleep 2
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

say "[1/2] unprivileged scan — every ARP frame here is the kernel's"
capture_run unpriv no
say "[2/2] privileged scan — the kernel's, plus the sweep's"
capture_run priv yes
rule

python3 - "$WORK" "$MAC" <<'PY'
import subprocess, sys, pathlib, collections
work, mac = pathlib.Path(sys.argv[1]), sys.argv[2].lower()

def read(pcap):
    out = subprocess.run(["tcpdump","-r",str(pcap),"-n","-tt","-e","arp"],
                         capture_output=True, text=True).stdout.splitlines()
    requests, replies, lengths = [], collections.Counter(), collections.Counter()
    for ln in out:
        parts = ln.split()
        if "Request" in ln and mac in ln.lower():
            try:
                target = parts[parts.index("who-has") + 1]
                requests.append((float(parts[0]), target))
                lengths[parts[-1]] += 1
            except (ValueError, IndexError):
                pass
        elif "Reply" in ln:
            try:
                replies[parts[parts.index("Reply") + 1]] += 1
            except (ValueError, IndexError):
                pass
    return requests, replies, lengths

def spacing(requests):
    gaps = sorted(b[0] - a[0] for a, b in zip(requests, requests[1:]))
    if not gaps:
        return "n/a", "n/a"
    return (f"{gaps[len(gaps)//2]*1e6:.1f}us",
            f"{gaps[min(int(len(gaps)*0.99), len(gaps)-1)]*1e6:.1f}us")

report = {}
for label in ("unpriv", "priv"):
    req, rep, lengths = read(work / f"{label}.pcap")
    report[label] = (req, rep, lengths)
    med, p99 = spacing(req)
    asked = collections.Counter(t for _, t in req)
    name = "privileged  " if label == "priv" else "unprivileged"
    print(f"  {name}  ARP requests {len(req):5d} to {len(asked):3d} addresses   "
          f"spacing median {med} p99 {p99}")
    print(f"                replies from {len(rep):3d} distinct hosts   "
          f"frame lengths { {k: v for k, v in lengths.most_common(4)} }")

ureq, urep, ulen = report["unpriv"]
preq, prep, plen = report["priv"]
ours = len(preq) - len(ureq)

print()
print("  The sweep's own contribution, by subtraction:")
print(f"    privileged requests {len(preq)} - unprivileged {len(ureq)} = {ours}")
extra = {k: plen[k] - ulen.get(k, 0) for k in plen if plen[k] - ulen.get(k, 0) > 0}
print(f"    and by frame length, the lengths the privileged run added: {extra}")
print()
print(f"  Distinct ARP responders: unprivileged {len(urep)}, privileged {len(prep)}.")

if ours <= 0:
    print()
    print("  VERDICT: the privileged run put no additional ARP on the wire. Either the")
    print("           capture device could not be opened — check the artifact's")
    print("           degradations — or the sweep did not run. Nothing about loss can")
    print("           be concluded from this, and no pacing decision should be made.")
    sys.exit(1)

lost = 0
asked_p = collections.Counter(t for _, t in preq)
present = set(prep) & set(asked_p)
to_present = sum(asked_p[a] for a in present)
lost = to_present - len(present)
rate = 100 * lost / to_present if to_present else 0.0
print(f"  Requests to hosts known present: {to_present}, of which {lost} drew no reply "
      f"({rate:.1f}%).")
print("  That figure still includes the kernel's asks to the same hosts; it bounds the")
print("  loss from above rather than measuring the sweep's alone.")
print()
if rate < 2:
    print("  VERDICT: under 2% against an upper bound, so the sweep's own loss is lower")
    print("           still. The three attempts already absorb it and pacing would buy")
    print("           nothing but wall clock.")
else:
    print("  VERDICT: the upper bound is material. Before adding pacing, re-run this on")
    print("           a wired segment: if the same bound appears there, it is the")
    print("           subnet's emptiness and the retransmit schedule showing through,")
    print("           not the radio. Pacing 762 frames at 1ms costs 0.76s of wall clock")
    print("           on every privileged scan, which is most of the budget a --deadline")
    print("           of 1s allows, so it needs the wired comparison first.")
PY
STATUS=$?
rule
exit $STATUS
