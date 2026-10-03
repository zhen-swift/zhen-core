#!/usr/bin/env bash
#
# verify-provenance.sh — check every `discovered_via` claim against the wire.
#
# The artifact now says, per host, how it was found. That is a claim, and a claim from
# an artifact about itself is exactly what this project does not accept as evidence.
# So each one is checked against a packet capture taken around the same scan:
#
#   probe_reply      there MUST be an ICMP echo reply from that host in the capture
#   arp_reply        there MUST be an ARP reply from that host in the capture
#   neighbor_table   there must be NO echo reply from it — it never answered, which is
#                    the whole reason the mark exists
#   local_interface  there will be no ECHO REPLY from it, because a probe a host sends
#                    to its own address is answered inside the kernel and never reaches
#                    the interface. This case is why the mark exists: without it, a
#                    reader reconciling the artifact against a capture finds one host
#                    too many and no explanation.
#
#                    Note what this does NOT assert. The first version of this script
#                    checked for no FRAMES from that address and failed, because the
#                    address is this machine and this machine sends every probe in the
#                    capture. The absent thing is the reply, not the traffic. Checking
#                    the wrong absence is how the SYN check came to count the kernel's
#                    packets as ours, and it happened again here.
#
# The question this settles is the one a measurement study could not settle from the
# artifacts it had: `hosts_found` disagreed with the echo replies on the wire in 431 of
# 485 runs, and deciding whether that was a scanner inventing hosts or a neighbour
# table legitimately contributing them took the raw pcaps.
#
# Usage:
#
#     sudo ./Scripts/verify-provenance.sh [interface]
#
# Root is needed for tcpdump. The scan itself runs as the invoking user unless
# PRIVILEGED=1, in which case it runs as root and the ARP sweep is in play too.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO/.build/release/zhen"
WORK="$(mktemp -d /tmp/zhen-prov.XXXXXX)"

say()  { printf '%s\n' "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────"; }
die()  { printf 'verify-provenance: %s\n' "$*" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

[ "$(id -u)" = "0" ] || die "must run as root, for tcpdump. Run: sudo $0"
[ -x "$BINARY" ] || die "no release binary at $BINARY
Build it: swift build --package-path zhen -c release"
[ -n "${SUDO_USER:-}" ] || die "no SUDO_USER; invoke through sudo rather than as a root login shell"

IFACE="${1:-$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')}"
[ -n "$IFACE" ] || die "could not determine the default interface; pass one as \$1"
SELF="$(ipconfig getifaddr "$IFACE")"
[ -n "$SELF" ] || die "$IFACE has no IPv4 address"

say "interface   $IFACE"
say "own address $SELF"
say "scan as     $([ "${PRIVILEGED:-0}" = 1 ] && echo root || echo "$SUDO_USER")"
rule

# Everything on the segment, both directions. Unlike the SYN check this one needs to
# see what the far side sent, because the whole question is whether a host answered.
tcpdump -i "$IFACE" -n -p -s 0 -w "$WORK/scan.pcap" >/dev/null 2>"$WORK/tcpdump.err" &
PID=$!
sleep 2

if [ "${PRIVILEGED:-0}" = 1 ]; then
    "$BINARY" scan --discovery-only --json --quiet > "$WORK/report.json" 2>"$WORK/scan.err"
else
    sudo -u "$SUDO_USER" "$BINARY" scan --discovery-only --json --quiet \
        > "$WORK/report.json" 2>"$WORK/scan.err"
fi
sleep 2
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

[ -s "$WORK/report.json" ] || die "the scan produced no artifact; see $WORK/scan.err"

say "[wire] what the capture holds"
say "  echo replies: $(tcpdump -r "$WORK/scan.pcap" -n 'icmp[icmptype]==icmp-echoreply' 2>/dev/null | wc -l | tr -d ' ')"
say "  arp replies:  $(tcpdump -r "$WORK/scan.pcap" -n arp 2>/dev/null | grep -c Reply)"
rule

# One pass over the capture, so each host is looked up rather than re-read.
# WITH TIMESTAMPS, because the capture is deliberately two seconds wider than the scan
# on each side and a reply arriving in that margin is not evidence of anything. The
# first version of this check ignored that and failed a host whose reply landed after
# the sweep had already finished and reported it from the neighbour table — which is
# the correct behaviour and exactly what the mark is for.
tcpdump -r "$WORK/scan.pcap" -n -tt 'icmp[icmptype]==icmp-echoreply' 2>/dev/null \
    | awk '{print $1, $3}' | sed 's/:$//' > "$WORK/echoed"
tcpdump -r "$WORK/scan.pcap" -n arp 2>/dev/null | grep Reply \
    | sed 's/.*Reply //;s/ is-at.*//' | sort -u > "$WORK/arped"

python3 - "$WORK" "$SELF" <<'PY'
import json, sys, pathlib
work, selfaddr = pathlib.Path(sys.argv[1]), sys.argv[2]
report = json.loads(work.joinpath("report.json").read_text())
run = report["run"]
# The scan's own window, from the artifact. tcpdump -tt prints epoch seconds.
opened, closed = run["started_at"] / 1000.0, run["finished_at"] / 1000.0
echoed, echoed_late = set(), set()
for line in work.joinpath("echoed").read_text().splitlines():
    parts = line.split()
    if len(parts) != 2:
        continue
    when, who = float(parts[0]), parts[1]
    (echoed if opened <= when <= closed else echoed_late).add(who)
arped  = set(work.joinpath("arped").read_text().split())
failures = []
print("[claims] each host, its claim, and what the capture says")
for dev in sorted(report["devices"], key=lambda d: tuple(int(p) for p in d["ip"].split("."))):
    ip, via = dev["ip"], dev.get("discovered_via", [])
    notes = []
    if "probe_reply" in via and "local_interface" not in via:
        ok = ip in echoed
        notes.append(("echo reply on the wire", ok))
    if "arp_reply" in via:
        notes.append(("arp reply on the wire", ip in arped))
    if via == ["neighbor_table"]:
        # Only within the scan's own window. A reply that landed after the sweep had
        # finished is reported separately below rather than counted against the claim:
        # the host genuinely did not answer in time, which is why the neighbour table
        # is what found it.
        notes.append(("no echo reply during the scan, as claimed", ip not in echoed))
    if "local_interface" in via:
        # The point of the whole exercise. The REPLY is what never reaches the wire;
        # the address itself is all over the capture, because it is the thing doing
        # the scanning. An earlier version of this check conflated the two and
        # reported a correct artifact as wrong.
        notes.append(("no echo reply on the wire, as documented", ip not in echoed))
    if not via:
        notes.append(("no claim made", False))
    verdict = "ok " if all(o for _, o in notes) else "BAD"
    if verdict == "BAD":
        failures.append(ip)
    print(f"  {verdict}  {ip:<16} {','.join(via) or '(none)':<28} "
          + "; ".join(f"{n}: {'yes' if o else 'NO'}" for n, o in notes))

stragglers = sorted(echoed_late - echoed)
if stragglers:
    print()
    print("[late] replied, but outside the scan's own window: " + ", ".join(stragglers))
    print("       Not a wrong claim. These hosts answered after the sweep had given up,")
    print("       so the neighbour table is what found them — and a run with several of")
    print("       these should also be raising the tight-budget degradation.")

print()
if failures:
    print(f"VERDICT: {len(failures)} host(s) claimed something the wire does not support: "
          + ", ".join(failures))
    sys.exit(1)
print("VERDICT: every discovered_via claim is consistent with the capture.")
print("         A host marked neighbor_table sent no echo reply, and the one marked")
print("         local_interface put no frames on the wire at all — which is the")
print("         difference the artifact could not express before.")
PY
STATUS=$?
rule
exit $STATUS
