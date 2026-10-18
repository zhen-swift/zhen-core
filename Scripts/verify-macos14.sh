#!/usr/bin/env bash
#
# verify-macos14.sh — the binary Sonoma installs, run on Sonoma.
#
# Everything else about the macOS 14 floor is checked on a newer Mac. The compiler checks
# every API's availability, and `release-binary.sh --check` checks each slice's minos.
# Neither runs anything on 14. What only Sonoma can answer is whether the kernel there
# hands back what the parsers expect (routing messages, the neighbour table, ICMP
# datagrams, BPF records), and whether the lock that replaces `Atomic` below 15 counts
# the same. So this runs the real binary on a real Sonoma, against a real network, and
# reads what each run says about itself.
#
# Run it on a macOS 14 machine or VM with BRIDGED networking on the home LAN: a NAT'd VM
# sees a network of one, and every check below passes vacuously on it.
#
# History goes to a scratch file, never to ~/Library/Application Support/zhen/.
#
# Usage:
#
#     sudo ./Scripts/verify-macos14.sh [path-to-zhen]     # default: the zhen on PATH
#
# Root is for the privileged half: the ARP sweep and the half-open scan, which open
# /dev/bpf*. The unprivileged runs are made as $SUDO_USER, so they are genuinely
# unprivileged.

set -uo pipefail

WORK="$(mktemp -d /tmp/zhen-macos14.XXXXXX)"
chmod 755 "$WORK"
HISTORY="$WORK/history.ndjson"
fail=0

say()  { printf '%s\n' "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────"; }
die()  { printf 'verify-macos14: %s\n' "$*" >&2; exit 1; }
ok()   { say "  ok    $*"; }
bad()  { say "  FAIL  $*"; fail=1; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

[ "$(id -u)" = "0" ] || die "must run as root for the BPF half. Run: sudo $0 ${1:-}"
[ -n "${SUDO_USER:-}" ] || die "no SUDO_USER; invoke through sudo, not a root shell"

OS="$(sw_vers -productVersion)"
case "$OS" in
    14.*) ;;
    *) die "this is macOS $OS; the point is to run on 14" ;;
esac

BIN="${1:-$(sudo -u "$SUDO_USER" -i command -v zhen)}"
[ -x "$BIN" ] || die "no zhen at '$BIN'; pass its path, or brew install it first"

as_user() { sudo -u "$SUDO_USER" env ZHEN_HISTORY="$HISTORY" "$BIN" "$@"; }
as_root() { env ZHEN_HISTORY="$HISTORY" "$BIN" "$@"; }

say "macOS     $OS ($(uname -m))"
say "binary    $BIN"
say "history   $HISTORY"
rule

# ── 1. It launches, and says what it is ─────────────────────────────────────────
say "[1/4] the binary"
VERSION="$(as_user --version 2>&1)" || bad "--version exited non-zero: $VERSION"
case "$VERSION" in
    *"commit unknown"*) bad "--version is unstamped: $VERSION" ;;
    *) ok "--version: $VERSION" ;;
esac
if otool -P "$BIN" 2>/dev/null | grep -q NSLocalNetworkUsageDescription; then
    ok "Info.plist section embedded"
elif command -v otool >/dev/null; then
    bad "no Info.plist section in the binary"
else
    say "  skip  otool not installed; the Info.plist section was not read"
fi

# Reads one report and prints what it says about itself, then the checks this script
# makes of it. Exits non-zero if any check fails.
inspect() {
    /usr/bin/python3 - "$@" <<'PY'
import json, sys
path, label, want = sys.argv[1], sys.argv[2], sys.argv[3:]
try:
    report = json.load(open(path))
except Exception as error:
    print(f"  FAIL  {label}: no report ({error})")
    sys.exit(1)
run = report["run"]
engine = run["engine"]
caps = engine.get("capabilities", [])
devices = report["devices"]
ports = sum(len(d.get("ports", [])) for d in devices)
print(f"  {label}: outcome={run['outcome']} devices={len(devices)} ports={ports} "
      f"capabilities={','.join(caps)}")
for degradation in report.get("degradations", []):
    print(f"        degraded: {' '.join(degradation['reason'].split())[:110]}")
failed = False
def check(ok, message):
    global failed
    print(f"  {'ok  ' if ok else 'FAIL'}  {message}")
    failed = failed or not ok
check(run["outcome"] != "cancelled", "the run was not cancelled")
check(len(devices) > 1, f"more than this machine was found ({len(devices)})")
text = json.dumps(report.get("degradations", []))
check("Local Network" not in text, "no Local Network remedy (the permission does not exist on 14)")
for capability in want:
    check(capability in caps, f"engine has {capability}")
if "ports" in want or any(c in want for c in ("syn_scan", "connect_scan")):
    check(ports > 0, f"some port was observed ({ports})")
print(str(len(devices)), file=open(path + ".count", "w"))
sys.exit(1 if failed else 0)
PY
}

# ── 2. Unprivileged: routing socket, neighbour table, ICMP datagrams ────────────
rule
say "[2/4] unprivileged discovery, as $SUDO_USER"
as_user scan --discovery-only --json --quiet > "$WORK/unpriv.json" 2>"$WORK/unpriv.err"
inspect "$WORK/unpriv.json" "unprivileged" icmp_sweep neighbor_table || fail=1

# ── 3. Privileged: the ARP sweep through BPF ───────────────────────────────────
rule
say "[3/4] privileged discovery, as root"
as_root scan --discovery-only --json --quiet > "$WORK/priv.json" 2>"$WORK/priv.err"
inspect "$WORK/priv.json" "privileged" arp_sweep icmp_sweep || fail=1
UNPRIV="$(cat "$WORK/unpriv.json.count" 2>/dev/null || echo 0)"
PRIV="$(cat "$WORK/priv.json.count" 2>/dev/null || echo 0)"
if [ "$PRIV" -ge "$UNPRIV" ]; then
    ok "root found no fewer devices ($PRIV against $UNPRIV)"
else
    # Seconds apart on a live network, a phone can leave. Rerun before believing it.
    bad "root found fewer devices ($PRIV against $UNPRIV); rerun once before believing it"
fi

# ── 4. Ports: half-open through BPF as root, connect as the user ───────────────
rule
say "[4/4] port scans on 22, 80 and 443"
as_root scan --deep --scan-type syn --ports 22,80,443 --yes --json --quiet \
    > "$WORK/syn.json" 2>"$WORK/syn.err"
inspect "$WORK/syn.json" "syn as root" syn_scan || fail=1
as_user scan --deep --scan-type connect --ports 22,80,443 --yes --json --quiet \
    > "$WORK/connect.json" 2>"$WORK/connect.err"
inspect "$WORK/connect.json" "connect as user" connect_scan || fail=1

rule
if [ "$fail" = 0 ]; then
    say "verify-macos14: PASS on macOS $OS"
else
    say "verify-macos14: FAIL on macOS $OS. Stderr of each run, kept in the output above"
    for f in "$WORK"/*.err; do [ -s "$f" ] && { say "── $(basename "$f")"; tail -5 "$f"; }; done
fi
exit $fail
