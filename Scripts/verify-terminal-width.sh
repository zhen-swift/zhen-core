#!/usr/bin/env bash
# verify-terminal-width.sh — stage 1 of Docs/plans/PORTS-rendering.md.
#
# The gate: `zhen scan > out.txt` must produce identical bytes whether it was launched
# from an 80-column window or a 200-column one. A shell exports COLUMNS from its window,
# so the redirected run must ignore it.
#
# Two pairs of runs:
#
#   redirected  COLUMNS=80 vs COLUMNS=200, stdout to a file. MUST match.
#   pty         a real pseudo-terminal at 80 columns vs one at 200. This run scans
#               WITHOUT --deep, so there is no port table and nothing consults the
#               width: SAME is correct and stays correct. Stage 4 made the width
#               load-bearing for the port tables specifically, which this run does not
#               produce. `PortViewSelectionTests` is what measures that.
#
# A scan is not deterministic — RTTs move and hosts come and go — so the target is a
# single address and the volatile numbers are normalised before diffing. What survives
# normalisation is the table's shape, which is the thing width changes.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Built, not merely located. `--show-bin-path` prints a path without building one, so
# the first run of this script measured a binary from before the change it was checking.
swift build --package-path "$REPO" -c release >/dev/null
BIN="$(swift build --package-path "$REPO" -c release --show-bin-path)/zhen"
TARGET="${TARGET:-10.10.20.1/32}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[ -x "$BIN" ] || { echo "no binary at $BIN — build first" >&2; exit 1; }

# Milliseconds, probe counts and elapsed times move between runs; column positions do
# not. Blanking them is what lets two live runs be compared at all.
normalise() {
    # Two live scans cannot be compared byte for byte, and the reason is not the window.
    # The RTT column is sized to its widest value, so a run that measured 23.70ms and
    # one that measured 9.12ms produce tables a character apart. The first version of
    # this script substituted a shorter placeholder, which shifted every column after it
    # and reported a layout change that had not happened.
    #
    # So this collapses runs of whitespace. What survives is WHICH columns are present
    # and in what order, which is what a width change alters — a dropped MODEL column, an
    # added port column. What it cannot see is a pure padding change, and that is covered
    # byte-exactly by `RedirectedWidthTests` against a fixed report, where nothing varies.
    python3 -c '
import re, sys
for line in sys.stdin:
    line = re.sub(r"[0-9]+(\.[0-9]+)?ms", "MS", line)
    line = re.sub(r"[0-9]+ probes, [0-9]+ replies", "PROBES", line)
    line = re.sub(r"[0-9]+(\.[0-9]+)? probes/s", "RATE", line)
    sys.stdout.write(" ".join(line.split()) + "\n")
'
}

run_redirected() { COLUMNS="$1" "$BIN" scan --cidr "$TARGET" --quiet > "$2" 2>/dev/null; }

run_pty() {
    COLUMNS="$1" python3 - "$1" "$2" "$BIN" "$TARGET" <<'PY'
import os, pty, sys, fcntl, termios, struct
cols, out, binary, target = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
captured = bytearray()
def read(fd):
    data = os.read(fd, 4096)
    captured.extend(data)
    return b""                      # swallow it; we want the file, not the screen
def sized(fd):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, cols, 0, 0))
pid, master = pty.fork()
if pid == 0:
    os.execv(binary, [binary, "scan", "--cidr", target, "--quiet", "--no-color"])
sized(master)
try:
    while True:
        chunk = os.read(master, 4096)
        if not chunk: break
        captured.extend(chunk)
except OSError:
    pass
os.waitpid(pid, 0)
open(out, "wb").write(bytes(captured))
PY
}

echo "binary  $BIN"
echo "target  $TARGET"
echo

echo "── redirected: COLUMNS must not reach the file ──────────────────────────────"
run_redirected 80  "$WORK/redir-80.txt"
run_redirected 200 "$WORK/redir-200.txt"
normalise < "$WORK/redir-80.txt"  > "$WORK/redir-80.norm"
normalise < "$WORK/redir-200.txt" > "$WORK/redir-200.norm"
echo "COLUMNS=80  -> $(wc -c < "$WORK/redir-80.txt" | tr -d ' ') bytes, $(awk '{ if (length > m) m = length } END { print m+0 }' "$WORK/redir-80.txt") widest line"
echo "COLUMNS=200 -> $(wc -c < "$WORK/redir-200.txt" | tr -d ' ') bytes, $(awk '{ if (length > m) m = length } END { print m+0 }' "$WORK/redir-200.txt") widest line"
if diff -q "$WORK/redir-80.norm" "$WORK/redir-200.norm" >/dev/null; then
    echo "PASS  identical after normalisation"
    REDIR=0
else
    echo "FAIL  the window reached the file:"
    diff "$WORK/redir-80.norm" "$WORK/redir-200.norm" | head -20
    REDIR=1
fi
echo

echo "── pty: two real terminals, 80 and 200 columns ──────────────────────────────"
run_pty 80  "$WORK/pty-80.txt"
run_pty 200 "$WORK/pty-200.txt"
normalise < "$WORK/pty-80.txt"  > "$WORK/pty-80.norm"
normalise < "$WORK/pty-200.txt" > "$WORK/pty-200.norm"
echo "80 cols  -> $(awk '{ if (length > m) m = length } END { print m+0 }' "$WORK/pty-80.txt") widest line"
echo "200 cols -> $(awk '{ if (length > m) m = length } END { print m+0 }' "$WORK/pty-200.txt") widest line"
if diff -q "$WORK/pty-80.norm" "$WORK/pty-200.norm" >/dev/null; then
    echo "SAME  the two terminals rendered identically."
    echo "      Correct, and permanently so for this run: no --deep means no port"
    echo "      table, and the device table is width-independent by design. The width"
    echo "      is load-bearing only for the port tables, measured in"
    echo "      PortViewSelectionTests."
else
    echo "DIFFER  the two terminals rendered differently, which is what stage 2 wants."
    diff "$WORK/pty-80.norm" "$WORK/pty-200.norm" | head -10
fi

exit $REDIR
