#!/usr/bin/env bash
#
# install.sh — build zhen for release and put it, and its manual, on the system.
#
# ── What this script will not do ───────────────────────────────────────────────
#
# It never runs `sudo` and never asks for a password. If the destination is not
# writable it says so, prints the exact command to run, and exits — because a build
# script that escalates on its own behalf is how a machine ends up with root-owned
# files nobody remembers agreeing to. Installing into a prefix you own needs no
# privilege at all, which is why `PREFIX` exists and is honoured.
#
# ── What it checks before it copies anything ──────────────────────────────────
#
# The Info.plist lives in the binary's `__TEXT,__info_plist` section rather than in a
# bundle, and it is put there by a linker flag. That flag has silently failed before:
# the path was relative, so building from anywhere but the package root produced a
# binary with no plist section, no warning, and a Local Network grant that attached to
# the terminal instead of the tool. The symptom is a scan that reports an empty
# network. So the section is verified in the built artifact, by reading it out of the
# Mach-O, before that artifact is allowed anywhere near a bin directory.
#
# Usage:
#
#     ./Scripts/install.sh                  # build release, install into /usr/local
#     PREFIX=~/.local ./Scripts/install.sh  # somewhere you own, no privilege needed
#     ./Scripts/install.sh uninstall        # remove both files from PREFIX

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE="$REPO"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
MANDIR="$PREFIX/share/man/man1"
MANPAGE="$PACKAGE/zhen.1"
ACTION="${1:-install}"

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "install: $*" >&2; exit 1; }

# A destination we cannot write to is a message, not an escalation. The command printed
# is the one the user would have to type anyway, and typing it themselves is the point.
require_writable() {
    local dir="$1" probe
    probe="$(dirname "$dir")"
    while [ ! -d "$probe" ] && [ "$probe" != "/" ]; do probe="$(dirname "$probe")"; done
    if [ -d "$dir" ]; then probe="$dir"; fi
    [ -w "$probe" ] && return 0
    say ""
    say "install: $probe is not writable by $(id -un)."
    say ""
    say "    Either install somewhere you own:"
    say ""
    say "        PREFIX=\$HOME/.local $0 $ACTION"
    say ""
    say "    or run this script yourself under sudo:"
    say ""
    say "        sudo PREFIX=$PREFIX $0 $ACTION"
    say ""
    exit 1
}

if [ "$ACTION" = "uninstall" ]; then
    require_writable "$BINDIR"
    rm -f "$BINDIR/zhen" "$MANDIR/zhen.1"
    say "install: removed $BINDIR/zhen and $MANDIR/zhen.1"
    say "install: the scan history at ~/Library/Application Support/zhen/ is left alone"
    exit 0
fi

[ "$ACTION" = "install" ] || die "unknown action '$ACTION' (expected install or uninstall)"
[ -f "$MANPAGE" ] || die "no manual page at $MANPAGE"

say "install: building release"
swift build --package-path "$PACKAGE" -c release
BIN="$(swift build --package-path "$PACKAGE" -c release --show-bin-path)/zhen"
[ -x "$BIN" ] || die "no binary at $BIN"

# The check the header explains. `otool -P` prints the section as text; an unembedded
# plist prints nothing at all, which is exactly how this failed silently the first time.
say "install: checking the embedded Info.plist"
PLIST="$(otool -P "$BIN" 2>/dev/null || true)"
case "$PLIST" in
    *NSLocalNetworkUsageDescription*) ;;
    *) die "the built binary has no __TEXT,__info_plist section, or it lacks the Local Network key.
       Installing it would give you a scanner that reports an empty network and no error.
       This is the -sectcreate linker flag in Package.swift." ;;
esac

# The manual is checked too, because a page that does not parse renders as nothing.
if command -v mandoc >/dev/null 2>&1; then
    mandoc -T lint "$MANPAGE" 2>&1 | grep -v 'outdated mandoc.db' | grep -q . \
        && die "the manual page does not lint clean; see mandoc -T lint $MANPAGE"
fi

require_writable "$BINDIR"
install -d "$BINDIR" "$MANDIR"
install -m 0755 "$BIN" "$BINDIR/zhen"
install -m 0644 "$MANPAGE" "$MANDIR/zhen.1"

say "install: $BINDIR/zhen"
say "install: $MANDIR/zhen.1"

# Installed is not the same as reachable, and a binary on disk that the shell cannot
# find is a support question rather than an install.
case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *) say ""
       say "install: $BINDIR is not on your PATH. Add it:"
       say ""
       say "        export PATH=\"$BINDIR:\$PATH\"" ;;
esac
if ! manpath 2>/dev/null | tr ':' '\n' | grep -qx "$PREFIX/share/man"; then
    say ""
    say "install: $PREFIX/share/man is not on your MANPATH, so 'man zhen' will not"
    say "         find the page. Read it directly with:"
    say ""
    say "        man $MANDIR/zhen.1"
fi

say ""
say "install: zhen $("$BIN" --version) is installed. It runs without privileges;"
say "         under sudo it adds an ARP sweep, half-open scanning and fingerprinting."
