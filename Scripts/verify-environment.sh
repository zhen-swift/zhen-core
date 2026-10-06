#!/bin/bash
# Re-verifies the build and signing prerequisites on this Mac.
# Read-only. Prints a PASS/FAIL line per item.
set -u

pass() { printf "  PASS  %s\n" "$1"; }
fail() { printf "  FAIL  %s\n" "$1"; }
info() { printf "  ----  %s\n" "$1"; }

echo "Toolchain"
if command -v swift >/dev/null; then pass "$(swift --version 2>&1 | head -1)"; else fail "swift not on PATH"; fi
if command -v xcodebuild >/dev/null; then pass "xcodebuild: $(xcodebuild -version 2>/dev/null | head -1)"; else fail "xcodebuild not on PATH"; fi
info "active developer dir: $(xcode-select -p 2>/dev/null || echo none)"

echo
# Not a failure any more. The SwiftData conformance was withdrawn on 2026-09-11 — the
# app and the command line share the portable log — so nothing in this repository needs
# the macro plugin, and a check that fails over it would be sending someone to install
# Xcode for code that no longer exists. Xcode is still needed to build the app bundle,
# which the toolchain check above covers. Reported because the day something Apple-side
# wants SwiftData back, this is the first thing that has to be true.
echo "SwiftData macro plugin (nothing needs it today; the store is the portable log)"
if [ -d /Applications/Xcode.app ]; then
  plugin=$(find /Applications/Xcode.app -name "libSwiftDataMacros.dylib" 2>/dev/null | head -1)
  if [ -n "$plugin" ]; then info "$plugin"; else info "Xcode present, plugin not found"; fi
else
  info "/Applications/Xcode.app not present — nothing here needs it"
fi

echo
echo "Code signing (the privileged helper cannot register without a real identity)"
ids=$(security find-identity -v -p codesigning 2>/dev/null | grep -c "valid identities found" || true)
security find-identity -v -p codesigning 2>/dev/null | sed 's/^/  /'
if security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application"; then
  pass "Developer ID Application identity present"
else
  fail "no Developer ID Application identity — helper registration will not work outside local ad-hoc testing"
fi

echo
echo "Socket permissions (the unprivileged path depends on these)"
cat > /tmp/ic_sockcheck.c <<'C'
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
int main(void) {
    int d = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    printf("  %s  socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) as this user\n", d >= 0 ? "PASS" : "FAIL");
    int r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    printf("  %s  socket(SOCK_RAW) expected to fail unprivileged\n", r < 0 ? "PASS" : "----");
    int b = open("/dev/bpf0", O_RDONLY);
    printf("  %s  /dev/bpf0 expected EACCES unprivileged\n", b < 0 ? "PASS" : "----");
    return 0;
}
C
if command -v cc >/dev/null && cc -o /tmp/ic_sockcheck /tmp/ic_sockcheck.c 2>/dev/null; then
  /tmp/ic_sockcheck
  rm -f /tmp/ic_sockcheck /tmp/ic_sockcheck.c
else
  fail "cc unavailable — skipped socket checks"
fi

echo
echo "File descriptor limit (deep scans need headroom)"
info "soft: $(ulimit -Sn)   hard: $(ulimit -Hn)"
