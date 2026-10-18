#!/usr/bin/env bash
#
# release-binary.sh — the prebuilt `zhen` for Macs that cannot build it.
#
# zhen runs on macOS 14, but building it needs Xcode 26, which needs macOS 15.6. So on
# Sonoma the Homebrew formula cannot build from source, and installs this instead: one
# universal binary (arm64 + x86_64) with a deployment target of 14, plus the manual,
# attached by hand to the tag's GitHub release. On 15.6 and later the formula still
# builds from source, and this file is never downloaded.
#
# ── What this script will not do ───────────────────────────────────────────────
#
# It never uploads. It prints the `gh release upload` command and stops, because
# publishing a binary is the one step here that cannot be taken back, and the house
# rules keep every write to a release in a person's hands, not a workflow's.
#
# It signs nothing beyond the linker's ad-hoc signature. A formula's downloads are not
# quarantined, so Gatekeeper never sees this file, and a Developer ID would claim a
# provenance this script cannot check.
#
# ── What it checks before it packs anything ───────────────────────────────────
#
#   - HEAD is exactly a tag, the tree is clean, and the binary's own `--version`
#     names that tag's version and commit. A release built from the wrong checkout
#     is worse than none.
#   - Both slices are there and each says minos 14.0. A slice built against the host
#     OS would install fine on Sonoma and then refuse to launch.
#   - The Info.plist section is embedded. Without it a scan reports an empty network
#     (see install.sh for that history).
#   - The x86_64 slice runs, under Rosetta. Nothing else here executes it.
#
# ── Why two builds and `lipo` ─────────────────────────────────────────────────
#
# SwiftPM's default build system on Swift 6.4 runs the StampCommit plugin where it
# cannot read `.git`, so the binary says "commit unknown" (measured 2026-10-18;
# `--build-system native` stamps correctly). The native system builds one triple at a
# time, so each architecture is its own build and `lipo` joins them. If a toolchain
# drops `native`, this fails at the commit check rather than shipping an unstamped binary.
#
# Usage:
#
#     ./Scripts/release-binary.sh            # at a tag: build, verify, pack, print the upload
#     ./Scripts/release-binary.sh --check    # any HEAD: build and verify only (CI runs this)

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-release}"
FLOOR="14.0"
OUT="$REPO/.build/release-binary"

say() { printf '%s\n' "release-binary: $*"; }
die() { printf '%s\n' "release-binary: $*" >&2; exit 1; }

case "$MODE" in
    release|--check) ;;
    *) die "unknown argument '$MODE' (expected nothing, or --check)" ;;
esac

cd "$REPO"

if [ "$MODE" = "release" ]; then
    [ -z "$(git status --porcelain --untracked-files=no)" ] || die "the tree has changes; release from a clean checkout"
    TAG="$(git describe --exact-match --tags HEAD 2>/dev/null)" || die "HEAD is not a tag; check out the release tag first"
fi
COMMIT="$(git rev-parse HEAD)"

rm -rf "$OUT"
mkdir -p "$OUT"

for ARCH in arm64 x86_64; do
    say "building $ARCH for macOS $FLOOR"
    swift build -c release --product zhen \
        --build-system native \
        --triple "$ARCH-apple-macosx$FLOOR" \
        --build-path "$REPO/.build/release-$ARCH"
done

BIN="$OUT/zhen"
lipo -create \
    "$REPO/.build/release-arm64/release/zhen" \
    "$REPO/.build/release-x86_64/release/zhen" \
    -output "$BIN"

ARCHS="$(lipo -archs "$BIN")"
[ "$ARCHS" = "x86_64 arm64" ] || die "expected slices 'x86_64 arm64', got '$ARCHS'"

for ARCH in arm64 x86_64; do
    MINOS="$(vtool -arch "$ARCH" -show-build "$BIN" | awk '/minos/ { print $2 }')"
    [ "$MINOS" = "$FLOOR" ] || die "$ARCH slice has minos '$MINOS', not $FLOOR"
done
say "slices: $ARCHS, each minos $FLOOR"

otool -P "$BIN" | grep -q NSLocalNetworkUsageDescription \
    || die "no Info.plist section in the binary; scans would report an empty network"

VERSION_LINE="$("$BIN" --version)"
case "$VERSION_LINE" in
    *"($COMMIT)") ;;
    *) die "--version says '$VERSION_LINE', not commit $COMMIT" ;;
esac

if arch -x86_64 /usr/bin/true 2>/dev/null; then
    X86_LINE="$(arch -x86_64 "$BIN" --version)"
    [ "$X86_LINE" = "$VERSION_LINE" ] || die "x86_64 slice says '$X86_LINE', arm64 says '$VERSION_LINE'"
    say "x86_64 slice runs under Rosetta"
elif [ "$MODE" = "release" ]; then
    die "Rosetta is not installed, so the x86_64 slice cannot be run: softwareupdate --install-rosetta"
else
    say "Rosetta is not installed; the x86_64 slice was built and checked but not run"
fi

if [ "$MODE" = "--check" ]; then
    say "ok: $VERSION_LINE"
    exit 0
fi

VERSION="${VERSION_LINE%% *}"
[ "$VERSION" = "$TAG" ] || die "the binary is version $VERSION but HEAD is tag $TAG"

ASSET="zhen-$VERSION-macos14-universal.tar.gz"
cp "$REPO/zhen.1" "$OUT/zhen.1"
tar -C "$OUT" -czf "$OUT/$ASSET" zhen zhen.1
SHA="$(shasum -a 256 "$OUT/$ASSET" | awk '{ print $1 }')"

say "packed $OUT/$ASSET"
say "sha256 $SHA"
say ""
say "Nothing has been uploaded. To publish it:"
say ""
say "    gh release upload $TAG '$OUT/$ASSET' --repo zhen-swift/zhen-core"
say ""
say "The formula then needs:"
say ""
say "    url \"https://github.com/zhen-swift/zhen-core/releases/download/$TAG/$ASSET\""
say "    sha256 \"$SHA\""
