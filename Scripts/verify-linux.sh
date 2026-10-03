#!/usr/bin/env bash
#
# verify-linux.sh — prove that ZhenCore builds on Linux.
#
# The portability rule is the constraint that shapes core more than anything else:
# ZhenCore must compile on Linux, with all Darwin machinery reachable only through
# the protocols it declares. Everything else in the repo checks that rule by INSPECTION
# — no `import Darwin`, no `#if` outside Platform/ — and inspection is not proof. Swift
# does not type-check inactive `#if` branches, and a rule nothing exercises is a rule
# that has already been broken somewhere nobody has looked.
#
# So this builds the real thing on the real platform. It builds ZhenCore ALONE:
# not ZhenDarwin, which is Apple-only by construction, and not the command line,
# which has an Apple-only engine dependency. Those are supposed to be excluded on
# Linux, and a script that pulled them in would be testing the wrong claim.
#
# Two mechanisms, tried in order:
#
#   1. A container running the official Swift image. This is the real answer — a real
#      Linux, a real Foundation, a real link step. Reached through docker or podman on
#      the host, or through a lima VM that is hosting one of them.
#   2. A Swift SDK cross-compile, if one is installed. Faster and needs no daemon, and
#      it produces real Linux ELF objects — but it compiles rather than running, so it
#      cannot catch a runtime difference, only a compile-time one.
#
#      The SDK's Swift version must match the COMPILER's exactly: a Foundation
#      .swiftmodule built by 6.2.3 cannot be read by a 6.3.3 compiler, and the resulting
#      error names your source file while having nothing to do with it. Xcode's
#      toolchain is usually ahead of the newest published Linux SDK, so this script
#      looks in ~/Library/Developer/Toolchains for a version that matches the SDK and
#      selects it via TOOLCHAINS if it finds one.
#
# If neither is available it says so plainly and exits non-zero, because "I could not
# check" is a different answer from "it builds" and must not be mistaken for one.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE="$REPO"
TARGET="ZhenCore"
IMAGE="${ZHEN_SWIFT_IMAGE:-swift:6.2}"

say() { printf '%s\n' "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────"; }

[ -d "$PACKAGE" ] || { say "verify-linux: no package at $PACKAGE"; exit 1; }

# ── 1. Container ────────────────────────────────────────────────────────────────
#
# `RUN` is an argv prefix rather than a command name, because one of the three ways
# of reaching a container runtime is not a command at all.
RUNTIME=""
RUN=()
for candidate in docker podman; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
        RUNTIME="$candidate"
        RUN=("$candidate")
        break
    fi
done

# Lima, if it is hosting one. On macOS this is often the only container runtime
# present: Docker Desktop is a licensing question in a lot of places, and colima is
# one more thing to install for a machine that already runs lima for other reasons.
# A VM with a working docker inside it is a container runtime, and refusing to see it
# would send someone off to install a second one for no reason.
#
# The package has to be visible inside the VM, which it is when the repository lives
# under a directory lima mounts — `$HOME` by default. When it does not, this is not a
# failure worth reporting: it simply is not a usable runtime, and the SDK path below
# is still there.
if [ -z "$RUNTIME" ] && command -v limactl >/dev/null 2>&1; then
    while read -r vm status; do
        [ "$status" = "Running" ] || continue
        limactl shell "$vm" docker info >/dev/null 2>&1 || continue
        limactl shell "$vm" test -d "$PACKAGE" >/dev/null 2>&1 || continue
        RUNTIME="docker in lima VM '$vm'"
        RUN=(limactl shell "$vm" docker)
        break
    done < <(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null)
fi

if [ -n "$RUNTIME" ]; then
    say "verify-linux: building $TARGET with $RUNTIME, image $IMAGE"
    rule
    # Two things keep the container from touching the working tree. `--build-path`
    # puts objects inside the container, because a macOS `.build` reused by a Linux
    # compiler produces failures that look like source problems and are not. And the
    # mount is read-only, so a check that is supposed to answer a question cannot
    # quietly change the thing it is asking about — which also happens to be what
    # makes the lima path work, since lima mounts the host read-only anyway.
    "${RUN[@]}" run --rm \
        -v "$PACKAGE:/pkg:ro" \
        -w /pkg \
        "$IMAGE" \
        swift build --target "$TARGET" --build-path /tmp/linux-build
    STATUS=$?
    rule
    if [ $STATUS -eq 0 ]; then
        say "verify-linux: PASS — $TARGET builds on Linux ($IMAGE)"
    else
        say "verify-linux: FAIL — $TARGET does not build on Linux ($IMAGE)"
    fi
    exit $STATUS
fi

# ── 2. Swift SDK cross-compile ──────────────────────────────────────────────────
SDK_ID="$(swift sdk list 2>/dev/null | grep -i 'linux' | head -1)"
if [ -n "$SDK_ID" ]; then
    say "verify-linux: no container runtime; falling back to the Swift SDK '$SDK_ID'"

    # Match the compiler to the SDK. The SDK id carries its version, e.g.
    # swift-6.2.3-RELEASE_static-linux-0.0.1.
    SDK_VERSION="$(printf '%s' "$SDK_ID" | sed -n 's/^swift-\([0-9][0-9.]*\)-.*/\1/p')"
    CURRENT_VERSION="$(swift --version 2>/dev/null | sed -n 's/.*Swift version \([0-9][0-9.]*\).*/\1/p' | head -1)"
    if [ -n "$SDK_VERSION" ] && [ "$SDK_VERSION" != "$CURRENT_VERSION" ]; then
        say "verify-linux: default compiler is $CURRENT_VERSION but the SDK is $SDK_VERSION; looking for a match"
        for tc in "$HOME/Library/Developer/Toolchains"/swift-"$SDK_VERSION"-RELEASE.xctoolchain                   /Library/Developer/Toolchains/swift-"$SDK_VERSION"-RELEASE.xctoolchain; do
            if [ -f "$tc/Info.plist" ]; then
                TOOLCHAINS="$(plutil -extract CFBundleIdentifier raw "$tc/Info.plist" 2>/dev/null)"
                if [ -n "$TOOLCHAINS" ]; then
                    export TOOLCHAINS
                    say "verify-linux: using toolchain $TOOLCHAINS ($tc)"
                    break
                fi
            fi
        done
    fi
    rule
    swift build --package-path "$PACKAGE" \
        --swift-sdk x86_64-swift-linux-musl \
        --target "$TARGET" \
        --scratch-path /tmp/zhen-linux-sdk-build
    STATUS=$?
    rule
    if [ $STATUS -eq 0 ]; then
        say "verify-linux: PASS — $TARGET cross-compiles for Linux"
    else
        say "verify-linux: FAIL — see above. A 'module compiled with Swift X cannot be"
        say "              imported by the Swift Y compiler' error is a version mismatch"
        say "              between the SDK and this toolchain, NOT a portability defect."
        say "              Install a matching SDK, or use a container."
    fi
    exit $STATUS
fi

# ── Neither ─────────────────────────────────────────────────────────────────────
cat <<'MESSAGE'
verify-linux: cannot check — no way to build for Linux on this machine.

  Neither docker nor podman is installed and reachable, and no Linux Swift SDK is
  installed for cross-compilation.

  This is NOT a pass. ZhenCore's portability is unverified until one of these
  runs:

    Docker Desktop      https://docs.docker.com/desktop/install/mac-install/
    Podman              brew install podman && podman machine init && podman machine start
    Colima              brew install colima docker && colima start
    Lima                limactl start template://docker

  A lima VM counts if it is Running, has a working docker inside it, and can see this
  repository — which it can when the repository lives under a directory lima mounts.

  Or install a Swift SDK matching this toolchain's version:

    swift --version                      # note the version
    swift sdk install <static-linux artifactbundle URL for that exact version>

  Then re-run this script. Set ZHEN_SWIFT_IMAGE to pick a different Swift image.
MESSAGE
exit 2
