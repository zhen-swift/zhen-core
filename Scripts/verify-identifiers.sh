#!/bin/bash
# verify-identifiers.sh — the documentation may not name an identifier that does
# not exist.
#
# The bundle identifiers are declared in three places: HelperIdentity in
# ZhenPrivilege, Scripts/build-app.sh, and the architecture documents. A test
# already pins the first two to each other. Nothing pinned the third, and after
# the 2026-09-23 rename Docs/03-zhen-app.md described `dev.jc.zhen` and
# `dev.jc.zhen.ScanEngine` — identifiers that were never registered. Anyone
# debugging a helper that would not register had a document sending them to look
# for the wrong label.
#
# That was the fourth time this repository asserted something about itself that
# was not true: the README's status section, the CLI's version, the arpSweep
# capability, and this. The first three were each fixed once. This is the check
# that makes the fix stick.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The code is the authority; the documents are copies.
APP=$(grep -o 'applicationBundleIdentifier = "[^"]*"' \
        Sources/ZhenPrivilege/HelperProtocol.swift \
        | sed 's/.*"\(.*\)"/\1/')
HELPER=$(grep -o 'static let label = "[^"]*"' \
        Sources/ZhenPrivilege/HelperProtocol.swift \
        | sed 's/.*"\(.*\)"/\1/')

[ -n "$APP" ] && [ -n "$HELPER" ] || {
    echo "verify-identifiers: could not read the identifiers from HelperProtocol.swift." >&2
    echo "The declaration moved or changed shape; this check is now lying by silence." >&2
    exit 2
}

echo "authority: $APP · $HELPER"

# RENAME-to-zhen.md is the rename plan and quotes the old identifiers on purpose.
# Study/ records what was measured under the former name and is never rewritten.
FOUND=$(grep -rhoE '\b(com|dev)\.[a-z]+\.[a-zA-Z.]*zhen[a-zA-Z.]*' Docs/ \
        --include='*.md' --exclude='RENAME-to-zhen.md' | sort -u || true)

BAD=""
while IFS= read -r id; do
    [ -z "$id" ] && continue
    case "$id" in
        "$APP"|"$HELPER"|"$APP".*) ;;
        *) BAD="$BAD $id" ;;
    esac
done <<< "$FOUND"

if [ -n "$BAD" ]; then
    echo "verify-identifiers: documents name identifiers the code does not declare:" >&2
    for id in $BAD; do
        echo "  $id" >&2
        grep -rn --include='*.md' --exclude='RENAME-to-zhen.md' -F "$id" Docs/ >&2 || true
    done
    exit 1
fi

echo "verify-identifiers: every identifier in Docs/ is one the code declares"
