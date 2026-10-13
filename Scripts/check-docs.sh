#!/usr/bin/env bash
#
# check-docs.sh — every path the documentation names must exist.
#
# Written for the documentation audit, 2026-09-30. It exists because of one defect it
# would have caught the day it was introduced: the reorganisation's path rewrite turned
# the README's three build commands into two identical `cd zhen` lines and a `cd zhen-app`
# that no longer had a Package.swift. Nobody noticed for four days, because nothing looks
# at prose.
#
# The same shape as verify-identifiers.sh: read the authority (the filesystem), compare the
# claim (the documents), and fail on a difference. It checks paths and nothing else — a
# document can still be wrong about what a file CONTAINS, and no script fixes that.
#
# Usage: Scripts/check-docs.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
checked=0

# Files whose prose is checked. Deliberately not every markdown file in the repository:
# the process record cites paths as they were at the time, which is the point of a record.
# Docs/AUDIT.md is one since the split: it measured the monorepo, and names its paths.
#
# The anchors include the monorepo's top-level directories, which do not exist here. That
# is deliberate: a document still saying `zhen/Sources/…` would otherwise pass, because the
# `Sources/…` inside it resolves.
FILES=(README.md CONTRIBUTING.md SECURITY.md Docs/README.md Docs/MANUAL.md)

for doc in "${FILES[@]}"; do
    [ -f "$doc" ] || { echo "MISSING DOCUMENT: $doc"; fail=1; continue; }

    # Repository-relative paths named in prose, backticks or fenced blocks. Anchored on a
    # known top-level directory so ordinary prose containing a slash is not a candidate.
    paths=$(grep -ohE '(Docs|Scripts|Sources|Tests|zhen|zhen-app|Study|Design)/[A-Za-z0-9_./-]*[A-Za-z0-9_-]' "$doc" \
            | sed 's/[.,:;)]*$//' | sort -u)

    while IFS= read -r p; do
        [ -z "$p" ] && continue
        # A .build path is an artifact of having built, not a committed file.
        case "$p" in *.build/*) continue ;; esac
        checked=$((checked + 1))
        [ -e "$p" ] || { echo "$doc: names a path that does not exist: $p"; fail=1; }
    done <<< "$paths"
done

# Every subcommand the tool declares must appear in the manual. The man page has its own
# stricter check; this one catches a command the guide never mentions, which is how a user
# ends up typing `zhen scan <host> <port>` and getting an error.
MANUAL=Docs/MANUAL.md
subs=$(grep -oE 'subcommands: \[[^]]*\]' Sources/zhen/Zhen.swift \
       | grep -oE '[A-Z][A-Za-z]*\.self' | sed 's/\.self//' | tr 'A-Z' 'a-z' | sort -u)
[ -z "$subs" ] && { echo "no subcommands parsed — the check measures nothing"; exit 2; }
for c in $subs; do
    checked=$((checked + 1))
    grep -qE "zhen $c" "$MANUAL" || { echo "$MANUAL: never shows 'zhen $c'"; fail=1; }
done

if [ "$fail" = 0 ]; then
    echo "check-docs: $checked claims checked across ${#FILES[@]} documents — PASS"
else
    echo "check-docs: FAIL"
fi
exit $fail
