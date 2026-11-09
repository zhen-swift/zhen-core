#!/usr/bin/env bash
#
# build-book.sh — builds Docs/book into an EPUB: "Zhen & Darwin, Illustrated".
#
# The book is pinned to a tag (BOOK_TAG below), not to whatever is checked out. Every
# `File.swift:NN` it cites is a line at that tag, so a reader can open the same lines, and
# `--check-refs` proves each one still exists there. It proves the line EXISTS, not that it
# still says what the book says it says; that is the fact pass, done by reading.
#
# Figures are hand-written SVG. They share one drawing kit, Docs/book/figures/_kit.svg,
# which is copied into every figure here at build time: e-readers do not follow <use>
# across files, so a figure in the EPUB has to carry its own symbols.
#
# Needs: pandoc 3.x, epubcheck, python3. rsvg-convert is optional (a PNG cover renders in
# more readers than an SVG one; without it the SVG is used).
#
# Usage: Scripts/build-book.sh [--check-refs] [--png] [--html]
#   --check-refs  fail if a cited file:line does not exist at BOOK_TAG
#   --png         also render every figure to Docs/book/build/png/, to look at them
#   --html        also build the web edition into Docs/book/build/site/, one page per
#                 chapter, which .github/workflows/book.yml publishes to GitHub Pages
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BOOK_TAG=0.9.0
BOOK=Docs/book
OUT=$BOOK/build
EPUB=$OUT/zhen-and-darwin.epub

check_refs=0
png=0
html=0
for arg in "$@"; do
    case "$arg" in
        --check-refs) check_refs=1 ;;
        --png) png=1 ;;
        --html) html=1 ;;
        *) echo "usage: $0 [--check-refs] [--png] [--html]" >&2; exit 64 ;;
    esac
done

for tool in pandoc epubcheck python3; do
    command -v "$tool" >/dev/null || { echo "build-book: $tool is not installed" >&2; exit 69; }
done

rm -rf "$OUT/figures" "$OUT/png"
mkdir -p "$OUT/figures"

# ── Figures: inject the kit ──────────────────────────────────────────────────────────
python3 -I - "$BOOK/figures" "$OUT/figures" <<'PY'
import pathlib, re, sys
src, dst = map(pathlib.Path, sys.argv[1:3])
kit = (src / "_kit.svg").read_text()
defs = re.search(r"^<defs>.*^</defs>", kit, re.S | re.M).group(0)
count = 0
for svg in sorted(src.glob("*.svg")):
    if svg.name.startswith("_"):
        continue
    text = svg.read_text()
    opening = re.search(r"<svg\b[^>]*>", text)
    if not opening:
        sys.exit(f"build-book: {svg.name} has no <svg> element")
    text = text[: opening.end()] + "\n" + defs + text[opening.end():]
    (dst / svg.name).write_text(text)
    count += 1
print(f"build-book: {count} figures")
PY

if (( png )) && command -v rsvg-convert >/dev/null; then
    mkdir -p "$OUT/png"
    for f in "$OUT"/figures/*.svg; do
        rsvg-convert -w 1200 -b white "$f" -o "$OUT/png/$(basename "${f%.svg}").png"
    done
    echo "build-book: PNGs in $OUT/png"
fi

# ── References ───────────────────────────────────────────────────────────────────────
python3 -I - "$BOOK" "$BOOK_TAG" "$check_refs" <<'PY'
import pathlib, re, subprocess, sys
book, tag, strict = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3] == "1"
chapters = sorted((book / "chapters").glob("*.md"))

# Every image a chapter names must exist.
missing = []
for ch in chapters:
    for img in re.findall(r"!\[[^\]]*\]\(([^)\s]+)", ch.read_text()):
        if not (book / img).exists():
            missing.append(f"{ch.name}: {img}")
if missing:
    sys.exit("build-book: missing figures:\n  " + "\n  ".join(missing))

if not strict:
    sys.exit(0)

files = subprocess.run(["git", "ls-tree", "-r", "--name-only", tag],
                       capture_output=True, text=True, check=True).stdout.split()
ref = re.compile(r"((?:[\w.+-]+/)*[\w.+-]+\.(?:swift|h|c|plist|md|yml|yaml|sh)):(\d+)(?:[-–](\d+))?")
lengths, problems, checked, external = {}, [], 0, 0
for ch in chapters:
    for m in ref.finditer(ch.read_text()):
        name, first, last = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        if name.startswith(("zhen-ios/", "zhen-app/")):
            sibling = pathlib.Path("..") / name
            if sibling.exists():
                n = len(sibling.read_text().splitlines())
                if last > n:
                    problems.append(f"{ch.name}: {m.group(0)} (file has {n} lines)")
            external += 1
            continue
        # An exact path wins: `Package.swift` is the root manifest, not a fixture copy.
        hits = [name] if name in files else [f for f in files if f.endswith("/" + name)]
        if len(hits) != 1:
            problems.append(f"{ch.name}: {m.group(0)} ({'not found' if not hits else 'ambiguous: ' + ', '.join(hits)})")
            continue
        path = hits[0]
        if path not in lengths:
            body = subprocess.run(["git", "show", f"{tag}:{path}"], capture_output=True, text=True, check=True).stdout
            lengths[path] = len(body.splitlines())
        if first < 1 or last < first or last > lengths[path]:
            problems.append(f"{ch.name}: {m.group(0)} ({path} has {lengths[path]} lines)")
        checked += 1
if problems:
    sys.exit("build-book: unresolved references at " + tag + ":\n  " + "\n  ".join(problems))
print(f"build-book: {checked} references resolve at {tag}; {external} in sibling repositories")
PY

# ── Cover ────────────────────────────────────────────────────────────────────────────
cover="$OUT/figures/cover.svg"
if command -v rsvg-convert >/dev/null; then
    rsvg-convert -w 1600 "$cover" -o "$OUT/cover.png"
    cover="$OUT/cover.png"
fi

# ── EPUB ─────────────────────────────────────────────────────────────────────────────
pandoc "$BOOK/metadata.yaml" "$BOOK"/chapters/*.md \
    --from markdown+fenced_divs+bracketed_spans \
    --to epub3 \
    --output "$EPUB" \
    --css "$BOOK/epub.css" \
    --epub-cover-image "$cover" \
    --resource-path "$OUT:$BOOK" \
    --toc --toc-depth 1 \
    --split-level 1 \
    --syntax-highlighting tango

epubcheck --quiet "$EPUB"
echo "build-book: $EPUB"

# ── Web edition ──────────────────────────────────────────────────────────────────────
# The same chapters as one page each, named after the chapter (`ping-without-root.html`).
# pandoc writes the pages through Docs/book/web/template.html and copies the figures they
# name; Scripts/book-site.py then adds the contents, the top bar, the previous/next cards
# and the front page, all from pandoc's own sitemap.json.
if (( html )); then
    SITE=$OUT/site
    rm -rf "$SITE"
    pandoc "$BOOK/metadata.yaml" "$BOOK"/chapters/*.md \
        --from markdown+fenced_divs+bracketed_spans \
        --to chunkedhtml \
        --output "$SITE" \
        --template "$BOOK/web/template.html" \
        --chunk-template '%i.html' \
        --resource-path "$OUT:$BOOK" \
        --toc --toc-depth 2 \
        --split-level 1 \
        --syntax-highlighting tango
    cp "$BOOK/web/book.css" "$BOOK/web/book.js" "$SITE/"
    cp "$OUT/figures/cover.svg" "$SITE/figures/cover.svg"
    cp "$EPUB" "$SITE/"
    python3 -I Scripts/book-site.py "$SITE" "$(basename "$EPUB")"
    echo "build-book: $SITE"
fi
