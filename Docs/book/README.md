# Zhen & Darwin, Illustrated

A picture-first book about every place zhen-core talks to the Darwin kernel: file
descriptors, sockets, kqueue, ICMP without root, Bonjour, BPF, the routing socket and the
privileged helper. Every chapter ends with what an iPhone or iPad gets.

**Read it online at <https://zhen-swift.github.io/zhen-core/>**, or download the EPUB from
the front page there.

It is **pinned to tag `0.9.0`**. Every `File.swift:NN` it cites is a line at that tag, the
version zhen-ios builds against. When the engine moves on, the book is re-pinned, not
quietly edited.

## When the engine changes

The book is pinned, so a code change never makes it wrong *at its tag*. It does go stale
for anyone reading it beside `main`. That is fine for a while, but only if it is written
down.

**The Darwin surface** is what the book describes. A change to any of these is a change the
book may need to follow:

- `Sources/ZhenDarwin`, `Sources/ZhenPrivilege`, `Sources/zhen-helper`, `Sources/CBPFShim`
  and `Sources/ZhenScan`
- the platform seams in `Sources/ZhenCore/Platform`
- the platforms and isolation settings in `Package.swift`, and `Sources/zhen/Info.plist`
- in zhen-ios, the scan path (`Zhen/Scanning`, `Zhen/Model`, `Zhen/App`) and the
  Diagnostics screen (`Zhen/Platform/CapabilityProbe.swift`)
- in zhen-app, the helper's registration and its launchd plist

**A pull request that touches it** names, in its description, the chapters it affects. For
each chapter it either updates it now or says that the chapter waits for the next re-pin.

**To find the chapters**, search for the file. The search is the authority:

```bash
grep -rln "ICMPSocket.swift" Docs/book/chapters
```

For a first look, this map is close enough:

| Area | Chapters |
|---|---|
| Descriptors, `errno`, resource limits, `sockaddr`, non-blocking I/O, kqueue | 2, 3, 4 |
| The ICMP sweep socket and packet | 5 |
| TCP connect scan, banners, TLS | 6 |
| UDP probing and payloads | 7 |
| Interfaces and the default route | 8 |
| Bonjour, NetBIOS, SSDP, `NSBonjourServices` | 9 |
| Sweep timing, Wi-Fi spacing, the Local Network permission | 10 |
| BPF and the C shim | 11 |
| The routing socket, ARP table, neighbour watch | 12 |
| SYN scan, raw frames, fingerprinting | 13 |
| The helper, XPC, code signing, capture policy | 14 |
| `DarwinScanner.make` and every `#if os(macOS)` gate | 15 |
| `ScanRunner`, the two channels, the zhen-ios call path | 16 |
| zhen-ios Diagnostics and what only a device can answer | 17 |
| A new syscall, errno or term; code that disagrees with its docs | Appendices B, C, A, D |

**A new feature that reaches the kernel** gets:

- a section in the chapter it belongs to, or a new chapter (see "Adding a chapter or a
  page");
- a line in that chapter's 📱 box saying what an iPhone or iPad gets: ✅, ❌ or ⚪️;
- entries in Appendix B for each new syscall, Appendix C for each new errno it handles, and
  Appendix A for each new term;
- a `::: honest` note, and a card in Appendix D, wherever the code and its own comments or
  docs disagree.

A feature that changes **what iOS gets** also updates chapter 15's comparison drawing
(`figures/15-compare.svg`) and `Docs/IPADOS.md`.

## Re-pinning after a release

A re-pin is its own pull request, opened **after** the release is tagged. `--check-refs`
reads every cited line with `git show <tag>:<file>`, so it cannot check a tag that does not
exist yet, and the release PR cannot re-pin itself.

1. Set `BOOK_TAG` in `Scripts/build-book.sh` to the new tag and run
   `Scripts/build-book.sh --check-refs`. It lists every citation that now points past the
   end of its file.
2. In every chapter the release touched, read each cited line again. A line that still
   exists may now say something else. The script cannot tell; only reading can.
3. Change every visible pin. This lists them all:

   ```bash
   grep -rn "0\.9\.0" Docs/book Scripts/build-book.sh Scripts/book-site.py
   ```

   That is every `@ 0.9.0` caption, the pinned-to lines in `010-welcome`, `901-syscalls`
   and `903-honest`, `figures/cover.svg`, `figures/15-compare.svg`, `metadata.yaml`, the
   two strings in `Scripts/book-site.py`, and this README.
4. The zhen-ios pin (`793ebb0`, in the `@ zhen-ios …` captions and Appendix D) moves the
   same way. `--check-refs` checks zhen-ios and zhen-app citations only when those
   repositories are checked out beside this one.

## Building

```bash
brew install pandoc epubcheck          # once; rsvg-convert (librsvg) is optional
Scripts/build-book.sh --check-refs     # → Docs/book/build/zhen-and-darwin.epub
Scripts/build-book.sh --png            # also renders every figure to build/png/
Scripts/build-book.sh --html           # also builds the web edition into build/site/
```

`build/` is ignored. The EPUB and the site are build products. `.github/workflows/book.yml`
builds both on every pull request that touches the book, and publishes the site to
GitHub Pages from `main`.

## Layout

| | |
|---|---|
| `metadata.yaml` | Title, author, language |
| `epub.css` | Typography and the callout boxes, for the EPUB |
| `web/` | The web edition: `template.html` (the page pandoc writes), `book.css` and `book.js`. `Scripts/book-site.py` adds the contents, top bar, previous/next cards and front page from pandoc's `sitemap.json` |
| `chapters/NNN-slug.md` | One file per chapter or part page, in build order. The first digit is the part (`1` for Part I and so on, `0` for the opening, `9` for the appendices) |
| `figures/_kit.svg` | The drawing kit: palette, text styles and the reusable symbols |
| `figures/*.svg` | One file per drawing, named after its chapter (`05-hero.svg`) |

## Chapter template

Every chapter has the same parts, in this order. Words are kept short and pictures do the
work.

1. `# N · Title`, then a **hero drawing** that tells the whole chapter.
2. `::: short`: **The short version**, 3–5 bullets.
3. Two to five `##` sections. Each has one drawing and a list, numbered steps for a
   sequence and bullets otherwise. Prose is a sentence or two at most.
4. Code bites only where they help: 8 lines at most, real code (trimming is allowed and
   said in the caption), each followed by its source caption:
   `[`File.swift:12-19` @ 0.9.0]{.src}`
5. `::: word` boxes introduce a new term the first time it appears.
6. `::: iphone`: **📱 On iPhone & iPad**. Each line starts with ✅ (works), ❌ (not built,
   not allowed) or ⚪️ (built but off, or not yet measured on a device).
7. `::: gotcha`: **⚠️ Gotchas the code remembers**, the bugs and traps the source comments
   record.
8. `::: remember`: **🧠 Remember**, a three-line recap.

`::: honest` (first line `🔍 Honest note: …`) marks a place where the code and its own
documentation disagree. Those are also collected in Appendix D.

## The cast and the metaphors

| In the drawings | Is |
|---|---|
| **Pip**, the peach packet (`#pip`, `#pip-worried`, `#pip-yay`) | the reader's guide; usually "our app" or a packet |
| **The castle** (`#castle`) | the kernel |
| **Doors** (`#door`) | system calls |
| **Tickets** (`#ticket`) | file descriptors |
| **Mailboxes** (`#mailbox`) | sockets |
| **The periscope** (`#periscope`) | BPF |
| **The crown** (`#crown`) | root |
| **The padlock** (`#lock`) | not allowed / needs privilege |
| `#phone`, `#laptop`, `#router`, `#device` | iPhone/iPad, the Mac, the network, a host on it |
| `#check`, `#cross`, `#off` | ✅ ❌ ⚪️ |

## Drawing rules

- A figure is `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 H" width="800" height="H">`,
  starting with the card
  `<rect x="4" y="4" width="792" height="H-8" rx="28" fill="#FFF8EE" stroke="#EADFCC" stroke-width="4"/>`.
  The card is what keeps a drawing readable in night mode.
- Use kit symbols with `<use href="#pip" x y width height/>`. The build copies the kit into
  each figure; do not paste `<defs>` into a figure.
- Text uses the kit classes `t h` (34 px), `t b` (26 px), `t s` (22 px) and `m` (22 px
  monospace), with `mid` to centre. **Nothing smaller than 22 px**: an 800-wide drawing is
  shown at about 350 px on a phone. Keep text short: labels, not sentences.
- Only the kit's palette (listed at the top of `_kit.svg`).
- Look at every drawing before it ships (`Scripts/build-book.sh --png`), and fix any overlap
  or text running off the card.

## Adding a chapter or a page

The web edition's navigation is derived, so a new chapter needs nothing in the site's
code. It does depend on these conventions, which `Scripts/book-site.py` reads:

- **The file name sets the order.** `chapters/NNN-slug.md`, sorted by name. The first digit
  is the part.
- **The first heading sets the kind.** The number before the `·` decides which it is:
  - `# 5 · Title` is a chapter
  - `# Part II · Title` is a part page
  - `# D · Title` is an appendix (one capital letter)
  - `# 0 · Title` is the opening
- **The first drawing is the chapter's hero.** It becomes the chapter's card on the front
  page and the teaser on the previous chapter's "next" card. **Its alt text is the blurb**
  under it, so write it as a caption.
- **Every `##` heading is listed in the contents** while that chapter is open, and the one
  being read is highlighted.
- **A heading's id is its address.** `# 5 · Ping without root` is published as
  `ping-without-root.html`. Renaming a chapter breaks every link to it, so rename only
  when it is worth that.
- Chapter numbers in the text ("see chapter 10") are written by hand. A new chapter in the
  middle renumbers the ones after it. Search for `chapter N` and update them.

## The web edition

- **How it is built:**
  1. pandoc writes one page per chapter through `web/template.html`, which leaves marked
     holes (`<!--BOOK:…-->`).
  2. `Scripts/book-site.py` fills the holes from pandoc's `sitemap.json`: the contents, the
     top bar, the previous/next cards, the front page and the prerender rule.
- **Where changes go:** look and layout in `web/book.css`, behaviour in `web/book.js`. The
  script only adds to a page. **Every page must still work with scripts off**: contents,
  links and previous/next cards all live in the HTML.
- **How to look at it:**
  1. Run `Scripts/build-book.sh --html` and serve `build/site/`.
  2. Screenshot it with headless Chrome.
  3. Check light and dark mode, the drawer, and the end-of-chapter cards.
  4. Headless Chrome will not go narrower than 500 px. A real phone width needs a real
     phone.

## Publishing

- `.github/workflows/book.yml` builds the EPUB and the site, with `--check-refs`, on every
  pull request that touches the book. Nothing is deployed from a pull request.
- A merge to `main` publishes the site to <https://zhen-swift.github.io/zhen-core/>.
  GitHub Pages caches pages for about ten minutes.
- The EPUB is not committed. The site serves it from its front page.
