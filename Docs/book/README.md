# Zhen & Darwin, Illustrated

A picture-first book about every place zhen-core talks to the Darwin kernel: file
descriptors, sockets, kqueue, ICMP without root, Bonjour, BPF, the routing socket and the
privileged helper. Every chapter ends with what an iPhone or iPad gets.

It is **pinned to tag `0.9.0`**. Every `File.swift:NN` it cites is a line at that tag, the
version zhen-ios builds against. When the engine moves on, the book is re-pinned, not
quietly edited.

## Building

```bash
brew install pandoc epubcheck          # once; rsvg-convert (librsvg) is optional
Scripts/build-book.sh --check-refs     # → Docs/book/build/zhen-and-darwin.epub
Scripts/build-book.sh --png            # also renders every figure to build/png/
```

`build/` is ignored. The EPUB is a build product.

## Layout

| | |
|---|---|
| `metadata.yaml` | Title, author, language |
| `epub.css` | Typography and the callout boxes |
| `chapters/NNN-slug.md` | One file per chapter or part page, in build order. The first digit is the part (`1` for Part I and so on, `0` for the opening, `9` for the appendices) |
| `figures/_kit.svg` | The drawing kit: palette, text styles and the reusable symbols |
| `figures/*.svg` | One file per drawing, named after its chapter (`05-socket.svg`) |

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
