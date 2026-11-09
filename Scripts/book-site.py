#!/usr/bin/env python3
"""book-site.py — dresses pandoc's chunked HTML as the book's web edition.

Scripts/build-book.sh --html runs pandoc with Docs/book/web/template.html, which leaves
marked holes (<!--BOOK:…-->) in every page. This fills them from pandoc's sitemap.json,
the one place that knows every chapter, its order and its sections:

  - a top bar: Contents, where you are, previous/next, a reading-progress line
  - the contents, as a sidebar on wide screens and a drawer on narrow ones, with the
    current chapter marked and its sections listed
  - previous/next cards at the end of a chapter; the next one shows that chapter's
    opening drawing and its caption, as a reason to keep going
  - the front page: the cover, start/continue/download, and every chapter as a card
  - a speculation rule, so the next chapter is already loaded when it is asked for

Nothing here reads the chapters' prose. It takes titles from the sitemap and, for the
cards, the first drawing of each chapter and that drawing's caption.

Usage: book-site.py <site-dir> <epub-file-name>
"""
import html
import json
import pathlib
import re
import sys

REPO = "https://github.com/zhen-swift/zhen-core"
BOOK = "Zhen &amp; Darwin, Illustrated"

site, epub = pathlib.Path(sys.argv[1]), sys.argv[2]
tree = json.loads((site / "sitemap.json").read_text())


# ── The chapters, in order ──────────────────────────────────────────────────────────
class Chunk:
    def __init__(self, node):
        s = node["section"]
        self.path = s["path"].split("#")[0]
        self.title = s["title"]
        self.sections = [
            (x["section"]["path"].split("#")[1], x["section"]["title"])
            for x in node["subsections"]
            if "#" in x["section"]["path"]
        ]
        m = re.match(r"^(Part [IVX]+|\d+|[A-Z]) · (.*)$", self.title)
        self.label, self.name = (m.group(1), m.group(2)) if m else ("", self.title)
        if self.label.startswith("Part"):
            self.kind = "part"
        elif self.label == "0":
            self.kind = "opening"
        elif self.label.isdigit():
            self.kind = "chapter"
        else:
            self.kind = "appendix"
        page = (site / self.path).read_text()
        img = re.search(r"<img\b[^>]*>", page)
        self.hero = re.search(r'src="([^"]+)"', img.group(0)).group(1) if img else None
        alt = re.search(r'alt="([^"]*)"', img.group(0)) if img else None
        self.blurb = alt.group(1) if alt else ""   # already HTML-escaped by pandoc
        self.part = None

    @property
    def short(self):
        """What the reader calls it: 'Chapter 5', 'Appendix D', 'Part II', 'Welcome'."""
        return {
            "chapter": f"Chapter {self.label}",
            "appendix": f"Appendix {self.label}",
            "part": self.label,
            "opening": "Welcome",
        }[self.kind]


chunks = [Chunk(n) for n in tree["subsections"]]
part = None
for c in chunks:
    if c.kind == "part":
        part = c
    elif c.kind == "appendix":
        part = None
    c.part = part if c.kind == "chapter" else None
chapter_count = sum(c.kind == "chapter" for c in chunks)
esc = html.escape


def where(c):
    if c.kind == "chapter" and c.part:
        return f"{esc(c.part.label)} · Chapter {esc(c.label)} of {chapter_count}"
    return esc(c.short)


# ── Pieces ──────────────────────────────────────────────────────────────────────────
ICON_MENU = ('<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">'
             '<path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="2" '
             'stroke-linecap="round"/></svg>')
ICON_PREV = ('<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">'
             '<path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2.2" '
             'stroke-linecap="round" stroke-linejoin="round"/></svg>')
ICON_NEXT = ICON_PREV.replace('d="M15 5l-7 7 7 7"', 'd="M9 5l7 7-7 7"')


def topbar(c, prev, nxt):
    def arrow(target, rel, icon):
        if not target:
            return f'<span class="topnav {rel} disabled" aria-hidden="true">{icon}</span>'
        return (f'<a class="topnav {rel}" href="{target.path}" rel="{rel}" '
                f'title="{esc(target.title)}" aria-label="{"Previous" if rel == "prev" else "Next"}: '
                f'{esc(target.title)}">{icon}</a>')
    here = where(c) if c else "Contents"
    return (
        '<header class="topbar">'
        '<button class="toc-toggle" type="button" aria-controls="toc" aria-expanded="false">'
        f'{ICON_MENU}<span>Contents</span></button>'
        f'<a class="brand" href="index.html">{BOOK}</a>'
        f'<span class="where">{here}</span>'
        f'<span class="topnavs">{arrow(prev, "prev", ICON_PREV)}{arrow(nxt, "next", ICON_NEXT)}</span>'
        '<span class="progress" aria-hidden="true"><span></span></span>'
        '</header>'
    )


def toc(current):
    def item(c):
        cur = c is current
        attrs = ' aria-current="page"' if cur else ""
        out = (f'<li class="toc-item{" current" if cur else ""}">'
               f'<a href="{c.path}"{attrs}><span class="toc-num">{esc(c.label)}</span>'
               f'<span class="toc-name">{esc(c.name)}</span></a>')
        if cur and c.sections:
            out += '<ol class="toc-sections">' + "".join(
                f'<li><a href="#{sid}">{esc(t)}</a></li>' for sid, t in c.sections) + "</ol>"
        return out + "</li>"

    groups, body = [], []
    for c in chunks:
        if c.kind == "part":
            groups.append(("part", c, []))
        elif c.kind == "appendix" and (not groups or groups[-1][0] != "appendix"):
            groups.append(("appendix", None, [c]))
        elif groups and c.kind in ("chapter", "appendix"):
            groups[-1][2].append(c)
        else:
            groups.append(("loose", None, [c]))
    for kind, head, members in groups:
        if kind == "loose":
            body.append(item(members[0]))
            continue
        if head is not None:
            cur = head is current
            mark = ' aria-current="page"' if cur else ""
            heading = (f'<a class="toc-part{" current" if cur else ""}" href="{head.path}"'
                       f'{mark}>{esc(head.title)}</a>')
        else:
            heading = '<span class="toc-part">Appendices</span>'
        body.append(f'<li class="toc-group">{heading}<ol>{"".join(item(m) for m in members)}</ol></li>')
    return (
        '<div class="scrim" hidden></div>'
        '<nav id="toc" class="toc" aria-label="Contents">'
        f'<div class="toc-head"><a class="toc-home" href="index.html">{BOOK}</a>'
        '<button class="toc-close" type="button" aria-label="Close the contents">×</button></div>'
        f'<ol class="toc-list">{"".join(body)}</ol>'
        f'<p class="toc-foot"><a href="{epub}" download>Download the EPUB</a></p>'
        '</nav>'
    )


def pager(prev, nxt):
    out = ['<nav class="pager" aria-label="Previous and next">']
    if prev:
        out.append(f'<a class="pager-card pager-prev" href="{prev.path}" rel="prev">'
                   f'<span class="pager-dir">{ICON_PREV}Previous</span>'
                   f'<span class="pager-title">{esc(prev.title)}</span></a>')
    else:
        out.append('<span class="pager-card pager-empty"></span>')
    if nxt:
        pic = f'<img src="{nxt.hero}" alt="" loading="lazy" />' if nxt.hero else ""
        out.append(f'<a class="pager-card pager-next" href="{nxt.path}" rel="next">{pic}'
                   f'<span class="pager-dir">Next{ICON_NEXT}</span>'
                   f'<span class="pager-title">{esc(nxt.title)}</span>'
                   f'<span class="pager-blurb">{nxt.blurb}</span></a>')
    else:
        out.append('<a class="pager-card pager-next pager-end" href="index.html">'
                   '<span class="pager-dir">The end</span>'
                   '<span class="pager-title">Back to the contents</span></a>')
    out.append("</nav>")
    return "".join(out)


def foot():
    return (
        '<footer class="foot">'
        f'<a href="{epub}" download>Download the EPUB</a>'
        f'<a href="{REPO}/tree/main/Docs/book">The book’s source</a>'
        f'<a href="{REPO}">zhen-core</a>'
        '<span>Pinned to zhen-core 0.9.0</span>'
        '<span class="keys"><kbd>←</kbd> <kbd>→</kbd> turn the page</span>'
        '</footer>'
    )


def head_extras(prev, nxt):
    out = []
    if nxt:
        out.append(f'<link rel="next" href="{nxt.path}" />')
    if prev:
        out.append(f'<link rel="prev" href="{prev.path}" />')
    rules = {}
    if nxt:
        rules["prerender"] = [{"source": "list", "urls": [nxt.path]}]
    if prev:
        rules["prefetch"] = [{"source": "list", "urls": [prev.path]}]
    if rules:
        out.append(f'<script type="speculationrules">{json.dumps(rules)}</script>')
    return "\n".join(out)


def card(c):
    pic = f'<img src="{c.hero}" alt="" loading="lazy" />' if c.hero else ""
    return (f'<li><a class="card card-{c.kind}" href="{c.path}">{pic}'
            f'<span class="card-num">{esc(c.short)}</span>'
            f'<span class="card-title">{esc(c.name)}</span>'
            f'<span class="card-blurb">{c.blurb}</span></a></li>')


def front():
    first = chunks[0]
    sections, current = [], None
    for c in chunks:
        if c.kind == "opening":
            sections.append(("Start here", None, [c]))
        elif c.kind == "part":
            sections.append((c.title, c, []))
        elif c.kind == "appendix" and sections[-1][0] != "Appendices":
            sections.append(("Appendices", None, [c]))
        else:
            sections[-1][2].append(c)
    out = [
        '<section class="front">',
        '<img class="cover" src="figures/cover.svg" alt="The cover: Pip the packet, a castle '
        'for the kernel, a ticket and a mailbox." />',
        '<div class="front-text">',
        f'<h1>{BOOK}</h1>',
        '<p class="subtitle">How a network scanner talks to the Apple kernel, explained with pictures.</p>',
        '<p>Every place zhen-core touches the Darwin kernel, from file descriptors to the '
        'privileged helper, drawn as a castle with doors. Every chapter ends with what an '
        'iPhone or iPad gets. Pinned to zhen-core 0.9.0.</p>',
        '<p class="actions">',
        f'<a class="btn primary" href="{first.path}">Start reading{ICON_NEXT}</a>',
        '<a class="btn continue" href="index.html" data-continue hidden>Continue: <span></span></a>',
        f'<a class="btn" href="{epub}" download>Download the EPUB</a>',
        '</p></div></section>',
    ]
    for title, head, members in sections:
        lead = f' <span class="part-blurb">{head.blurb}</span>' if head and head.blurb else ""
        link = f'<a href="{head.path}">{esc(title)}</a>' if head else esc(title)
        cls = "cards small" if title == "Appendices" else "cards"
        out.append(f'<section class="shelf"><h2>{link}{lead}</h2>'
                   f'<ol class="{cls}">{"".join(card(m) for m in members)}</ol></section>')
    return "\n".join(out)


# ── Every page ──────────────────────────────────────────────────────────────────────
def dress(path, c, prev, nxt):
    page = site / path
    text = page.read_text()
    title = f"{esc(c.title)} · {BOOK}" if c else BOOK
    text = re.sub(r"<title>.*?</title>", f"<title>{title}</title>", text, count=1, flags=re.S)
    text = text.replace("<!--BOOK:HEAD-->", head_extras(prev, nxt))
    text = text.replace("<!--BOOK:TOP-->", topbar(c, prev, nxt))
    text = text.replace("<!--BOOK:TOC-->", toc(c))
    text = text.replace("<!--BOOK:FOOT-->", foot())
    if c is None:
        text = re.sub(r'(<main id="content" class="page">).*?(</main>)',
                      lambda m: m.group(1) + "\n" + front() + "\n" + m.group(2),
                      text, count=1, flags=re.S)
        text = text.replace("<body>", '<body class="home" data-page="index.html">', 1)
    else:
        text = text.replace("<!--BOOK:PAGER-->", pager(prev, nxt))
        text = text.replace(
            "<body>",
            f'<body class="chapter kind-{c.kind}" data-page="{c.path}" data-title="{esc(c.title)}">', 1)
    text = text.replace("<!--BOOK:PAGER-->", "")
    page.write_text(text)


dress("index.html", None, None, chunks[0])
for i, c in enumerate(chunks):
    dress(c.path, c, chunks[i - 1] if i else None, chunks[i + 1] if i + 1 < len(chunks) else None)
print(f"book-site: {len(chunks)} pages dressed")
