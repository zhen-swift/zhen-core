// Zhen & Darwin, Illustrated — the web edition's behaviour.
//
// Everything here is an enhancement: with scripts off, every page still has its contents,
// links and previous/next cards. This adds the drawer, the arrow keys, the reading-progress
// line, the "you are here" mark in the contents, and "Continue where you left off".
(() => {
  const root = document.documentElement;
  const body = document.body;
  const toc = document.getElementById("toc");
  const toggle = document.querySelector(".toc-toggle");
  const scrim = document.querySelector(".scrim");
  const narrow = window.matchMedia("(max-width: 1099px)");

  // ── The contents drawer (narrow screens) ──────────────────────────────────────────
  function setOpen(open) {
    root.classList.toggle("toc-open", open);
    toggle?.setAttribute("aria-expanded", String(open));
    if (scrim) scrim.hidden = !open;
    if (open) {
      (toc?.querySelector('[aria-current="page"]') ?? toc?.querySelector("a"))?.focus({ preventScroll: true });
    } else if (toc?.contains(document.activeElement)) {
      toggle?.focus();
    }
  }
  toggle?.addEventListener("click", () => setOpen(!root.classList.contains("toc-open")));
  toc?.querySelector(".toc-close")?.addEventListener("click", () => setOpen(false));
  scrim?.addEventListener("click", () => setOpen(false));
  // A section link in the drawer scrolls this page; close the drawer so the text shows.
  toc?.addEventListener("click", (e) => {
    if (narrow.matches && e.target.closest('a[href^="#"]')) setOpen(false);
  });
  narrow.addEventListener("change", () => setOpen(false));

  // ── Keys: ← → turn the page, Esc closes the drawer ────────────────────────────────
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && root.classList.contains("toc-open")) {
      setOpen(false);
      return;
    }
    if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (e.target.closest?.("input, textarea, select, [contenteditable]")) return;
    const rel = e.key === "ArrowLeft" ? "prev" : e.key === "ArrowRight" ? "next" : null;
    if (!rel) return;
    const link = document.querySelector(`.topbar a[rel="${rel}"]`);
    if (link) {
      e.preventDefault();
      window.location.href = link.href;
    }
  });

  // ── Reading progress ──────────────────────────────────────────────────────────────
  const bar = document.querySelector(".progress > span");
  if (bar && body.classList.contains("chapter")) {
    let queued = false;
    const draw = () => {
      queued = false;
      const max = root.scrollHeight - window.innerHeight;
      const done = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 1;
      bar.style.transform = `scaleX(${done})`;
    };
    const ask = () => {
      if (!queued) {
        queued = true;
        requestAnimationFrame(draw);
      }
    };
    window.addEventListener("scroll", ask, { passive: true });
    window.addEventListener("resize", ask);
    draw();
  }

  // ── The contents: show the current chapter, and the section being read ────────────
  const current = toc?.querySelector('.toc-item.current, .toc-part.current');
  if (toc && current) {
    toc.scrollTop = Math.max(0, current.offsetTop - toc.clientHeight / 3);
  }
  const sectionLinks = [...(toc?.querySelectorAll(".toc-sections a") ?? [])];
  if (sectionLinks.length && "IntersectionObserver" in window) {
    const byId = new Map(sectionLinks.map((a) => [decodeURIComponent(a.hash.slice(1)), a]));
    const headings = [...byId.keys()].map((id) => document.getElementById(id)).filter(Boolean);
    const visible = new Set();
    const mark = () => {
      // The last heading scrolled past the top third of the screen is the one being read.
      let active = headings[0];
      for (const h of headings) {
        if (h.getBoundingClientRect().top < window.innerHeight / 3) active = h;
      }
      sectionLinks.forEach((a) => a.classList.remove("active"));
      byId.get(active?.id)?.classList.add("active");
    };
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => (en.isIntersecting ? visible.add(en.target) : visible.delete(en.target)));
      mark();
    }, { rootMargin: "0px 0px -60% 0px" });
    headings.forEach((h) => io.observe(h));
    window.addEventListener("scroll", () => requestAnimationFrame(mark), { passive: true });
    mark();
  }

  // ── Continue where you left off ───────────────────────────────────────────────────
  // Per reader, in this browser only. Storage can be missing or blocked; the page works without it.
  const KEY = "zhen-darwin:last-read";
  const page = body.dataset.page;
  if (page && page !== "index.html") {
    try {
      localStorage.setItem(KEY, JSON.stringify({ page, title: body.dataset.title }));
    } catch {}
  }
  const resume = document.querySelector("[data-continue]");
  if (resume) {
    try {
      const last = JSON.parse(localStorage.getItem(KEY) || "null");
      if (last?.page && /^[\w.-]+\.html$/.test(last.page)) {
        resume.href = last.page;
        resume.querySelector("span").textContent = last.title || last.page;
        resume.hidden = false;
      }
    } catch {}
  }
})();
