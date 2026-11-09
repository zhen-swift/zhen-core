# 0 · Welcome: meet the cast

![Pip, the castle, its doors, tickets and mailboxes.](figures/00-hero.svg)

::: short
The short version

- Zhen is a network scanner. To find who's on your network, it has to ask the **kernel** for help, thousands of times a second.
- The kernel is a **castle**. Your app can't walk in; it knocks on **doors** (system calls).
- The kernel hands back **tickets** (file descriptors), and the most important things a ticket points at are **mailboxes** (sockets).
- Only one part of Zhen, **ZhenDarwin**, ever knocks. Everything else is plain Swift.
- Each chapter is pictures first, short lists second, and real code only where it helps.
:::

## Meet the cast

![Eight characters you'll see in every chapter.](figures/00-cast.svg)

- **Pip** is your guide. In a drawing Pip is usually "our app", and sometimes a single packet.
- **The castle** is the kernel: the one program that owns the hardware.
- **A door** is a system call, one kind of request: `socket`, `read`, `close`…
- **A ticket** is a file descriptor, the small number the kernel gives back (chapter 2).
- **A mailbox** is a socket, the thing that actually sends and receives on the network.
- Later you'll meet the **periscope** (BPF, Mac only), the **crown** (root) and the **padlock** (not allowed).

::: word
New word: kernel

The **kernel** is the core of the operating system. It runs with full power over the hardware, and every app has to ask it for anything that touches a disk, a screen or a network.
:::

## Four layers, one door-knocker

![The apps sit on top. Only ZhenDarwin talks to the kernel. ZhenCore, beside it, is pure Swift.](figures/00-layers.svg)

From the top down:

1. **The apps.** `zhen-ios` (iPhone and iPad), `zhen-app` (the Mac app) and the `zhen` command line.
2. **ZhenScan**, the adapter the two apps use: "run one scan, give me the result". It makes no syscalls of its own (`Package.swift:41-46`). The command line has its own pipeline instead (`ScanRunner.swift:17-22`).
3. **ZhenDarwin**, the **only** code that knocks on the kernel's doors. Every file in it is wrapped in `#if canImport(Darwin)` (`Package.swift:139-144`).
4. **The kernel**, Apple's XNU (chapter 1).

And beside them:

- **ZhenCore** is the brains: models, timing, wire formats. It is pure Swift with no network syscalls, and it must keep compiling on Linux (`Package.swift:141-144`). Every layer above uses it.
- One small exception: ZhenCore takes a file lock (`flock`) on the history file, because Foundation has no portable way to do it (`LogHistoryStore.swift:91-111`).

## How to read this book

![Six kinds of box and three marks.](figures/00-boxes.svg)

Every chapter has the same shape: a big drawing, **the short version**, two to five sections with a drawing each, and these boxes:

- **short**: the whole chapter in 3–5 bullets. Read only these and you'll still follow along.
- **word**: a new word, explained the first time it shows up. They are all collected in Appendix A.
- **iphone** (📱): what an iPhone or iPad gets. Each line starts with a mark:
  - ✅ works
  - ❌ not built, or not allowed
  - ⚪️ built but switched off, or not yet measured on a real device
- **gotcha** (⚠️): bugs and traps that the code's own comments remember.
- **remember** (🧠): a three-line recap.
- **honest**: a place where the code and its own comments disagree. They are collected in Appendix D.

Code bites are real code, eight lines at most, with a caption like `ICMPSocket.swift:81` that says exactly where they come from.

## The map

![Four parts and the appendices.](figures/00-map.svg)

1. **Part I · Kernel basics** (chapters 1–4): the castle, tickets, addresses, and never waiting.
2. **Part II · The engine that runs everywhere** (chapters 5–10): ping, TCP, UDP, interfaces, names, and the smart parts on top. All of it runs on the iPhone too.
3. **Part III · Mac only** (chapters 11–14): BPF, the routing table, SYN scans and the privileged helper.
4. **Part IV · The iOS lens** (chapters 15–17): what your iPhone gets, from a tap to a syscall, and what only a real device can answer.
5. **Appendices A–E**: glossary, syscall cheat sheet, errno table, honest notes, further reading.

::: iphone
📱 On iPhone & iPad

- ✅ The same engine runs on the iPad: ZhenCore, ZhenDarwin and ZhenScan all build for iOS (`Package.swift:71-76`).
- ❌ The privileged half doesn't: no BPF, no routing socket, no helper (Part III says why).
- ⚪️ What a real device's sandbox allows is checked by the app's **Diagnostics** screen (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:28-33`). Part IV is about that.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Line numbers move.** Every `File.swift:NN` here is a line at tag `0.9.0`. If you read a newer checkout, search for the code, not the number.
- **"Main actor by default" is for apps, not scanners.** The library targets turn it off on purpose; otherwise every socket call would queue up behind the UI (`Package.swift:14-23`).
:::

::: remember
🧠 Remember

- Castle = kernel, door = system call, ticket = file descriptor, mailbox = socket.
- Only **ZhenDarwin** knocks on doors. ZhenCore is pure Swift.
- Look for ✅ ❌ ⚪️ in every chapter to see what your iPhone gets.
:::
