# Documentation

Two kinds of document, and the difference matters more than the order.

| | |
|---|---|
| **This folder** | **Reference.** What is true now. Start here |
| `plans/` | **Intent.** What was decided, and the reasoning. Superseded in places by what building found — each says so |

If you are new, read `MANUAL.md`, then `01-the-library.md`.

**Paths in older documents.** Until 2026-10-03 this package lived at `zhen/` inside a
larger repository, beside the app and the measurement study. Documents written before then
name its files with a leading `zhen/`; here that directory is the root, so drop the
prefix. A path they name outside `zhen/` is in one of these:

| | |
|---|---|
| [`zhen-app`](https://github.com/zhen-swift/zhen-app) | the macOS app, its design system and artboards, and their documents |
| [`zhen-study`](https://github.com/zhen-swift/zhen-study) | the frozen measurement study behind the timing model |
| the archived monorepo | not published here: ledgers, run reports, agent briefs, and the package's history before it moved to `zhen/` on 2026-09-26 |

## Start here

| | |
|---|---|
| `MANUAL.md` | **How to use the tool.** Task-shaped: the two questions it answers, every subcommand, how to read a port result, and what it deliberately does not do. `man zhen` is the reference; this is the guide |
| `AUDIT.md` | The state of the documentation and of maintainability, measured on the monorepo before the split. Says what was wrong and in what order to fix it |
| `DIRECTION.md` | What the tool is for, and why it goes deeper at layer 2 rather than wider at layer 7 |
| `IPADOS.md` | The engine on iPadOS: what the sandbox leaves of it, what was cut and why, and what only a device can still answer |

## The specification

| | |
|---|---|
| `SPEC.md` | The original technical specification. Still authoritative on **concurrency, the identity model, the store, deadlines and the privilege model** — that is where the hard thinking lives, and it is amended rather than replaced where it has been overtaken. The store requirement carries two such amendments, dated in place: SwiftData is Darwin-only, so it could not survive the portability requirement unqualified — and then, once the app was wired to the same file the command line writes, the SwiftData conformance was withdrawn for shipping nowhere. One further part is deliberately out of date: the naming and layout describe one package with `IC`-prefixed modules where the tool is now this package, with the app in its own repository |

## Build briefs

Written as instructions to whoever implements each layer, which is why they address the
reader directly. They are kept as-is because the reasoning in them is the record of why
each layer looks the way it does. **Where a brief names a mechanism the repository has
since changed, the reasoning still holds and the mechanism does not** — the notes below
say which.

| | |
|---|---|
| `01-the-library.md` | The definition layer: the output model, the async contracts, and the nine places the platform does not meet Swift halfway. Its manifest excerpts predate the merge of `zhen-core` and `zhen-cli`; `Package.swift` is the authority |
| `02-the-cli.md` | The command-line tool. Same note on the manifest |
| `04-privileged-helper.md` | The `SMAppService` seam: where it attaches, what Darwin's missing `BIOCLOCK` costs, and what has to be true before it is built. It is built |

The app's brief, `03-zhen-app.md`, is in `zhen-app` with the app.

## `plans/` — intent

| | |
|---|---|
| `IPV6-plan.md` | IPv6 before Linux, and why. Its coverage claim for `ff02::1` was withdrawn by measurement; the note is in place |
| `PORTS-plan.md` | The port-scanning capability, and why UDP needs a fourth state |
| `PORTS-ergonomics.md` | Why asking about a port should be one short command |
| `PORTS-rendering.md` | Matrix or long form, and why a single `PORTS` column would be wrong |
