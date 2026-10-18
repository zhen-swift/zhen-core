# zhen-core

A fast, native network scanner for macOS, written entirely in Swift 6 — the engine, the
`zhen` command line, and the privileged helper, as one Swift package.

Scans a `/24` in about three seconds, names the devices it can, and — the part most
scanners get wrong — tells you plainly what it could *not* work out and why.

```
ADDRESS      NAME                     MODEL       HARDWARE           RTT       TTL
10.10.20.1   —                        —           7O:20:51:74:CB:28  15.06ms   64
10.10.20.2   Sala de                  AppleTV5,3  C8:69:CD:5E:02:E1  32.04ms   64
10.10.20.3   —                        —           86:9F:22:5E:14:B3  268.93ms  32
10.10.20.8   MacBook Pro              —           52:A1:8A:5E:05:8A  —         —
10.10.20.12  —                        —           32:37:C0:5E:17:22  33.41ms   64
9 devices · 3109ms · 761 probes, 15 replies · 245 probes/s
```

This repository is the library and the command-line tool. Two others sit beside it:

| | |
|---|---|
| [`zhen-app`](https://github.com/zhen-swift/zhen-app) | the macOS app, which depends on this package by version |
| [`zhen-study`](https://github.com/zhen-swift/zhen-study) | the frozen measurement study behind the timing model |

Nothing here knows the app exists.

## Why

Three things make a fast, honest scanner possible on this platform:

- **Unprivileged ICMP datagram sockets work on macOS.** No password, no helper, no
  setuid binary — the default path is fully functional and always has been.
- **The ARP table is free layer-2 truth.** The kernel already knows the hardware address
  of everything this machine has recently talked to.
- **Bonjour gives names `nmap` never sees.** On a home network that is most of the naming
  value, and it is why mDNS here is a primary source rather than a fallback.

The timing is where the speed comes from, and it is one idea: **retransmit early, declare
late.** "How long before I ask again?" is answered from a low quantile of observed round
trips, because a lost frame costs one packet. "How long before I say nobody is home?"
genuinely needs the tail of the distribution — but it is asked *once*, at the end, and it
overlaps every address at the same time. A conventional scanner pays the tail per host,
per attempt, on the two hundred addresses where nothing exists.

**No subprocesses. No bundled interpreters. No external binaries. Ever.**

## Installing

`zhen` runs on macOS 14 (Sonoma) and later, on Apple silicon and Intel. Building it
needs Xcode 26, which needs macOS 15.6, so on Sonoma install it through Homebrew
(`brew tap zhen-swift/zhen && brew install zhen`), which fetches a prebuilt binary there. On 15.6
and later, from source:

```bash
PREFIX=$HOME/.local ./Scripts/install.sh
```

Builds release and installs `zhen` and its man page under the prefix. It never calls
`sudo` and never asks for a password; if the destination is not writable it prints the
exact command and stops. `sudo PREFIX=/usr/local ./Scripts/install.sh` for system-wide,
and the same command with `uninstall` to remove it.

If a command behaves unlike the manual, check which copy you are running: `type -a zhen`.
An older install earlier on `PATH` shadows a newer one, and macOS puts `/usr/local/bin`
ahead of `~/.local/bin`.

## Using it as a library

```swift
.package(url: "https://github.com/zhen-swift/zhen-core.git", from: "0.8.0")
```

## Building

One package, needs only a Swift toolchain:

```bash
swift build            # the library and the command line
swift test             # everything; on Linux, everything portable
swift build --product zhen-helper
```

`ZhenCore` has no platform code in it, so it builds on Command Line Tools alone — and on
Linux, which CI proves on every change rather than asserting. See
`.github/workflows/ci.yml`.

## Using it

Nearly everything divides in two: **what is on this network**, and **what is open on this
host**.

```bash
zhen scan                          # sweep the network on your default route
zhen scan --cidr 10.10.20.0/24     # a network you name
zhen scan --deep --ports 22,80,443 # sweep, then probe what answered
zhen scan --deadline 5s            # spend at most five seconds

zhen ports 10.10.20.11 22          # is ssh open on this host
zhen ports 10.10.20.11 ssh,http    # by service name — selects a port, never names a result
zhen ports 10.10.20.0/24 22        # is ssh open anywhere on this network
zhen ports fe80::1%en0 22          # IPv6, zone and all
zhen ports 10.10.20.1 53 --udp     # UDP
zhen ports host 22 --check         # exit 0 if open, 1 if not; prints nothing

zhen hosts                         # everything history has seen, present or absent
zhen events                        # what changed between scans
zhen history 10.10.20.11           # one device, and what has happened to it
zhen export                        # the whole history as one JSON document

zhen scan --json                   # a machine-readable artifact
zhen scan --ndjson                 # one event per line, as they happen
```

**`Docs/MANUAL.md` is the guide**; `man zhen` is the reference. Port results carry four
states rather than two — `open`, `closed`, `filtered` and `open_filtered` — and the manual
explains why collapsing them loses the only signal that separates a firewalled host from a
dead address.

Every run produces a report that states what it cost — probes sent, replies seen, elapsed
per stage, and the budget each stage was given. A scanner whose selling point is speed
should be able to prove it from its own output, so a regression is a diff rather than a
feeling.

**Read `SECURITY.md` before pointing this at a network you do not run.**

## Shape

| Target | What it is | Isolation |
|---|---|---|
| `ZhenCore` | Model, time, concurrency, protocols. No platform code. Builds and tests on Linux | non-isolated |
| `CBPFShim` | Header-only C for the `BIOCSETIF` family, which are macros ClangImporter will not evaluate | — |
| `ZhenPrivilege` | The one privileged resource. Small enough to read in a sitting, because a root process should not carry a TLS client around | non-isolated |
| `ZhenDarwin` | Sockets, BPF, `dns_sd`, the route table. Every file behind `#if canImport(Darwin)` | non-isolated |
| `ZhenScan` | The app's adapter over the engine — sibling to the CLI's `ScanPipeline` | non-isolated |
| `zhen` | The command line | **MainActor** |
| `zhen-helper` | The launch daemon the app bundle embeds | non-isolated |

### The isolation column is the important one

Swift 6.2's main-actor-by-default is right for a command line, where entry points and
terminal output are inherently serial, and actively harmful in a scanner, where it would
hop every socket helper onto the main actor and serialize the scan behind the display.

Getting it backwards does not fail. It compiles, it runs, and the scanner is quietly
serialized for the rest of the product's life. That is why the boundary is a target
boundary and not an annotation: there is no keyword to forget.

`ZhenScan` lives here rather than with the app for exactly this reason — it is the one
piece of the app's data layer that must stay off the main actor, and the app target is
main-actor by default.

## Documentation

| | |
|---|---|
| `Docs/MANUAL.md` | how to use the tool |
| `Docs/README.md` | what each document is and the order to read them |
| `Docs/SPEC.md` | the original technical specification |
| `Docs/01-the-library.md`, `Docs/02-the-cli.md` | architecture and rationale |
| `CHANGELOG.md` | what changed, newest first |

## History

This package moved to the root of its own repository on 2026-10-03. Its history here
begins on 2026-09-26, when it was gathered into one package at `zhen/`; everything before
that — when it was `zhen-core` and `zhen-cli` under `Packages/` — is in the archived
monorepo this repository was split from.

## Licence

**Apache License 2.0.** Use it, fork it, ship it commercially — the licence asks only
that you keep the notice and state your changes. It also grants a patent licence, which
MIT does not, and that is the reason to prefer it here. See `LICENSE` and `NOTICE`.

Shipping it inside something else? The `NOTICE` text belongs in your acknowledgements —
the licence asks for that much — and a link back to this repository is appreciated beyond
it: it is how a small project gets found. Citing it in a paper or a report: `CITATION.cff`
has the details, and GitHub offers them as **Cite this repository**.
