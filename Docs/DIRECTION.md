# Direction: a portable network tool, CLI first

Written 2026-09-26. A positioning decision and the roadmap it implies. Supersedes the
implicit ordering in every other plan in this folder.

**The app is now downstream of the library.** Where the app's needs and the CLI's
conflict, the CLI wins and the app follows. Where a better API breaks the app, take the
better API.

---

## 1. Where the tool actually stands

| | |
|---|---|
| Licence | Apache 2.0 — correct for a community library, already in place |
| CI | macOS build and test, **plus a Linux job that builds and tests `ZhenCore`** |
| `ZhenCore` on Linux | **already portable and enforced by CI** |
| `ZhenDarwin` on Linux | does not exist — every probe, sweep and scan is macOS-only |
| IPv6 | **zero.** Not a gap in coverage, an absence: no `AF_INET6`, no `in6_addr`, anywhere |
| 802.1Q VLAN tags | **not read.** Documented in three places as a known limit |

The bones for a community library are there. What is missing is that the library does
nothing off macOS, and nothing on a network that is tagged or dual-stack.

## 2. The thesis: go deeper at layer 2, not wider at layer 7

nmap owns breadth and will own it forever. Twenty-five years of service probes and NSE
scripts is not a gap that gets closed by a fast reimplementation, and trying is how this
becomes a worse nmap.

The edge is the opposite direction. **This tool is already at layer 2, which is where
nmap is weakest**, and there is no serious Swift networking library at all. Three
pillars, each of which nmap does badly or not at all:

| | The pillar | Why it is ours |
|---|---|---|
| **L2 truth** | VLAN tags, LLDP and CDP neighbour discovery, ARP anomaly detection | LLDP tells you **which switch port a host is plugged into**. nmap cannot do this. It is the single most useful fact in a wiring closet and no portable tool surfaces it well |
| **Continuity** | `zhen diff`, `zhen watch` — what changed on this network since yesterday | The history store already exists. nmap needs `ndiff` bolted on as a separate Python script. This is half-built and nobody else has it native |
| **A real library** | `ZhenCore` as the Swift package people import | Apache 2.0, CI-portable, and there is no competition. A Vapor service that wants to know what is on its LAN has nothing to import today |

"Not just a fancy ARP" is answered by going **further down**, not further up.

## 3. Portability is the unlock, and it is one target

`ZhenLinux`, sibling to `ZhenDarwin`, behind the `PlatformSeam` that already exists.

| Capability | macOS today | Linux equivalent |
|---|---|---|
| Frame capture | `/dev/bpf*` | `AF_PACKET` + `SOCK_RAW` |
| Filter | BPF program via `BIOCSETF` | the same BPF, via `SO_ATTACH_FILTER` — **the filter compiler is already portable** |
| Neighbour table | `sysctl` route messages | netlink `RTM_GETNEIGH` |
| Privilege | `SMAppService` daemon + XPC | `CAP_NET_RAW` on the binary — no helper, no daemon, no notarization |
| ICMP unprivileged | `SOCK_DGRAM`/`IPPROTO_ICMP` | the same, via `ping_group_range` |

Linux is *simpler* than what has already been built. There is no helper to install, no
code signature to arrange, no user-facing consent. `CAP_NET_RAW` and the tool runs.

This also fixes something structural: a seam with one implementation is not a seam, it is
an indirection. The Darwin assumptions that leaked through it only become visible when a
second platform pulls on them.

## 4. Ranked, with the reasoning

| | Work | Why here |
|---|---|---|
| **1** | `ZhenLinux` — capture, filter, neighbours, ICMP, TCP scans | The portability claim, and it proves the seam. Everything after this is written once for two platforms instead of twice for one |
| **2** | **IPv6 end to end** | The biggest credibility gap. A network tool that cannot see a dual-stack network is not a network tool in 2026. Deliberately after the seam, so it is done once |
| **3** | **802.1Q** — read tagged frames, report the VLAN per host | Today a trunk port shows nothing. This is the difference between a home-LAN toy and something usable at work |
| **4** | **LLDP and CDP** — passive listen, report switch, port, and native VLAN | The differentiator. Passive, so it works where active scanning is forbidden |
| **5** | **`zhen diff`** — two runs, what appeared, vanished, changed address or identity | The store is already there. Cheapest large feature on the list |
| **6** | **`zhen watch`** — continuous scan, emit change events on NDJSON | Deliberately absent today, per `Zhen.swift`. With diff done, this is the loop around it |
| **7** | **ARP anomalies** — duplicate address, gratuitous ARP, a MAC that moved ports | Falls out of 3, 4 and 6 nearly free, and it is the security-adjacent value nobody gets from a sweep |
| **8** | **Library hygiene** — public API review, DocC, semver, a tagged 1.0 | Do it once the API has been pulled on by two platforms and two address families, not before |

UDP, `top-N` and the service-probe database stay where they are: behind everything above.
They are how you become a slower nmap.

## 5. What this costs, stated plainly

**The app stops being a peer.** It keeps building and keeps its accessibility work, but it
no longer constrains the library. Stages 6, 7 and 8 of the responsive plan finish; nothing
new is started there. The app becomes the demo that the library is good.

**Two constraints get relaxed on purpose:**

- *Artifact schema stability.* Frozen because readers existed. The readers are the app and
  the study, and the study is finished and frozen. Adding IPv6 addresses and VLAN tags to
  a device **will** be a schema change. Do it once, deliberately, as schema 3 — not
  drip-fed.
- *macOS-only assumptions in the CLI.* `zhen-cli` declares `.macOS(.v26)`. That comes off.

**Two constraints get stricter:**

- *Public API.* Once people import it, a rename is someone else's build break. The API
  review at item 8 is not optional and its absence today is fine only because nobody has
  imported it yet.
- *CI.* The Linux job currently builds `ZhenCore` alone. It has to build and test the
  whole thing, and the macOS-only skips have to be visible rather than silent.

**The honest risk.** The paper is unfinished — `paper` has zero commits and four known
fixes outstanding. This roadmap is a year of evenings. Doing both badly is the default
outcome of not choosing. **Finish the paper on study 1 as it stands.** It measures a
macOS ARP scanner against nmap and that result does not improve by making the tool
portable; it only gets harder to write as the thing it describes moves underneath it.

## 6. What the README has to stop saying

> *A fast, native network scanner for macOS, written entirely in Swift 6.*

Every clause of that is a smaller claim than the plan above. It gets rewritten when item
1 lands and not before — a positioning statement written ahead of the code is marketing.

---

## 7. Immediate next action

**Item 1, stage one only: make `ZhenLinux` capture a frame.**

Not the whole platform. One target, `AF_PACKET`, one filter attached with
`SO_ATTACH_FILTER` reusing the existing BPF compiler, one ARP request on the wire and one
reply read back, under `CAP_NET_RAW` and not root. That is the question the rest of item 1
depends on, the same way stage 0 worked for the responsive plan: if the filter compiler
does not port cleanly, the shape of `ZhenLinux` changes and it is better to know in a day.
