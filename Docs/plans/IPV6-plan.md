# IPv6, and the refactor that makes it affordable

Written 2026-09-26. **Revises `Docs/DIRECTION.md`: IPv6 moves ahead of Linux.**
The reason is in section 2 and it is not "coverage".

---

## 1. Code quality, measured before anything is added

| | Count | Verdict |
|---|---|---|
| Force unwraps, `try!`, `as!` | **0 / 0 / 0** | exceptional |
| `fatalError` | 1 | fine |
| Structs vs classes | **151 / 31** | value-type first, as it should be |
| Protocols used as seams | **14** | real dependency inversion, not decoration |
| Comment share in the large files | **40-45%**, and they explain *why* | rare and worth protecting |

This is already better than most shipped Swift. Three things are not.

**`ScanPipeline.run` is 156 lines of code doing seven jobs** — discovery, name-resolution
merge, local-host MAC patching, the port stage, stage timing, degradation collection and
report assembly, all in one function body. It is the single responsibility violation in
the codebase and it is load-bearing: **every capability on the roadmap adds another branch
to it.** IPv6 adds two, Linux adds one, VLAN adds one. Fix it before, not after.

**`SSDPProbe.search` is 116 lines** — same shape, smaller.

**51 extensions across 28,000 lines is low.** Protocol conformances are declared inline on
the type. Splitting them out — `extension Device: Codable`, `extension IPv4Address:
Comparable` — is the Hacking-with-Swift habit and it matters more once the model grows a
second address family, because it is what keeps `Device.swift` from doubling.

## 2. Why IPv6 comes before Linux

I said Linux first two days ago. That was wrong, for a reason specific to this tool.

**IPv6 on a local link is not "the same scan with longer addresses". It is a second layer
2 discovery protocol**, and this tool's whole thesis is layer 2:

| | IPv4 | IPv6 |
|---|---|---|
| Neighbour discovery | ARP, 254 requests for a /24 | **NDP** — ICMPv6 Neighbor Solicitation |
| Finding hosts on the link | sweep every address | **one packet to `ff02::1`**, answered by every host that answers ICMPv6 echo — not all of them (below) |
| Always present? | only if configured | **yes** — every modern host self-assigns a link-local `fe80::` address |

That middle row is the product win, **with its coverage claim withdrawn as measured
2026-09-26.** One multicast packet is faster than a 254-address ARP sweep, quieter, and
works on a /64 where enumeration is impossible by construction. It does **not** reach every
host: on JC's network one solicitation found 6-7 hosts against the sweep's 10, five trials
of five, because four hosts answer no ICMPv6 echo at all. "Every modern host self-assigns a
link-local address" is true; "therefore one packet reaches all of them" does not follow from
it, and that inference was this document's mistake.

It earns its packet anyway: one host answered the multicast that no v4 probe found. So it
ships as a **complementary** source fused by MAC, not as a replacement for the sweep.
See Q2 in `Docs/process/V6-questions.md` for the decision and the gate that replaces D2's.

**The ordering argument.** IPv6 changes the model — `Device.ip: IPv4Address` is the crux,
and `IPv4Address` is named in 41 files. Doing it first means `ZhenLinux` is written once
against the final model. Doing Linux first means writing it for v4 and then retrofitting
v6 into two platforms instead of one.

## 3. Schema 3, done once

`open_filtered` bumped the artifact to 2 for a state nothing produces. Schema 3 is the
real one, and it should carry everything the roadmap needs so there is no schema 4 next
month:

- a device's addresses become a **set**, not a single `ip` — a host has a v4 address, a
  link-local v6 and often a global v6, and they are one device
- per-address family on every observation
- room for the VLAN tag that item 3 of the roadmap will add

Write the migration for schema 1 and 2 documents in the same commit. The history store has
real data in it.

---

## 4. Stages

**Stage 0 — decompose `ScanPipeline.run`.** No behaviour change, no new capability. Pull
the seven jobs into named stages behind a small protocol so a stage can be added without
touching the others. *Gate:* `zhen scan` and `zhen scan --deep` produce byte-identical
artifacts before and after, same fixture, same seed.

**Stage 1 — `IPAddress` in the model.** An enum over v4 and v6, `Comparable`, `Codable`,
parseable from text including zone identifiers (`fe80::1%en0`). `IPv4Address` stays exactly
as it is and becomes a case. *Gate:* every RFC 5952 canonical-form example round-trips; the
41 files that name `IPv4Address` still compile.

**Stage 2 — `Device` holds addresses, not an address.** Schema 3, with migration from 1
and 2. *Gate:* every artifact in the history store reads back; a device with a v4 and two
v6 addresses is one device, not three.

**Stage 2b — the UDP engine, shipped with schema 3.** See `Docs/plans/PORTS-plan.md` on why
UDP needs the fourth state. `open_filtered` exists and nothing produces it; this is the
stage that closes that, and it belongs in the same breaking release as schema 3 rather
than in one of its own.

It is cheaper than it looks and it **removes** code. `SSDPProbe` and `NetBIOSProbe` each
carry their own `sendto`/`recvfrom` pair — the UDP datagram machinery is already written
twice and abstracted zero times. Extract one `UDPProbe` seam from them, add a payload
table for DNS 53, NTP 123, NetBIOS 137, SNMP 161, mDNS 5353 and SSDP 1900, and the port
scanner reuses what the naming stage already speaks.

*Gate:* a parsed answer is `open`; silence is `open_filtered` and never `filtered`; the
two existing naming probes still pass their suites after being rebased onto the extracted
seam.

**Stage 3 — ICMPv6 echo, unprivileged.** The v6 twin of `ICMPSocket`, `SOCK_DGRAM` /
`IPPROTO_ICMPV6`. *Gate:* a link-local address answers, and the checksum is verified
against a captured packet — ICMPv6 checksums cover a pseudo-header that ICMPv4's do not,
which is the thing that silently fails.

**Stage 4 — `ff02::1` multicast discovery**, as a complement (D2′; Q2 in
`Docs/process/V6-questions.md`). One solicitation beside the v4 sweep, responders joined to v4
devices by MAC. *Gate, as Q2 rewrote it:* the union finds at least what the v4 sweep finds
alone, plus every host only the multicast reached; every v6 address lands on the right v4
device; a v6-only responder is a device of its own. One packet sent, not 254. The original
gate — at least as many hosts as the sweep — failed as measured and is withdrawn.

**Stage 5 — NDP neighbour table.** The v6 side of `NeighborTable`, so a cached neighbour
counts as discovery evidence the same way an ARP entry does. *Gate:* a host that answers
neither ICMP nor multicast but sits in the NDP cache is still reported, with its source
named as the cache.

**Stage 6 — port scanning over v6.** `TCPConnectScan` first, since it is socket-level and
mostly address-family-agnostic. SYN scan over v6 needs a different BPF filter and a
different pseudo-header; it is a stage of its own and it is fine for it to come later.
*Gate:* a port open on a v6 address is reported as open, and the artifact names the family.

**Stage 7 — extensions pass.** Protocol conformances moved out of the type bodies.
*Gate:* `Device.swift` is shorter after adding v6 than it was before.

## 5. Out of scope

- SYN scan over IPv6 — its own stage, after this; it needs a different BPF filter and a
  different pseudo-header
- **nmap's service-probe database.** Banner plus TLS certificate is the honest floor and
  it is where port scanning stops. Matching a thousand probe signatures is how this
  becomes a slower nmap, and it is not the differentiator
- `top-N` — correctly refused in `8c266ef`; it stays refused until there is frequency
  data this project can source
- IPv6 global-address enumeration — a /64 is 18 quintillion addresses; multicast and NDP
  are the only sane discovery, and pretending otherwise is the "fancy ARP" failure in a new
  costume
- Linux — next, and cheaper for having waited
