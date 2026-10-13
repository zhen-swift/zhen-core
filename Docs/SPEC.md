# Zhen — Implementation Specification

**Audience:** an AI implementer with vision capability, reading this *after* the UI design canvas
has been produced.

**Division of authority:** the design canvas is the visual source of truth — layout, hierarchy,
color, spacing, typography, states. This document is the technical source of truth — architecture,
concurrency, data model, protocols, and behavior. Where they appear to disagree, the design wins
on *what the user sees* and this document wins on *how it works*. Neither should be silently
overridden; flag the conflict instead.

**Status when this was written:** greenfield. `~/Dev/InfinityCastle/` is empty apart from this
file. Nothing has been implemented.

---

## Mission

A native macOS application that scans a local network, identifies every device on it, remembers
everything it has ever seen, and shows what changes over time.

**Amended 2026-10-13:** this specification originally included an integration with one vendor's
network controller, as a privileged source of facts no on-wire probe can reach. That integration
was dropped before it was built, and every part of this document that described it has been
removed rather than left to read as a plan. The name-priority slot it occupied survives as
`NameSource.administrative` — see `Sources/ZhenCore/Model/Naming.swift`.

It is written entirely in Swift 6. It launches no subprocesses, bundles no interpreters, and
depends on no external binaries.

**The GUI is the product.** A command-line binary exists over the same library for scripting and
automation, but the app is the point, and the architecture is shaped by what the app needs.

### Requirements

1. **100% Swift 6.** Strict concurrency, async/await throughout. No external binaries, ever.
2. **IP scanning** — host discovery across the local network.
3. **Deep scan** — open ports and host identification, natively.
4. **mDNS integrated** — Bonjour drives naming conventions as a primary source.
5. **Persistence behind one protocol** — hosts, connection history, and network activity over
   time, reached through `HistoryStore` in core. **Amended 2026-09-09:** the original rule was
   "SwiftData only, not even as a cache", which cannot hold alongside the portability requirement
   that came later — SwiftData is Darwin-only — so a second conformance, an append-only log,
   served Linux. **Amended again 2026-09-11: the SwiftData conformance is withdrawn, and history
   is the portable log on every platform.** The app was wired to the log file `zhen scan`
   writes, because one shared file is the only reason the app and the command line agree about
   the network, and that left the SwiftData store referenced by nothing but its own tests. A
   conformance that ships nowhere is not a second implementation of an idea, it is a second
   description of one, and it was already costing an Xcode-only macro plugin as a build
   prerequisite and a place in the store suite that the conformance the app actually opens did
   not have. What the original rule was protecting against — a second store appearing as an
   unaccountable cache beside the first — is still protected: there is one store, and the seam
   above it has two conformances that ship, the log and the session-lifetime one the app falls
   back to when there is nowhere to write. SwiftData returns the day something Apple-side needs
   what it offers and the log cannot give — live queries driving a view, most plausibly — and
   that is a decision to take with a feature in hand rather than in advance.
6. *(Withdrawn — the controller integration; see the amendment under Mission.)*
7. **One shared library** behind both a CLI and a SwiftUI macOS app.
8. **Privileged path optional** — a sudoless engine and a root/BPF engine both exist; sudoless is
   the default and must remain fully functional.
9. **Every stage bounded by a deadline.** Nothing may block indefinitely. Partial results are a
   normal, expected outcome — not an error.

### Prior art

A Python implementation previously existed. **It has been deleted and
is deliberately not a specification.** Do not attempt to reproduce its output, structure, or
behavior, and do not treat it as a correctness benchmark. The requirements above are the spec.
A handful of its non-obvious domain findings are preserved inline in this document because they
are genuinely hard to rediscover; they are marked as such.

---

## Verified environment

Measured directly on the target machine — trust these over assumptions:

| Fact | Value |
|---|---|
| Swift | 6.3.3 (`swiftlang-6.3.3.1.3`) |
| macOS | 26.6.2, arm64 |
| SDK | MacOSX 26.5 |
| `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` as normal user | **works** — unprivileged ICMP is viable |
| `socket(AF_INET, SOCK_RAW, ...)` | EPERM |
| `open("/dev/bpf0")` | EACCES (`crw------- root:wheel`); no ChmodBPF daemon installed |
| `getifaddrs`, route/ARP `sysctl` | work unprivileged |
| `ModelContainer`, `ModelContext` in SDK 26.5 | both `@unchecked Sendable` |
| `Darwin.net.bpf` / `.route` / `.if_arp` modulemaps | present and importable |

**Critical build prerequisite:** `@Model`, `@ModelActor`, `@Attribute` and `@Relationship` are
external macros provided by the `SwiftDataMacros` compiler plugin. That plugin ships **only with
full Xcode** — Command Line Tools provide just `libObservationMacros.dylib` and
`libSwiftMacros.dylib`. Without Xcode installed, **nothing using SwiftData will compile**, and
there is no flag or workaround (hand-writing `PersistentModel` requires underscored SPI). Xcode
was being installed at the time this document was written; verify with:

```
ls /Applications/Xcode.app && \
find /Applications/Xcode.app -name "libSwiftDataMacros.dylib" | head -1
```

**Important nuance about SwiftData and concurrency:** the usual advice that "`ModelContext` isn't
`Sendable`" is stale for this SDK — it is. The real constraint is **executor affinity**: a context
faults objects against a specific queue, so a `PersistentModel` read on one actor and touched from
another faults on the wrong queue. `@ModelActor` remains correct, for that reason.

---

## Package layout

```
~/Dev/InfinityCastle/
  Package.swift               // platforms: [.macOS(.v15)], swiftLanguageModes: [.v6]
  SPEC.md                     // this file
  Sources/
    CBPFShim/                 // C, header-only: ~15 static inline fns exposing BIOC* ioctl values
    ICCore/                   // value types, Deadline, boundedPool, engine protocols, event diffing
    ICNet/                    // getifaddrs, route/ARP sysctl, ICMP, TCP connect, banner probes
    ICDiscovery/              // dns_sd mDNS, SSDP, NetBIOS, NameProvider cascade
    ICPrivileged/             // BPF ARP sweep, SYN scan, PrivilegeBroker
    ICStore/                  // SwiftData @Model entities, @ModelActor HistoryStore
    ICAssembly/               // composition root: selects engines, builds the pipeline
    castle/                   // executable: ArgumentParser + renderers
  Apps/
    InfinityCastle.xcodeproj  // SwiftUI app, links ICAssembly
  Tests/
```

```
CBPFShim ─┐
ICCore ───┼─> ICNet ──┬─> ICDiscovery ─┐
          │           └─> ICPrivileged ┤
          └─> ICStore ─────────────────┴─> ICAssembly ─┬─> castle (CLI)
                                                       └─> InfinityCastle.app
```

`ICCore` owns the engine protocols. **Nothing in the pipeline depends on `ICPrivileged`** — only
`ICAssembly` knows both implementations exist. This keeps all raw-packet code in one auditable
target and lets a future privileged XPC helper link `ICPrivileged` alone.

**Per-target isolation, and this is a real trap:**

```swift
// library targets
.swiftLanguageMode(.v6), .defaultIsolation(nil)
// castle executable and the app
.swiftLanguageMode(.v6), .defaultIsolation(MainActor.self)
```

Swift 6.2's main-actor-by-default is correct for a UI shell and actively harmful in a scanner — it
would silently hop every socket helper onto the main actor. Set it per-target from the start.

`CBPFShim` exists solely because `BIOCSETIF` and friends are function-like macros over
`sizeof(struct ifreq)`, which ClangImporter cannot import. Export them as `static inline` functions
returning `unsigned long`. **Do not wrap `ioctl` itself** — the Darwin overlay already provides a
non-variadic `ioctl(_:_:UnsafeMutableRawPointer)`.

Only external dependency: `swift-argument-parser`.

---

## Concurrency model

**Principle:** anything holding a file descriptor is owned by an actor and never shared. Only
frozen value types cross isolation boundaries.

### Core value types (`ICCore`)

```swift
public struct MACAddress: Hashable, Sendable { let raw: UInt64 }        // 48 bits packed
public struct IPv4Address: Hashable, Sendable, Comparable { let raw: UInt32 }
public struct IPv4Network: Hashable, Sendable { let base: UInt32; let prefix: UInt8 }
```

Packing a MAC into an integer makes normalization a property of the type rather than a parsing
step — macOS `arp` emits unpadded forms like `0:92:35:30:a:1`. It also makes the identity system's
key test trivial: `isLocallyAdministered == (raw >> 40) & 0x02 != 0`.

### The name cascade is a total order, not a procedure

```swift
public enum NameSource: Sendable { case administrative, mdns, ssdp, netbios, dns }   // .priority 0…4

public struct NameCandidate: Sendable, Hashable, Comparable {
    let value: String
    let source: NameSource
    let rank: Int          // mDNS service-type quality rank; 0 for other sources
    let model: String?
}
// Comparable == lexicographic (source.priority, rank) → the entire cascade is `candidates.min()`
```

Priority order is `administrative > mdns > ssdp > netbios > dns`: a name a person deliberately
assigned should beat one a device advertises about itself.

Keep every losing candidate on `HostFacts.allNames`. **The design shows these** ("also known as…"
in the device detail view) — they are the explanation for why a device is named what it is.

### Failures are values

```swift
public struct Degradation: Sendable, Hashable {
    let stage: Stage; let reason: String; let recoverable: Bool
}
```

Never swallow a probe failure. The core value of this tool is explaining *why* a device is
unidentified, and the design surfaces degradations directly in the live-scan view
("mDNS unavailable: Local Network permission denied"). A silent `catch {}` destroys the product's
main feature.

### Deadlines

```swift
public struct Deadline: Sendable {
    let instant: ContinuousClock.Instant
    var remaining: Duration { max(.zero, instant - .now) }
    func clamped(to parent: Deadline) -> Deadline
}
```

`ContinuousClock` deliberately: not `SuspendingClock` (a laptop sleeping mid-scan must expire the
budget, not extend it) and not `Date` (immune to NTP steps). Engines *receive* a deadline and
subdivide it with `clamped(to:)`. No engine reads a global timeout constant.

```swift
public func boundedPool<Item: Sendable, Out: Sendable>(
    over items: [Item], concurrency: Int, deadline: Deadline,
    onProgress: (@Sendable (Int, Int) -> Void)? = nil,
    work: @Sendable @escaping (Item) async -> Out?
) async -> [Item: Out]                // partial on expiry; never throws
```

Sliding-window `withTaskGroup`: prime with `concurrency` children, then `for await` and refill.
A sibling task sleeps to the deadline and calls `cancelAll()`. The non-throwing `-> Out?` shape
encodes that a failed probe is a data point, not an error.

### The invariant everything depends on

> `Task.cancel()` is cooperative. Cancelling a task blocked in `connect()` does **not** unblock it,
> and `withTaskGroup` will not return until the child does.

Therefore **every leaf operation must be non-blocking or carry a kernel timeout**:

- ICMP / UDP: `O_NONBLOCK` fd + `DispatchSourceRead`.
- TCP: `O_NONBLOCK` → `connect` → `EINPROGRESS` → `DispatchSourceWrite` → `getsockopt(SO_ERROR)`.
- **Never `read()` a blocking fd from a Task.** The cooperative pool is core-count-sized; a few
  blocked reads deadlock the scanner rather than slowing it. This is the single most likely way
  this implementation goes wrong.
- **Reverse DNS cannot be interrupted.** `getnameinfo`/`gethostbyaddr` have no cancellation.
  Use `DNSServiceQueryRecord` from `dns_sd` instead — fd-driven and cancellable via
  `DNSServiceRefDeallocate`.

### Resource limit

`RLIMIT_NOFILE` is **256 soft** on macOS. A /24 × 100 ports is ~25,400 probes. Call `setrlimit` to
the hard limit at startup and derive pool concurrency from the actual value
(`min(512, limit/4)`). Otherwise deep scans fail confusingly on day one.

---

## Engines

Two protocols, because privilege changes how discovery and port scanning work and changes nothing
else in the pipeline.

```swift
public protocol DiscoveryEngine: Sendable {
    var kind: EngineKind { get }                   // .unprivileged / .privilegedBPF / .composite
    var capabilities: EngineCapabilities { get }   // OptionSet: .arpSweep .icmpSweep .synScan .osFingerprint
    func discover(network: IPv4Network, interface: NetworkInterface,
                  deadline: Deadline, progress: ProgressSink) async -> DiscoveryResult
}

public protocol PortScanEngine: Sendable {
    var kind: EngineKind { get }
    var capabilities: EngineCapabilities { get }
    func scan(targets: [IPv4Address], ports: PortSpec, perHostDeadline: Duration,
              deadline: Deadline, progress: ProgressSink) async -> PortScanResult
}
```

Four deliberate shape decisions:

1. **Non-throwing, returning an envelope** — `DiscoveryResult { hosts, degradations,
   usedCapabilities }`. A deadline hit is a *normal return* at every level. `throws` is the wrong
   shape because a thrown error discards partial work, and partial results are requirement 9.
2. **`capabilities` as an OptionSet**, so the UI can say "OS fingerprint unavailable — requires the
   privileged engine" without knowing which engine is installed.
3. **`Deadline` passed in, never owned.** Makes the budget tree explicit and testable.
4. **`ProgressSink` as a Sendable closure box**, not a protocol existential:
   `struct ProgressSink: Sendable { let emit: @Sendable (ProgressEvent) -> Void }`. Route it into
   an `AsyncStream<ProgressEvent>` that the `@MainActor` view model consumes — this is what drives
   the live-scan screen.

### Implementations

- **`UnprivilegedDiscoveryEngine`** (default): ICMP datagram sweep + ARP cache via
  `sysctl(CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO)` + TCP-ping to 80/443/22 for
  hosts that ignore ICMP. Capture TTL from replies; it feeds OS hinting for free.
- **`BPFDiscoveryEngine`**: layer-2 ARP sweep over `/dev/bpf*`. Finds hosts that answer nothing else.
- **`CompositeDiscoveryEngine([bpf, unprivileged])`**: merges results by IP. **Running as root must
  never find fewer hosts than running unprivileged** — an either/or branch would cause exactly
  that by losing ICMP-only hosts. Composition is the reason this protocol exists.
- **`ConnectScanEngine`**: non-blocking TCP connect via TaskGroup. `ECONNREFUSED` distinguishes
  closed from filtered (timeout).
- **`SYNScanEngine`**: over BPF when privileged, followed by connect+banner on the ports SYN found
  open — banners require a real connection regardless.
- **`BannerProbe`**: SSH version string, HTTP `Server:` header, SMB, and TLS certificate CN/SAN via
  `NWConnection` + `NWProtocolTLS` + `sec_protocol_options_set_verify_block`. Combine with TTL
  (64 → Linux/macOS/iOS, 128 → Windows, 255 → network gear) and MAC OUI into an `OSHint`.

Note the identity philosophy: on a home LAN, fused identity signals (mDNS model strings, OUI,
SSDP descriptions, TLS subjects) beat TCP/IP OS fingerprinting. `AppleTV5,3` from a Bonjour TXT
record is more precise than any fingerprint guess. Build fusion first; treat OS hinting as
supplementary.

---

## mDNS — a primary source, not a fallback

Use **`dns_sd` directly.** `NWBrowser` has a nicer Sendable surface but returns **no IP address**,
and the entire cascade keys on IP; recovering addresses would require an `NWConnection` per
instance. `DNSServiceGetAddrInfo` is one query.

Implementation shape:

1. `DNSServiceCreateConnection` **once**, then `DNSServiceBrowse` per service type with
   `kDNSServiceFlagsShareConnection` — one socket for all types, not one per type.
2. `DNSServiceSetDispatchQueue(shared, queue)` hands callback delivery to GCD; no manual
   `DispatchSourceRead` + `DNSServiceProcessResult` loop is needed.
3. The C callback is `@convention(c)` with a `void *context`, so Swift can only supply a
   non-capturing closure — pass an `Unmanaged.passRetained(session).toOpaque()` box.
4. Bridge to `AsyncStream`. In `continuation.onTermination`, call `DNSServiceRefDeallocate` and
   release the box. This fires on both normal finish and consumer cancellation, which is exactly
   the required semantics.
5. Cascade Browse → Resolve → GetAddrInfo on the shared connection; an actor accumulates partial
   sightings into `MDNSSighting(ip, serviceType, instanceName, txt, hostname)`.

### Domain knowledge worth preserving (from prior art — hard to rediscover)

- **Service types carry a quality rank.** The same device advertises
  `"Sala de estar principal"` on `_companion-link._tcp` and
  `"70-35-60-63.1 Sala de estar principal"` on `_sleep-proxy._udp`. Rank types by name cleanliness
  and let the best-ranked win. Roughly 17 types are worth browsing, including
  `_googlecast._tcp` (cleanest — its TXT `fn` key is a user-set friendly name),
  `_companion-link._tcp`, `_airplay._tcp`, `_homekit._tcp`, `_device-info._tcp`,
  `_spotify-connect._tcp`, `_sonos._tcp`, `_esphomelib._tcp`, `_androidtvremote2._tcp`,
  `_workstation._tcp`, `_smb._tcp`, `_ssh._tcp`, `_ipp._tcp`, `_printer._tcp`, `_hue._tcp`,
  `_raop._tcp`, `_sleep-proxy._udp`.
- **Model lives under TXT keys `am`, `model`, `rpMd`, `ty`, `device`** — first non-empty wins.
  **Never `md`**: on `_raop` that key is the supported-metadata list (`"0,1,2"`), not a model.
  Put this in a code comment; it is a silent data-corruption trap.
- **Instance names need cleaning:** strip a `HEXMAC@` prefix (`_raop`), a sleep-proxy
  `xx-xx-xx-xx.N ` prefix, and a trailing ` [aa:bb:cc:dd:ee:ff]` (avahi `_workstation`).
- **Loopback remap:** the local machine resolves itself to `127.0.0.1` over mDNS. Remap to the
  machine's primary outbound address.

### SSDP

UDP M-SEARCH to `239.255.255.250:1900`, then fetch each responder's `LOCATION` URL and parse
`<friendlyName>` and `<modelName>`. Catches things that ignore Bonjour: TVs, printers, consoles,
NAS boxes.

**Bind to the selected interface's address, not `INADDR_ANY`, and set `IP_MULTICAST_IF`** —
otherwise M-SEARCH leaks out a VPN tunnel on a multi-homed machine. Split the budget roughly 60%
listening / 40% fetching descriptions.

### NetBIOS

A single NBSTAT node-status query on UDP/137 is the whole protocol — no library required. Query
only hosts still unnamed after mDNS and SSDP.

---

## SwiftData store

> **Superseded in part, 2026-09-11.** The store is the append-only log described under the
> requirements, on every platform; the SwiftData conformance was withdrawn when nothing shipped
> it. What is below is still the design that matters and is still authoritative: the entities are
> what a store has to be able to reconstruct, the identity rules and the anti-collapse guard are
> implemented as written — in `HistoryLedger`, above the store rather than inside it, so that a
> second conformance cannot carry a second copy of them — and the retention tiers, the location
> rules and the `sudo` landmine all stand. Read `@Model` and `@ModelActor` below as "the store",
> not as SwiftData.

### Entities

```
Host                  id, firstSeen, lastSeen, displayName, displayModel, vendor, confidence
                      identifiers: [HostIdentifier], observations: [HostObservation]
HostIdentifier        kind, value, weight, firstSeen, lastSeen, isRandomized, host
                      #Unique(kind, value)
ScanRun               id, startedAt, finishedAt, network, interface, privileged, engineKind,
                      hostCount, degradations, presenceBitmap
HostObservation       run, host, ip, mac, name, nameSource, nameRank, model, vendor, reverseDNS,
                      sources, rttMillis, ttl, ports: [PortObservation]
PortObservation       observation, port, proto, state, service, product, version, banner, tlsSubject
ScanEvent             id, at, run, host?, kind, severity, summary, details
```

`ScanEvent.kind` covers at minimum: `hostAppeared`, `hostDisappeared`, `ipMoved`, `portOpened`,
`portClosed`, `nameChanged`, `vendorChanged`, `hostsMerged`. These are what the Activity timeline
renders.

### Identity — the hardest problem in this system

Private Wi-Fi addresses rotate, and on the target network this is the **common case, not the edge
case**: several hosts present randomized MACs. Keying on MAC would create a new "host" on every
rotation and make the history worthless.

**MAC is never the primary key.** Identity is a weighted join table:

```swift
public enum HostKey: Hashable, Sendable {
    case universalMAC(MACAddress)            // 100 — globally administered, genuinely stable
    case mdnsInstance(String)                //  60 — normalized Bonjour instance name
    case dhcpHostname(String)                //  40
    case randomizedMAC(MACAddress)           //  30 — locally administered, rotates
    case ipLease(IPv4Network, IPv4Address)   //  10 — last resort
}
```

`mdnsInstance` (60) deliberately outranks `randomizedMAC` (30): an iPhone using private addressing
that advertises a stable Bonjour name must remain **one** `Host` across rotations, and that
requires the name to beat the MAC.

Resolution, executed inside the store actor:

1. Compute all candidate keys from `HostFacts`, sort by weight descending.
2. Look up `HostIdentifier` rows; **first hit wins**.
3. If two candidates resolve to **different** hosts → **merge**: keep the earlier `firstSeen`,
   repoint the loser's identifiers and observations, delete it, emit `.hostsMerged`. This is how a
   phone first seen only by rotating MAC is absorbed once mDNS names it. **Merges must
   be events** — otherwise the history becomes inexplicable to the user.
4. No match → new `Host`, attach all candidate identifiers.
5. Always upsert every candidate key with a fresh `lastSeen`, so identity *accumulates* over time.

**Anti-collapse guard.** A wrong merge is far worse than a missed one, because a missed
merge is recoverable — a later observation carrying a shared key joins the two records —
and un-merging is not: the two histories have already been written into each other and
nothing records which half was whose. Accept an `ipLease` match **only if** that host was not already
observed in the current run under a different IP. Otherwise create a new host and let a later
mDNS observation merge them. Bias toward splitting.

`ipMoved` falls out naturally: resolve by MAC, observe an IP differing from the last observation.

### Store concurrency

```swift
@ModelActor
public actor HistoryStore {
    func beginScan(_ meta: ScanMeta) async throws -> ScanRunID
    func record(_ hosts: [HostFacts], in run: ScanRunID) async throws
    func finishScan(_ run: ScanRunID, outcome: ScanOutcome) async throws -> [ScanEvent]
    func prune(_ policy: RetentionPolicy) async throws -> PruneStats
    func recentEvents(limit: Int) async throws -> [ScanEvent]
}
```

**Structs in, structs out.** A `PersistentModel` must never cross an isolation boundary — not
because it isn't `Sendable` (in this SDK it is) but because faulting is executor-bound.
`ScanRunID` is a Sendable UUID wrapper; it and `PersistentIdentifier` are the only handles that
travel.

`finishScan` returns the derived events because diffing requires the previous run, which is
store-resident. But keep the diff itself a **pure free function in `ICCore`**:

```swift
public func deriveEvents(previous: [HostFacts], current: [HostFacts],
                         at: Date, run: ScanRunID) -> [ScanEvent]
```

This is the logic most likely to be subtly wrong, and as a free function it is testable with zero
I/O and zero database.

One transaction per `record(_:)` batch, not per host. Disable autosave; save explicitly.

### Retention

A 60-second watch interval is 1,440 runs/day; 30 hosts × 20 ports ≈ **865,000 port rows/day**.
Three tiers, run after each `finishScan`:

1. **Raw** — full observations for the last N runs (default 200) or 24h, whichever is larger.
2. **Change-only** — beyond that, delete observations identical to their predecessor for the same
   host. Presence is preserved by `ScanRun.presenceBitmap`, one bit per known host. "Was host X up
   at run Y" is the actual watch-mode query and it compresses to bits. `ScanRun` rows are tiny and
   kept forever.
3. **Events** — pruned by age only (default 365 days). **Events are the durable record; the
   observation tables are a cache of them.**

Checkpoint the store periodically. A database deleting ~800k rows/day without reclaiming pages
grows on disk while shrinking logically.

### Location

`~/Library/Application Support/dev.jc.InfinityCastle/history.store`, overridable via `--store` or
`IC_STORE_PATH`; `--store none` for in-memory.

- **Not** an App Group container — that needs a provisioning profile, and Phase 1 must not depend
  on app signing infrastructure.
- **Decide and hold:** the app ships **unsandboxed, Developer ID** — not Mac App Store. The App
  Sandbox has no entitlement covering raw sockets or BPF, and sandboxed multicast requires
  `com.apple.developer.networking.multicast`, a managed entitlement requiring Apple approval. A
  network scanner is not an App Store app. If sandboxing is ever forced, this design breaks and
  requires XPC to a helper.
- **Landmine:** under `sudo`, resolve the path from `SUDO_USER`'s home, **not** root's. Otherwise
  privileged runs write to `/var/root/Library/...` and unprivileged runs see an empty database.
  Handle this on day one.

---

## Privilege model

**Mechanism: run under `sudo`, open BPF at startup, then irrevocably drop privileges.**

```
if geteuid() == 0 {
    open /dev/bpfN, configure it, retain the fd
    setgid(SUDO_GID ?? getgid())     // gid first
    setuid(SUDO_UID ?? getuid())     // setuid, not seteuid — irrevocable
}
```

File descriptors survive the drop, shrinking the root window from *the entire scan — including a
database engine writing to disk* — down to a handful of
startup syscalls.

Rejected for now, with reasons: a **setuid helper** requires `chown root` + `chmod u+s` after every
build and macOS increasingly distrusts setuid; **`SMAppService`/`SMJobBless`** requires Developer
ID signing and an app bundle, and is the correct answer *later*, once the app exists.

### The no-subprocess rule is structural

**Zhen never spawns a process.** No `Foundation.Process`, no `posix_spawn`, no `sudo`
invocation anywhere in the codebase.

`--privileged` means *"I expect to already be root."* If `geteuid() != 0`, print
`re-run: sudo castle scan --privileged` and exit non-zero. **Never prompt**, so a hidden password
prompt can never block. (The prior Python implementation shipped exactly that bug — `sudo`'s
prompt captured into a pipe, blocking forever.)

Enforce it mechanically: **add a test that fails if `Foundation.Process` or `posix_spawn` appears
in the built modules.** "No subprocesses" is the property that justifies this entire project; make
it a checked invariant rather than a promise.

If BPF fails even under root — `/dev/bpf*` nodes are exclusive-open, and Wireshark, `tcpdump`, a
VPN client or Little Snitch may hold them — scan `bpf0..N` for a free node, then **degrade to the
unprivileged engine and record a `Degradation`**. Never hard-fail.

```swift
public protocol PrivilegeBroker: Sendable {
    var isPrivileged: Bool { get }
    func acquireBPF(interface: String, bufferSize: Int) async throws -> BPFHandle
}
struct SudoPrivilegeBroker: PrivilegeBroker      // now
struct DeniedPrivilegeBroker: PrivilegeBroker    // always throws .notPrivileged
// later: struct XPCPrivilegeBroker: PrivilegeBroker
```

---

## CLI surface (`castle`)

| Command | Purpose |
|---|---|
| `castle scan` | Discovery + naming. `--deep` adds ports; `--privileged` selects BPF engines. |
| `castle watch --interval 5m` | Repeat scans, derive events, prune. |
| `castle hosts` | Every host ever seen, with last-seen and identity confidence. |
| `castle history <host>` | Timeline for one host: IP moves, name changes, port changes. |
| `castle events [--since 24h]` | The derived event log. |
| `castle export` | Full NDJSON dump of the store. |

Global flags: `--json`, `--quiet`, `--cidr`, `--iface`, `--store`, `--retain-days`.
JSON goes to **stdout**, progress to **stderr**, and every JSON document carries a
`schema_version` key.

**Watch scheduling:** compute tick times from a fixed origin (`origin + n*interval`) on
`ContinuousClock`, **not** `sleep(interval)` after each run — a 90s scan on a 60s interval would
otherwise drift to 150s spacing. Skip missed ticks and log the skip.

**Signals:** install `DispatchSourceSignal` (not `signal()`) for SIGINT/SIGTERM. The first signal
unwinds cleanly, commits the partial run and derives its events; the second hard-exits. Otherwise
Ctrl-C at hour three of a watch discards that tick's work.

---

## Building the GUI from the design canvas

The design canvas defines five artboards. Implement each as a SwiftUI view, treating the canvas as
authoritative for layout, spacing, type scale, color and state presentation.

| Artboard | View | Data source |
|---|---|---|
| **Devices** (main window) | `DeviceListView` + sidebar navigation | `HistoryStore.hosts()` |
| **Device detail** | `DeviceDetailView` | one `Host` + its observations, ports, and `allNames` |
| **Activity timeline** | `ActivityView` | `ScanEvent` records, filterable by kind and time |
| **Live scan** | `ScanProgressView` | `AsyncStream<ProgressEvent>` from `ProgressSink`, plus `[Degradation]` |
| **Settings** | `SettingsView` | scan defaults, `RetentionPolicy`, privileged toggle |

Implementation notes that the design depends on:

- **The unidentified device is the acceptance case.** Several hosts have a randomized MAC and no
  name, vendor or model. The design handles this deliberately — an unknown device is a normal
  state, not an error state. Do not render it as a failure, and do not let empty fields collapse
  the layout.
- **Identity confidence must be visible** without shouting. `Host.confidence` derives from the
  weight of its strongest `HostIdentifier`.
- **Degradations surface in the UI**, in the live-scan view specifically. Wire `Degradation`
  through to the view model rather than logging it.
- **"Known by"** in device detail renders `HostFacts.allNames` — the competing candidates and which
  source won. Do not discard losing candidates in the pipeline.
- **Live updates:** the app links `ICAssembly` directly and consumes `AsyncStream`. It does not
  shell out to `castle` and does not parse JSON.
- The view models are `@MainActor` and `@Observable`; the scanning stack is not. Keep the boundary
  crisp — main-actor isolation must not leak into `ICNet` or `ICDiscovery`.

---

## Build order

1. **Verify Xcode**, then `Package.swift` and `ICCore` primitives — `Deadline`, `boundedPool`,
   `MACAddress`, `IPv4Address`, engine protocols, `Degradation`.
2. **`ICStore` early, not late.** The schema bounds what the UI can show, and identity is the
   hardest problem here. Validate `@ModelActor` headless in a throwaway executable *before*
   building dependents — there is no fallback store by design.
3. **`ICNet`** — interfaces, ARP cache, ICMP sweep, TCP connect. Milestone: a correct device list.
4. **`ICDiscovery`** — mDNS first (it carries most of the naming value), then SSDP, NetBIOS,
   reverse DNS, and the `NameProvider` cascade.
5. **Deep scan** — connect scan and banner probes.
6. **`ICAssembly` + `castle`** — pipeline, `EventDeriver`, watch mode, pruning.
7. **SwiftUI app** against the design canvas.
8. **`ICPrivileged` last** — BPF and SYN scan are the optional path and must block nothing.

---

## Verification

Verify against the requirements. There is no prior implementation to match.

- **Unit tests on pure logic**, where the subtlety lives:
  - `NameCandidate` ordering across all five sources, including mDNS rank ties.
  - `IdentityResolver` across a simulated private-MAC rotation — one device, four MACs, must
    remain one `Host`.
  - The anti-collapse guard — two devices swapping DHCP leases must **not** merge.
  - `deriveEvents` against handcrafted before/after sets.
  - Instance-name cleaning against real Bonjour strings, e.g.
    `"5E0A1B2C3D4E@Mac Studio de Luis._raop._tcp.local."`,
    `"70-35-60-63.1 Sala de estar principal"`, `"host [aa:bb:cc:dd:ee:ff]"`.
- **No-subprocess invariant** — a test failing if `Foundation.Process`/`posix_spawn` appears in the
  built modules.
- **Deadline invariant** — run every stage against an unreachable `--cidr 10.99.99.0/24`. Each must
  return within budget, yield partial results, and populate `degradations`. Nothing hangs.
- **Discovery correctness** — on the live network, cross-check against an independent list of the
  subnet's clients, such as the router's own. Every client it knows should appear.
- **Port scan correctness** — verify against a host with known open ports.
- **Identity over time** — `castle watch --interval 30s` for an hour; force a device off and back
  on. Confirm `hostAppeared`/`hostDisappeared` land, a private-MAC device stays a single `Host`
  across rotation, and the store stays flat in size under pruning.
- **Privilege parity** — `castle scan` versus `sudo castle scan --privileged` must yield a
  superset, never fewer hosts, and both must use the same store path.
- **GUI** — against the design canvas, with the unidentified-device case as the acceptance bar.

---

## Risks, ranked

1. **TCC Local Network permission — highest impact, and silent.** On macOS 26, ICMP-to-LAN, mDNS,
   SSDP multicast and NetBIOS all require it, and **denial returns zero results rather than an
   error**. A bare SPM executable has no bundle, so the grant attaches to Terminal and never
   appears under the tool's own name in System Settings. Mitigations: embed an Info.plist with
   `NSLocalNetworkUsageDescription` and `NSBonjourServices` (listing every browsed type) via
   `-Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist`; and detect it actively — if the
   ICMP sweep finds nothing while the ARP cache is non-empty, emit a `Degradation` naming TCC. The
   app bundle handles this correctly by nature, which is a further argument for building the GUI
   early.
2. **SwiftData headless in a CLI.** `@ModelActor` outside an app bundle is less-travelled ground.
   Validate at step 2, before the schema has dependents. There is no fallback store by design, so
   settle this early. **Retired 2026-09-09**, and by a ruling rather than by a proof: the CLI gets
   the portable log and never sees SwiftData, so the bundle-less case is not one this project
   needs. What was validated is the case that remains — `@ModelActor` builds under SwiftPM and
   runs headless under `swift test`, on disk, across a reopen.
3. **Cooperative-pool starvation** from any accidentally-blocking fd read (the concurrency
   model).
4. **BPF exclusive-open contention** with Wireshark, VPN clients or Little Snitch.
5. **`RLIMIT_NOFILE` = 256 soft** — raise at startup or deep scans fail confusingly.
6. **`sudo` store path** resolving to `/var/root` (the SwiftData store).
7. **Variable-length C structs.** `sockaddr_dl` must be parsed with `withUnsafeBytes` and explicit
   offsets, never `bindMemory` — otherwise alignment UB.
