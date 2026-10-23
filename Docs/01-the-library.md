# 01 — the library (`zhen/Sources`)

> **Amended 2026-09-26.** The two packages this document describes are now one, at
> `zhen/`, and the app's sources moved into its own Xcode project at `zhen-app/`. The
> manifest excerpts below are kept because the reasoning attached to them is still the
> reasoning in force — the isolation settings, the memory-safety exemptions, the reason
> the engines live beside the model. **`zhen/Package.swift` is the authority**; anything
> here that contradicts it is history, not instruction. See `Docs/DIRECTION.md` for why.


**Run this first.** Nothing else in the repo can be written until the types in this
document exist, because both consumers depend on them and neither may define its own.

---

## What this package is

`zhen-core` is a **definition package**: the data model, the time and
concurrency primitives, and the protocol surface that describes scanning. It
contains no user interface, no command parsing, and no application lifecycle.

```
                     zhen (the package)
                    /              \
        zhen-app              zhen (the executable)
     (Apple app, macOS first)   (portable: macOS, Linux, later Windows)
```

Both consumers depend on core. **Core depends on nothing but the standard library
and Foundation.** Neither consumer may add a type the other would also need — if
both want it, it belongs here.

> Naming note: the Apple-side package is called `zhen-app` per the agreed
> diagram, but it ships macOS first. The name keeps room for iOS later; nothing in
> core assumes either platform. The engine now builds for iPadOS, without the
> privileged half; see `IPADOS.md`.

The portability rule is load-bearing and it constrains the design more than
anything else here: **the public API of core must compile on Linux.** Darwin-only
machinery — `dns_sd`, `kqueue`, BPF — is reachable only through protocols declared
here and implemented in platform-specific targets. A `#if canImport(Darwin)` inside
a public type's body is a design failure; a protocol with two conformances is not.

### Non-goals for this package

No sockets are opened here. No packets are parsed here. Core declares *what a probe
result is*, not how to obtain one. The engine implementations live in the platform
targets and are injected.

---

## What already exists

`zhen` is already migrated and in place: `MACAddress`,
`IPv4Address`, `IPv4Network`, `Deadline`, `boundedPool`, `NameSource`,
`NameCandidate`, `Degradation`, `HostFacts` and the engine protocols, with 19 tests,
all under the `ZhenCore` module name.

Do not rewrite it. It already encodes decisions that cost thought — packed address
types so normalization is a property of the type, the name cascade expressed as a
total order so resolution is `candidates.min()`, and non-throwing envelopes so a
deadline hit is a normal return. Build the output model alongside it.

Your first act is to confirm it still builds:

```bash
cd zhen && swift build && swift test
```

## Package manifest

```swift
// swift-tools-version: 6.2
import PackageDescription

let coreSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    // Non-isolated by default. Swift 6.2's main-actor-by-default is correct for a
    // UI shell and actively harmful here: it would silently hop every probe helper
    // onto the main actor and serialize the scanner behind the UI.
    .defaultIsolation(nil),
    // Surfaces every unsafe construct as a compiler diagnostic. Core should have
    // none; the platform targets will, and each one must be justified in a comment.
    .strictMemorySafety(),
]

let package = Package(
    name: "zhen-core",
    platforms: [.macOS(.v15), .iOS(.v17)],
    products: [.library(name: "ZhenCore", targets: ["ZhenCore"])],
    targets: [
        .target(name: "ZhenCore", swiftSettings: coreSettings),
        .testTarget(name: "ZhenCoreTests", dependencies: ["ZhenCore"],
                    swiftSettings: coreSettings),
    ]
)
```

Module layout:

```
Sources/ZhenCore/
  Model/        the output types — the whole output model
  Time/         Deadline, MonotonicInstant, Timing
  Concurrency/  boundedPool, ProbeStream, ProgressSink
  Engines/      the protocol surface consumers program against
  Platform/     protocol declarations for what only a platform can do
```

---

## The output model

These types are the product. The CLI serializes them; the app renders them; a third
consumer we haven't written yet will read them from a file. Design them as a wire
format that happens to be Swift, not as an internal convenience.

**Rules that apply to every type in `Model/`:**

- `struct`, `Sendable`, `Hashable`, `Codable`. No classes, no reference semantics.
- Explicit `CodingKeys` on everything. A field rename must never silently change
  the JSON. Renaming a Swift property is a refactor; renaming a JSON key is a
  breaking change, and the compiler should be the thing that tells you so.
- **No `Date` in the model.** `Date` is a `Double` since 2001 and encodes with
  platform-dependent precision. Use `Timestamp`, an `Int64` of milliseconds since
  the Unix epoch, and convert at the edges. Measurement uses `ContinuousClock`,
  which is monotonic and immune to NTP steps; wall-clock stamps are for display
  only and the two must never be mixed.
- Optionality means *not observed*, never *zero*. A host with no RTT is
  `rttMillis == nil`, never `0`. The unidentified device is the acceptance case for
  this whole product and empty fields must survive the round trip intact.

### Envelope

```swift
public struct ScanReport: Sendable, Hashable, Codable {
    /// Bumped on any breaking change to the shapes below. Every consumer checks it
    /// before decoding and refuses a version it does not know.
    public static let schemaVersion = 1

    public var schema: Int = Self.schemaVersion
    public var run: ScanRun
    public var devices: [Device]
    public var degradations: [Degradation]
}

public struct ScanRun: Sendable, Hashable, Codable {
    public var id: UUID
    public var startedAt: Timestamp
    public var finishedAt: Timestamp?
    public var target: IPv4Network
    public var interface: String
    public var engine: EngineDescriptor
    public var outcome: Outcome        // .complete, .deadlineExpired, .cancelled
    public var timing: Timing          // wall time per stage, probes sent, replies seen
}
```

`Outcome.deadlineExpired` is a **success** value. It means the budget was spent and
the results are partial, which is normal operation, not failure. Nothing in the API
should let a consumer mistake it for an error.

### Device

```swift
public struct Device: Sendable, Hashable, Codable {
    public var ip: IPv4Address
    public var mac: MACAddress?
    public var names: [NameCandidate]     // every candidate, winners and losers
    public var vendor: String?            // OUI-derived; nil for a randomized MAC
    public var identification: Identification   // what a person reads: how well we know
                                               // WHAT this is
    public var identityStability: Stability    // what an engineer reads: how stable the
                                               // join key is, from the strongest identifier
    public var ttl: UInt8?                // 64 unix-like, 128 Windows, 255 network gear
    public var rtt: RTTSample?
    public var ports: [PortObservation]
    public var firstSeen: Timestamp
    public var lastSeen: Timestamp
}
```

`names` keeps the losing candidates deliberately. Explaining *why* a device is
named what it is, is the feature; discarding the alternatives destroys it.

**Two confidences, and they are not the same number.** This looks like duplication
and isn't — conflating them is the mistake.

`identification` answers *how well do we know what this thing is*: do we have a
name, a model, a vendor, an OS hint, and how many independent sources agree. It is
`.identified`, `.partial` or `.minimal`, it is what the device list shows next to
every row, and it is the only one an everyday user ever sees. A MacBook that
advertises a clean Bonjour name is **identified**, even though its MAC rotates
every few weeks. A router we could only name from its model string is **partial**,
even though its hardware MAC never changes.

`identityStability` answers a different question — *how likely is this record to
fragment or to merge wrongly* — and derives from the weight of the strongest
`HostIdentifier`: a universal MAC is strong, an mDNS instance is moderate, a
randomized MAC is weak, an IP lease is a last resort. It is the number that
explains why the identity history looks the way it does, and it belongs one level
in: the device detail's identity card, and the CLI's JSON. Never in the list.

Compute both, encode both, and let the surface decide which one it is asking for.


### Ports and services

```swift
public struct PortObservation: Sendable, Hashable, Codable {
    public var port: UInt16
    public var proto: TransportProtocol   // .tcp, .udp
    public var state: PortState           // .open, .closed, .filtered
    public var service: ServiceIdentity?  // from a banner, never from a port-number table alone
    public var rtt: RTTSample?
}
```

`.closed` is a positive result — a RST arrived — and is strictly more informative
than `.filtered`, which is silence. Collapsing them, as a naive scanner does, throws
away the only signal that distinguishes a live host behind a firewall from a dead
address.

### Timing

Carry it in the model rather than logging it. A scanner whose selling point is speed
must be able to prove it, and the numbers belong in the machine-readable output so a
regression is a diff, not a feeling.

```swift
public struct Timing: Sendable, Hashable, Codable {
    public var stages: [StageTiming]      // name, elapsedMillis, probesSent, repliesSeen
    public var probesSent: Int
    public var repliesSeen: Int
    public var peakConcurrency: Int
    public var effectiveProbesPerSecond: Double
}
```

---

## The async contracts

Every long-running operation in this system is an `AsyncSequence`. There are no
completion handlers, no delegates, and no callbacks in the public API — those exist
only inside the platform targets where C interop forces them, and they are bridged
before they escape.

```swift
public protocol HostDiscovery: Sendable {
    var descriptor: EngineDescriptor { get }

    /// Terminal form: everything, once, when it is done or the budget expires.
    func discover(_ target: ScanTarget, deadline: Deadline) async -> DiscoveryResult

    /// Streaming form: hosts as they answer, which is what a live UI binds to and
    /// what makes the CLI feel instant. Never fails; degradations arrive as events.
    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent>
}
```

Two entry points rather than one because they have genuinely different consumers,
and expressing the terminal form as "collect the stream" is the wrong default: the
terminal form can batch aggressively and skip per-event allocation, which the
streaming form cannot.

**Backpressure is a decision, not an accident.** `AsyncStream` with an unbounded
buffer will happily accumulate 65,000 events while a SwiftUI list renders 30 of
them. Every stream in this system declares its policy explicitly:

```swift
let (stream, continuation) = AsyncStream<ProbeEvent>.makeStream(
    bufferingPolicy: .bufferingNewest(4096)
)
continuation.onTermination = { _ in socket.close() }   // fires on cancel too
```

`.bufferingNewest` is right for progress events: a UI that fell behind wants the
current state, not a replay of history. Results that must not be dropped travel in
the terminal envelope, never in the progress stream. Keeping those two in separate
channels is what lets the progress channel be lossy without lying.

---

## Swift 6 features this package is built on

Not a survey — these are load-bearing, and reviewers should reject code that
reimplements them by hand.

**`Span` and `RawSpan`.** Safe, borrowed, zero-copy views over memory. Every packet
parser takes a `RawSpan` and never an `UnsafeRawBufferPointer`, so bounds are
checked and no pointer escapes its buffer's lifetime. This is the language finally
giving us the thing the Cambridge/UCL specialization work says matters most —
passing a received buffer through the layers without copying it — with none of the
usual memory-safety cost. Use `loadUnaligned(fromByteOffset:as:)`; wire data is not
aligned and `bindMemory` on it is undefined behaviour, not merely unwise.

**`InlineArray<N, Element>`.** Fixed-size headers with no heap allocation. An ICMP
echo header is 8 bytes and known at compile time; allocating an `[UInt8]` per probe
across 65,000 probes is 65,000 pointless mallocs.

**`Synchronization.Atomic` and `Mutex`.** Counters shared across the probe fan-out —
probes sent, replies seen, peak concurrency — are `Atomic<Int>` with
`.relaxed` ordering. They are statistics; they do not order anything, and paying for
sequential consistency on a counter incremented a million times is measurable. This
follows the specialization paper's fifth principle directly: avoid data-structure
locking and cache-line contention on the fan-out path.

**Noncopyable types for descriptor ownership.**

```swift
public struct FileDescriptor: ~Copyable, Sendable {
    private let raw: Int32
    public consuming func close() { Darwin.close(raw) }
    deinit { Darwin.close(raw) }
}
```

A file descriptor is a resource with exactly one owner. `~Copyable` makes
double-close and use-after-close compile errors rather than production mysteries,
which matters enormously when the fd count is in the thousands and a leak exhausts
the process limit rather than merely wasting memory.

**`DiscardingTaskGroup`.** For fan-out where results are delivered through a
continuation rather than returned, `withDiscardingTaskGroup` does not accumulate
child results. A regular `withTaskGroup` over 65,000 probes retains every child's
result until the group retires; the discarding variant is what keeps memory flat.

**Typed throws.** `func bind() throws(SocketError)` where a real error exists. Most
of this API does not throw at all — a failed probe is a value — but where a genuine
error escapes, the type says which, and the caller's `catch` is exhaustive.

**Custom executors.** The socket actors get a `SerialExecutor` backed by a dedicated
`DispatchQueue`, not the cooperative pool. Reasoning in the executor-affinity note.

---

## What must be done by hand, why, and how to contain it

Each of these is a place where the platform does not meet Swift halfway. The rule is
the same every time: **do the unsafe thing once, in one file, behind a Sendable
value type, and let nothing above it know.**

### The cooperative pool must never block

`Task.cancel()` is cooperative. A task blocked in `connect()` or `read()` does not
unblock when cancelled, and `withTaskGroup` will not return until the child returns.
The Swift cooperative pool is sized to the core count — a handful of blocked
descriptors deadlocks the scanner outright rather than slowing it.

*Containment:* every descriptor is `O_NONBLOCK`, always, with readiness delivered by
a `DispatchSource` or a kqueue thread. No exceptions, and a code review that sees a
blocking read on a socket fd rejects the change. This is the single most likely way
this implementation goes wrong.

### The ICMP checksum

macOS gives an unprivileged process `SOCK_DGRAM`/`IPPROTO_ICMP`, which is the reason
host discovery needs no root at all — a genuine advantage over nmap on this
platform. But the kernel rewrites only the identifier field; **the application
computes the checksum.**

The algorithm is the one's-complement sum of 16-bit words with carries folded back
in. Done naively it is a per-probe cost paid 65,000 times, so accumulate in a
`UInt32`, fold once at the end, and handle the trailing odd byte explicitly:

```swift
func checksum(_ bytes: RawSpan) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < bytes.byteCount {
        sum &+= UInt32(bytes.unsafeLoadUnaligned(fromByteOffset: i, as: UInt16.self))
        i += 2
    }
    if i < bytes.byteCount { sum &+= UInt32(bytes[i]) }   // odd tail, low byte
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
    return ~UInt16(truncatingIfNeeded: sum)
}
```

*Bypass considered and rejected:* letting the kernel do it by using a raw socket.
That requires root, which forfeits the unprivileged default that makes this tool
pleasant. Computing sixteen-bit sums is cheaper than asking a user for a password.

### `ioctl` request macros are unimportable

`BIOCSETIF` and friends are function-like C macros over `sizeof(struct ifreq)`.
ClangImporter cannot import them, so they are simply invisible to Swift.

*Containment:* a header-only C target exposing about fifteen `static inline`
functions that return the computed `unsigned long`. Do **not** wrap `ioctl` itself —
the Darwin overlay already provides a non-variadic
`ioctl(_:_:UnsafeMutableRawPointer)`, and wrapping it again just adds a layer that
can disagree with the platform.

### Variable-length C structures

`sockaddr_dl` inside a routing-socket message is variable length and unaligned.
`bindMemory` on it is alignment undefined behaviour that will work on your machine
and crash on someone else's.

*Containment:* parse with `RawSpan` and explicit byte offsets, using
`loadUnaligned`. One parser, one file, exhaustively tested against captured bytes
committed as fixtures — the ARP table walk and the interface enumeration both go
through it.

### C callbacks cannot capture

`dns_sd` callbacks are `@convention(c)` with a `void *context`, so Swift can supply
only a non-capturing closure. There is no way around it.

*Containment:* box the session with `Unmanaged.passRetained(...).toOpaque()`, recover
it in the callback, and bridge to an `AsyncStream`. Release the box in
`continuation.onTermination` — which fires on both normal completion and consumer
cancellation, giving exactly the lifetime semantics required. Everything above this
file sees an `AsyncSequence` and knows nothing about C.

### Reverse DNS cannot be cancelled

`getnameinfo` and `gethostbyaddr` have no cancellation and no timeout. A task
blocked in one of them ignores its deadline completely.

*Containment:* `DNSServiceQueryRecord` for PTR lookups — fd-driven, cancellable by
`DNSServiceRefDeallocate`, and it composes with the same stream bridge as 7.5.

### The descriptor limit

`RLIMIT_NOFILE` is **256 soft** on macOS. A /24 across 100 ports is roughly 25,400
probes; at 256 descriptors the scan fails confusingly on the first run.

*Containment:* `setrlimit` to the hard limit at startup and derive pool concurrency
from the value actually granted — `min(512, limit / 4)` — never from a constant. The
quarter is headroom for everything else the process has open.

### Executor affinity for socket actors

A socket actor whose executor is the shared cooperative pool competes with every
other task in the process, and kqueue readiness handling is latency-sensitive in a
way that ordinary async work is not.

*Containment:* give the socket actors a `SerialExecutor` backed by a dedicated
`DispatchQueue`. It costs a `SerialExecutor` conformance and buys predictable
wake-up latency for the one thing whose latency is the product.

### The permission that fails silently

On current macOS, ICMP to the local network, mDNS, SSDP multicast and NetBIOS all
require the Local Network entitlement, and **denial returns zero results rather than
an error.** A bare SPM executable has no bundle, so the grant attaches to the
terminal and never appears under the tool's own name.

*Containment, two parts.* Embed an `Info.plist` into the executable at link time
with `NSLocalNetworkUsageDescription` and `NSBonjourServices` listing every browsed
service type:
`-Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker <path>`.
And detect it actively: **if the ICMP sweep finds nothing while the ARP cache is
non-empty, that is the signature of denial** — emit a `Degradation` naming it. The
detection is a heuristic and the user-facing string must say so; claiming certainty
about a permission we cannot query is the kind of small lie that erodes trust in
everything else the tool reports.

---

## Acceptance

- All 19 existing tests still pass, and the new model types are covered.
- `swift build` clean with `.strictMemorySafety()` — no `unsafe` in core at all.
- Every `Model/` type round-trips through `JSONEncoder`/`JSONDecoder` unchanged,
  including the all-`nil` unidentified device, verified by a property test.
- A DocC catalog exists and every public symbol has a doc comment. This package is
  consumed by people who will never read its source.
- No `#if canImport(Darwin)` anywhere in the public API surface.

---

## Bibliography

Each entry is here because it changes a decision in this document, and the line
under it says which.

**Marinos, I., Watson, R. N. M., & Handley, M. (2014). Network Stack Specialization
for Performance. *ACM SIGCOMM '14*.** University of Cambridge and University College
London.
<https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/201408-sigcomm2014-specialization.pdf>
The foundational argument for this whole project: general-purpose stacks lose to
specialized ones by 2–10× on throughput, and the losses are syscall overhead,
buffering that blows the cache, repeated copies and domain transitions. Their five
principles — zero-copy to its logical extreme, a bufferless event model, cross-layer
amortization, heavy batching, and no locking or cache-line contention — are the
design rules behind the async contracts and the Swift 6 features this package rests
on, and `Span` is what lets us follow the first one without giving up memory safety.

**Grosvenor, M. P., Schwarzkopf, M., Gog, I., Watson, R. N. M., Moore, A. W., Hand,
S., & Crowcroft, J. (2015). Queues Don't Matter When You Can JUMP Them! *USENIX
NSDI '15*.** University of Cambridge.
<https://www.usenix.org/system/files/conference/nsdi15/nsdi15-paper-grosvenor.pdf>
Latency variance comes from queueing, and bounding what you put in flight bounds the
tail far better than going faster does. This is the justification for
`boundedPool`'s fixed concurrency window over an unbounded fan-out: the naive
scanner that fires everything at once produces a long tail of timeouts that costs
more wall-clock than the queue ever saved.

**Moore, A. W., Hall, J., Kreibich, C., Harris, E., & Pratt, I. (2003). Architecture
of a Network Monitor. *Passive and Active Measurement (PAM) '03*.** University of
Cambridge.
<https://www.cl.cam.ac.uk/research/srg/netos/projects/archive/nprobe/publications/pam2003moore.pdf>
On separating capture from analysis, and on why timestamps must be taken as close to
the wire as possible. Our `Timing` model and the rule that measurement uses
`ContinuousClock` while display uses wall time both come from this discipline.

**Antichi, G., Shahbaz, M., Geng, Y., Zilberman, N., Covington, A., Bruyere, M.,
McKeown, N., Feamster, N., Felderman, B., Blott, M., Moore, A. W., & Owezarski, P.
(2014). OSNT: Open Source Network Tester. *IEEE Network*, 28(5).** Cambridge and
Queen Mary University of London.
<https://www.cl.cam.ac.uk/~nz247/publications/antichi2014osnt.pdf>
A measurement tool must characterize its own accuracy before its numbers mean
anything. This is why `Timing` is part of the output model rather than a log line:
a claim of speed that cannot be reproduced from the artifact is marketing.

**Varghese, G., & Lauck, T. (1987). Hashed and Hierarchical Timing Wheels: Data
Structures for the Efficient Implementation of a Timer Facility. *ACM SOSP '87*.**
<https://www.cs.columbia.edu/~nahum/w6998/papers/sosp87-timing-wheels.pdf>
The algorithmic core of probe timeout management. A sorted list or heap of pending
timeouts costs O(log n) per insertion and expiry across tens of thousands of probes;
a hashed timing wheel makes both O(1). With 25,000 probes in flight this is the
difference between timeout bookkeeping being free and it being the bottleneck.

**Lemon, J. (2001). Kqueue: A Generic and Scalable Event Notification Facility.
*USENIX Annual Technical Conference (FREENIX Track)*.**
<https://people.freebsd.org/~jlemon/papers/kqueue_freenix.pdf>
Why readiness notification on Darwin is O(number of ready events) rather than
`select`'s O(number of watched descriptors), and why the changelist and eventlist
are batched in a single syscall. The non-blocking rule for the cooperative pool and
the executor decision both rest on this, and the batching is the specialization paper's
fourth principle showing up at the syscall boundary.

**Cormode, G., & Muthukrishnan, S. (2005). An Improved Data Stream Summary: The
Count-Min Sketch and Its Applications. *Journal of Algorithms*, 55(1).** Cormode is
at the University of Warwick.
<https://dsf.berkeley.edu/cs286/papers/countmin-latin2004.pdf>
Sublinear-space frequency estimation. In watch mode, exact per-host counters over a
long run cost memory proportional to hosts times observations; a sketch answers "how
often has this host appeared" in fixed space with a bounded error, which is more
than good enough for a heuristic and is the difference between a watch that runs for
a week and one that grows without limit.

**Bloom, B. H. (1970). Space/Time Trade-offs in Hash Coding with Allowable Errors.
*Communications of the ACM*, 13(7).**
Membership testing with one-sided error in a fraction of the space. "Have I already
probed this address in this run" is asked millions of times; false positives are
tolerable (a skipped duplicate probe), false negatives would not be, and Bloom's
structure has exactly that asymmetry.

**Chambi, S., Lemire, D., Kaser, O., & Godin, R. (2016). Better Bitmap Performance
with Roaring Bitmaps. *Software: Practice and Experience*, 46(5).**
<https://arxiv.org/abs/1402.6407>
Compressed bitmaps with fast random access. Per-run host presence — the "was host X
up at run Y" query that watch mode is entirely built around — compresses to bits,
and Roaring is the structure that keeps it both small and directly queryable rather
than forcing a decompress-to-answer.

**Little, J. D. C. (1961). A Proof for the Queuing Formula: L = λW. *Operations
Research*, 9(3).**
The arithmetic behind choosing a concurrency window. In-flight probes equals probe
rate times mean response time, so a 200 ms mean RTT at a target of 5,000 probes per
second requires 1,000 in flight. This is how `boundedPool`'s concurrency is
*derived* from measured RTT rather than guessed, and why the number must adapt as
the sweep learns the network's actual latency.

**Jacobson, V. (1988). Congestion Avoidance and Control. *ACM SIGCOMM '88***, and
**Karn, P., & Partridge, C. (1987). Improving Round-Trip Time Estimates in Reliable
Transport Protocols. *ACM SIGCOMM '87*.**
The smoothed RTT and mean-deviation estimator, and the rule that a retransmitted
probe's RTT sample must be discarded because you cannot tell which transmission it
answers. Our per-host adaptive timeout is this estimator; a fixed timeout is why
conventional scanners are slow on a fast LAN — they wait a second for a host that
answers in 400 microseconds.
