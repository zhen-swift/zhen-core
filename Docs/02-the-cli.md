# 02 — the command line (`zhen/Sources/zhen`)

> **Amended 2026-09-26.** The two packages this document describes are now one, at
> `zhen/`, and the app's sources moved into its own Xcode project at `zhen-app/`. The
> manifest excerpts below are kept because the reasoning attached to them is still the
> reasoning in force — the isolation settings, the memory-safety exemptions, the reason
> the engines live beside the model. **`zhen/Package.swift` is the authority**; anything
> here that contradicts it is history, not instruction. See `Docs/DIRECTION.md` for why.


**Run after the library.** This target owns no types. If you find yourself
declaring a struct that describes network reality, it belongs in core and the app
needs it too.

---

## What this package is

A command-line scanner built on `ZhenCore`, and the **portability proving
ground**. The Apple app can afford to be Darwin-only; the CLI cannot, because its
whole reason to exist beyond convenience is that it travels — macOS today, Linux
next, Windows after that.

That constraint is useful pressure rather than a tax. Anything the CLI cannot
express portably is, by definition, something the app is about to hide behind a
platform protocol — the CLI finds those seams before they calcify.

```
ZhenCore  ──►  zhen (executable)   (this document)
                └─►  zhen-app        (document 03)
```

### The performance claim this binary has to defend

nmap is slow on macOS for reasons that are structural, not incidental: conservative
fixed timeouts tuned for the internet rather than a LAN, per-host serialization, and
a privilege model that pushes users toward `sudo` for work that does not need it.
This binary should beat it on a home /24 by a wide margin while running entirely
unprivileged, and `zhen bench` exists so that claim is a number anyone can
reproduce rather than an assertion in a README.

---

## Package manifest

```swift
// swift-tools-version: 6.2
import PackageDescription

let settings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    // The executable is main-actor-isolated by default: command entry points and
    // terminal output are inherently serial, and this keeps them that way without
    // annotation. Core stays non-isolated, so no scanning work is pulled onto it.
    .defaultIsolation(MainActor.self),
]

let package = Package(
    name: "zhen-cli",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(path: "../zhen-core"),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "zhen",
            dependencies: [
                .product(name: "ZhenCore", package: "zhen-core"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: settings,
            linkerSettings: [
                // See the bundle-less permission problem — without this the Local
                // Network grant attaches to the terminal and the scanner silently
                // returns nothing.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT", "-Xlinker", "__info_plist",
                    "-Xlinker", "Sources/zhen/Info.plist",
                ], .when(platforms: [.macOS]))
            ]
        ),
        .testTarget(name: "zhenTests", dependencies: ["zhen"], swiftSettings: settings),
    ]
)
```

`swift-argument-parser` is the only external dependency in the entire repo. Keep it
that way; every addition is a supply chain we then own.

---

## Command surface

```
zhen scan      [--cidr <net>] [--iface <name>] [--discovery-only]
                    [--deep] [--ports <spec>]
                    [--retransmit-timeout <duration>] [--shared-budget]
                    [--reach history|learned|<duration>] [--reach-percentile <p>]
                    [--no-neighbor-watch] [--look-longer]
zhen hosts     [--since <duration>] [--json] [--store <path>]
zhen events    [--since <duration>] [--json] [--store <path>]
zhen history   <host> [--json] [--store <path>]
zhen export    [--json] [--store <path>]
zhen watch     --interval <duration>
zhen bench     [--compare <baseline.json>]
```

Global: `--json`, `--ndjson`, `--quiet`, `--deadline <duration>`,
`--concurrency <n>`, `--no-color`.

`watch` and `bench` do not exist yet. They are absent rather than stubbed: a subcommand
that parses and then says "not implemented" appears in help, gets scripted against, and
then changes behaviour.

**History is a file, and whose file it is matters.** `scan` records every run to
`history.ndjson` under the platform's application-support directory, and the four
reading commands open the same file. Under `sudo` the path is rebuilt beneath the home
of the user named in `SUDO_USER`, because every home-directory API answers `/var/root`
for a privileged scan — the history would land where the person who typed the command
cannot read it, and their next unprivileged scan would open an empty store and report
the whole network as newly appeared. `ZHEN_HISTORY` overrides the path exactly, and
`--store` does the same for one command.

**Two flags exist to make the scan worse, on purpose.** `--retransmit-timeout` pins
the interval before an unanswered probe is resent, and `--shared-budget` collapses
that interval and the end-of-scan wait into a single number. Both are slower than the
default and neither is advice. They are here because the split budget and its adaptive
interval are *claims* about why this scanner is fast, and a claim like that is only
checkable against the same scanner with the mechanism removed — comparing against a
different program cannot isolate anything, since every other difference comes along
with it. They are mutually exclusive, they refuse rather than pick a winner, and the
artifact records which policy produced it in `budget_policy`, so a measured 150 ms
interval and an imposed one are never confusable after the fact.

**How long to wait is a property of the address (0.8.0).** `--reach history`, the
default, waits longer for the addresses this network's history says usually answer —
up to the 97th percentile (`--reach-percentile`) of their *cold* first-contact times,
capped at 5 s, with more attempts — and gives every other address the short wait learned
from the scan's own replies. A network with fewer than 20 cold samples waits 1.5 s
everywhere, once. The scan ends at the latest per-address deadline, or as soon as every
expected address has answered; while only expected addresses remain it says so
(`settling`). `--reach learned` is the single learned wait for everyone, as before 0.8.0;
`--reach 3s` waits exactly that. `--look-longer` re-asks the latest scan's
`expected_missing` for 10 s (or `--reach <duration>`) and adds what answers to that scan
instead of starting one. `--no-neighbor-watch` is an ablation: with `--reach learned` it
is 0.7.0's mechanism, which study 2 compares against.

**Three output modes, and they are not interchangeable.** `--json` emits one
`ScanReport` on completion, for a caller that wants the artifact. `--ndjson` emits
one event per line as it happens, for a caller that wants to stream. The default is
human-readable text on a terminal. All three carry the same schema version, and the
human mode is a rendering of the same model — never a separate code path that can
drift from what the machine modes report.

**JSON to stdout, progress to stderr, always.** `zhen scan --json > out.json`
must produce a valid document while the user still sees a progress bar. This is not
a preference; it is the difference between a tool that composes in a pipeline and
one that does not.

### Exit codes

```
0    the scan ran — including a partial result from an expired deadline
64   usage error (EX_USAGE)
69   a required capability was unavailable (EX_UNAVAILABLE) — e.g. Local Network denied
75   temporary failure (EX_TEMPFAIL) — the interface went away mid-scan
130  interrupted
```

A partial result exits 0 deliberately. The deadline expiring is the system working
as designed, and a script that treats it as failure would be wrong on a busy
network. Whether a run was complete is a field in the artifact, not the exit status.

---

## Structure of the program

```swift
@main
struct Zhen: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "zhen",
        abstract: "Fast native network discovery.",
        subcommands: [Scan.self, Watch.self, Hosts.self, History.self,
                      Events.self, Export.self, Bench.self],
        defaultSubcommand: Scan.self
    )
}

struct Scan: AsyncParsableCommand {
    @OptionGroup var options: GlobalOptions

    func run() async throws {
        let scanner = try PlatformScanner.make()          // the platform seam
        let renderer = Renderer.forCurrentOutput(options)  // tty / json / ndjson

        try await withThrowingTaskGroup { group in
            group.addTask { try await renderer.consume(scanner.stream(target, deadline: deadline)) }
            group.addTask { try await SignalHandler.run(onFirst: { renderer.finish() }) }
            try await group.next()
            group.cancelAll()
        }
    }
}
```

The whole program is one structured task tree. Cancellation propagates from the root
by construction, which is what makes Ctrl-C correct rather than something bolted on
afterwards.

---

## Swift 6 features this package is built on

**`AsyncParsableCommand`.** `run() async throws` is the entry point; there is no
`RunLoop`, no semaphore, and no `dispatchMain()` anywhere in this package. If you
see one in a review, something has been bridged wrongly.

**Structured concurrency for lifetime.** The task group above means a cancelled
scan tears down its sockets deterministically, because every child's cancellation
runs `continuation.onTermination`. No manual cleanup path exists, so no manual
cleanup path can be forgotten.

**`for await` with backpressure that actually applies.** A terminal renders perhaps
sixty frames a second while the scanner produces thousands of events. The renderer
consumes the stream at its own pace and the stream's `.bufferingNewest` policy
discards stale progress rather than queueing it. Coalesce redraws on a timer;
do not redraw per event.

**`Atomic` counters, `.relaxed`.** Probe and reply counts crossing task boundaries
are statistics, not synchronization. Ordering them costs real time at a million
increments and buys nothing.

**Typed throws at the boundary.** `throws(ScanSetupError)` on setup, where the
failures are genuinely enumerable — no interface, no permission, bad CIDR — so the
top-level mapping to an exit code is a `switch` the compiler checks for
exhaustiveness. Once scanning starts, nothing throws; failures are degradations in
the artifact.

**`@concurrent` where work is genuinely CPU-bound.** Under Swift 6.2's approachable
concurrency, `nonisolated` async functions run on the caller's actor by default,
which is the right default and wrong for the report encoder. Serializing a large
`ScanReport` on the main actor stalls the progress display; mark it `@concurrent`
and it moves off.

---

## The platform seam

This is the design decision that decides whether Linux is a weekend or a rewrite.

```swift
public protocol PlatformScanner: Sendable {
    static func make() throws(ScanSetupError) -> Self
    var capabilities: EngineCapabilities { get }
    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent>
}
```

| Concern | Darwin | Linux | Windows (later) |
|---|---|---|---|
| Readiness | kqueue via `DispatchSource` | epoll via corelibs-libdispatch | IOCP — needs its own conformance |
| Unprivileged ICMP | `SOCK_DGRAM`/`IPPROTO_ICMP` | same, gated by `ping_group_range` | raw socket, admin |
| Interfaces | `getifaddrs` | `getifaddrs` | `GetAdaptersAddresses` |
| Neighbour table | route `sysctl` | `/proc/net/arp` or netlink | `GetIpNetTable2` |
| mDNS | `dns_sd` | Avahi, or none | none |

Two rules keep this honest. **A missing capability is a `Degradation`, never a
build failure** — Linux without Avahi scans fine and reports that Bonjour names were
unavailable, exactly as macOS does when the permission is denied. And **`#if os(...)`
appears only in `Platform/`**, never in a command, a renderer, or anything in core.
The moment a conditional leaks into command code, the portability claim is gone and
nobody notices for six months.

---

## What must be done by hand, why, and how to contain it

### The bundle-less permission problem

On current macOS the Local Network permission gates ICMP to the LAN, mDNS, SSDP and
NetBIOS — and **denial returns zero results, not an error.** A bare SPM executable
has no bundle, so the grant attaches to the terminal that launched it and never
appears under this tool's name in System Settings.

*Containment:* embed the `Info.plist` into the `__TEXT,__info_plist` section at link
time, as in the manifest above, carrying `NSLocalNetworkUsageDescription` and
`NSBonjourServices` with every service type the discovery layer browses. A type that
is browsed but not declared silently returns nothing.

*Bypass when it still fails:* the ARP table is readable without the permission. If
the ICMP sweep finds nothing while the neighbour table is populated, that asymmetry
is the signature of denial — report it as a degradation naming the permission, and
say plainly that it is inferred. We cannot query the grant, and pretending otherwise
is a lie the user will eventually catch.

### Signals

`signal()` handlers may only call async-signal-safe functions, which excludes
essentially everything interesting, and Swift gives no guarantees inside one.

*Containment:* `DispatchSourceSignal` with `signal(SIGINT, SIG_IGN)` first, so
delivery happens on a queue where ordinary code is legal. First signal unwinds
cleanly, flushes the partial artifact and derives its events; second signal exits
immediately. Ctrl-C at hour three of a watch must not discard that tick's work.

*Portability:* Windows has no POSIX signals. The handler is part of `Platform/`.

### Watch scheduling drifts if you sleep

`sleep(interval)` after each run means a 90-second scan on a 60-second interval
drifts to 150-second spacing, and the "every minute" history silently becomes
something else — which corrupts the comparison the whole feature exists for.

*Containment:* compute tick times from a fixed origin — `origin + n × interval` on
`ContinuousClock` — skip missed ticks, and record the skip as an event. Monotonic
specifically: a laptop that sleeps must not have its schedule dragged by the wall
clock jumping.

### Terminal rendering without a dependency

*Containment:* `isatty(1)` decides between the interactive renderer and plain
output; `NO_COLOR` and `--no-color` are honoured; ANSI goes to stderr only. No
curses dependency — the progress display is a few escape sequences and a redraw
timer, and adding a C library to draw a bar is a bad trade.

### JSON must be byte-stable

Dictionary iteration order is unspecified, so unsorted keys make every artifact
differ from the last and defeat diffing a scan against yesterday's.

*Containment:* `.sortedKeys` on the encoder, plus `.withoutEscapingSlashes`. Numbers
are integers wherever possible — never a locale-formatted string. And the non-ASCII
apostrophe in a name like `Alex's MacBook Pro` must survive unescaped; verify with a
fixture, because this is exactly the sort of thing that quietly breaks in a
round trip.

---

## `zhen bench`

The claim is speed, so make it falsifiable. `bench` runs a fixed scan profile
against a target, records `Timing` from the artifact, and compares against a
committed baseline: wall time to first host, wall time to complete, probes per
second, peak concurrency, and how many hosts were found — because a scanner that is
fast because it missed half the network is not fast.

Fail the run on a regression beyond a threshold. A performance claim without a
regression test decays within a month.

---

## Acceptance

- `zhen scan --json > out.json` produces a valid document with a progress
  display still visible on the terminal.
- A scan against an unroutable network returns within its deadline, reports partial
  results, and populates `degradations`. Nothing hangs.
- Ctrl-C mid-scan commits the partial run and exits 130; a second Ctrl-C exits at
  once.
- `--concurrency` beyond the descriptor limit does not fail — it clamps and says so.
- Every command has help text; no `fatalError` in a reachable path.
- The package compiles with only `Platform/` excluded on a non-Darwin build, proving
  the seam holds before anyone has a Linux machine in front of them.

---

## Bibliography

**Marinos, I., Watson, R. N. M., & Handley, M. (2014). Network Stack Specialization
for Performance. *ACM SIGCOMM '14*.** Cambridge / UCL.
<https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/201408-sigcomm2014-specialization.pdf>
Syscall overhead and buffering dominate, and batching recovers most of it. The
renderer's coalesced redraws and the batched kqueue changelist are the same
principle applied at two different boundaries — amortize the crossing, do not
eliminate the work.

**Grosvenor, M. P., Schwarzkopf, M., Gog, I., Watson, R. N. M., Moore, A. W., Hand,
S., & Crowcroft, J. (2015). Queues Don't Matter When You Can JUMP Them! *USENIX
NSDI '15*.** Cambridge.
<https://www.usenix.org/system/files/conference/nsdi15/nsdi15-paper-grosvenor.pdf>
Bounded in-flight work bounds tail latency. `--concurrency` exists as a knob because
of this, and its default is derived rather than picked: more probes in flight past
the point of saturation makes the slowest probe slower, not the scan faster.

**Little, J. D. C. (1961). A Proof for the Queuing Formula: L = λW. *Operations
Research*, 9(3).**
The default for `--concurrency` is `targetRate × observedRTT`, not a constant. On a
LAN with a 0.4 ms mean RTT, a few hundred in flight already saturates; on a slow
link the same number starves. Deriving it from measurement is why the scanner adapts
to the network instead of being tuned for one.

**Amdahl, G. M. (1967). Validity of the Single Processor Approach to Achieving Large
Scale Computing Capabilities. *AFIPS Spring Joint Computer Conference*.**
The serial fraction bounds the speedup. In this program the serial fraction is
report encoding, terminal rendering and store writes — which is precisely why the
encoder is `@concurrent` and the renderer coalesces. Parallelizing the probe fan-out
further, once those dominate, buys nothing.

**Varghese, G., & Lauck, T. (1987). Hashed and Hierarchical Timing Wheels. *ACM SOSP
'87*.**
<https://www.cs.columbia.edu/~nahum/w6998/papers/sosp87-timing-wheels.pdf>
O(1) insertion and expiry for the pending-probe table. With tens of thousands of
outstanding probes each carrying its own adaptive deadline, a heap-based timer set
becomes the bottleneck before the network does.

**Lemon, J. (2001). Kqueue: A Generic and Scalable Event Notification Facility.
*USENIX ATC (FREENIX)*.**
<https://people.freebsd.org/~jlemon/papers/kqueue_freenix.pdf>
Readiness cost proportional to ready events rather than watched descriptors, and
batched registration. The Darwin conformance in the platform seam, and why `select`
is not an option at this descriptor count.

**Jacobson, V. (1988). Congestion Avoidance and Control. *ACM SIGCOMM '88*;
Karn, P., & Partridge, C. (1987). Improving Round-Trip Time Estimates in Reliable
Transport Protocols. *ACM SIGCOMM '87*.**
The smoothed-RTT and mean-deviation estimator behind the adaptive per-host timeout,
and Karn's rule that a retransmitted probe yields no usable sample. This is the
single largest source of the speed advantage over a fixed-timeout scanner on a LAN:
waiting one second for a host that answers in 400 microseconds is almost all of
nmap's wall clock on a quiet /24.

**Moore, A. W., Hall, J., Kreibich, C., Harris, E., & Pratt, I. (2003). Architecture
of a Network Monitor. *PAM '03*.** Cambridge.
<https://www.cl.cam.ac.uk/research/srg/netos/projects/archive/nprobe/publications/pam2003moore.pdf>
Timestamp discipline, and the separation of capture from analysis — which is exactly
the split between this package's scanning path and its rendering path.

**Antichi, G., et al. (2014). OSNT: Open Source Network Tester. *IEEE Network*,
28(5).** Cambridge / QMUL.
<https://www.cl.cam.ac.uk/~nz247/publications/antichi2014osnt.pdf>
A tester must characterize its own accuracy. `zhen bench` is that idea in a
subcommand: the tool reports its own timing in the artifact so the claim can be
checked by someone who does not trust us.
