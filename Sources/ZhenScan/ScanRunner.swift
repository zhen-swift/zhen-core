// ScanRunner.swift — one scan, start to finished artifact.
//
// This target is non-isolated by construction — see the manifest. Nothing in here may
// touch the main actor, and the way that is guaranteed is that main-actor isolation is
// not the default here the way it is in the app target next door.
//
// ── The one rule that shapes this file ───────────────────────────────────────────
//
// **The artifact comes from `discover(_:deadline:progress:)`. The display comes from the
// sink.** They are different channels and the difference is load-bearing: the progress
// channel is `.bufferingNewest` and may drop events, which is only safe because results
// travel in the returned envelope. Assembling the device list from the events the UI
// happened to see would silently drop devices from a report that still says
// `outcome: complete` — the exact bug the CLI's pipeline was restructured to remove.
//
// ── Duplication worth naming ─────────────────────────────────────────────────────
//
// This is the second implementation of the same pipeline. the command line has one, in
// `ScanPipeline.swift`, and it does the same four things in the same order. They cannot
// be shared today because the CLI's lives in an executable target, which nothing can
// import, and neither package may be modified from here. Two pipelines that must agree
// about what a scan IS will drift; the fix is for this to live in `ZhenCore`
// alongside the engines it drives.

import Foundation
import ZhenCore
import ZhenDarwin

/// What a finished scan produced, plus the events derived from comparing it to history.
public struct CompletedScan: Sendable {
    /// The artifact. Everything the UI shows as fact comes from here.
    public var report: ScanReport
    /// What changed since the previous run in this session.
    public var events: [DerivedEvent]

    /// Creates a value from its fields.
    public init(report: ScanReport, events: [DerivedEvent]) {
        self.report = report
        self.events = events
    }
}

/// Runs scans against the real network.
///
/// Holds the platform engines and nothing else — no UI state, no store, no opinions
/// about presentation. It is constructed once and reused, because building it raises the
/// descriptor limit and reads the interface list, neither of which should happen per
/// scan.
public struct ScanRunner: Sendable {
    private let scanner: DarwinScanner
    private let store: any HistoryStore

    /// The interface scans go out of, resolved once at construction.
    public let interface: NetworkInterface
    /// Anything that went wrong while building the scanner — a clamped concurrency
    /// request. Carried so it reaches the artifact rather than a log.
    public let setupDegradations: [Degradation]

    /// Builds a runner for this machine.
    ///
    /// - Throws: `PlatformError` when there is no usable interface, which is the one
    ///   condition the app cannot scan through and must say so about.
    /// - Parameter capture: `.helperThenDirect` by default, because the app is what
    ///   the privileged helper exists for: a person who installed it has said they want
    ///   the layer-2 sweep, and they did not launch the app under `sudo`. A direct open
    ///   is still tried first, so a privileged launch does not depend on a daemon.
    public init(
        store: any HistoryStore,
        concurrencyOverride: Int? = nil,
        capture: CapturePolicy = .fromEnvironment
    ) async throws(PlatformError) {
        let scanner = try await DarwinScanner.make(
            concurrencyOverride: concurrencyOverride, capture: capture
        )
        self.scanner = scanner
        self.store = store
        self.interface = try scanner.interfaces.primaryInterface()
        self.setupDegradations = [
            DarwinScanner.clampNotice(
                requested: concurrencyOverride,
                granted: scanner.descriptorLimit,
                effective: scanner.concurrency
            ),
        ].compactMap { $0 }
    }

    /// What the engine can do, for the artifact and for Settings.
    public var descriptor: EngineDescriptor { scanner.descriptor }

    /// Runs one scan.
    ///
    /// - Parameters:
    ///   - network: what to scan. Defaults to the primary interface's own network.
    ///   - budget: the total time allowed. Every stage subdivides this with
    ///     `clamped(to:)`; nothing reads a global timeout.
    ///   - deepScan: whether to probe ports on the hosts that answered.
    ///   - progress: display only. Lossy by design, and nothing here is load-bearing.
    /// - Returns: the artifact and the events it implies. Never throws — a deadline hit
    ///   and a cancellation are both normal returns carrying real partial results.
    public func run(
        network: IPv4Network? = nil,
        budget: Duration,
        deepScan: Bool,
        progress: ProgressSink
    ) async -> CompletedScan {
        let startedAt = Timestamp.now
        let runID = UUID()
        let target = ScanTarget(network: network ?? interface.network, interface: interface)
        let deadline = Deadline(after: budget)
        var degradations = setupDegradations
        for degradation in degradations { progress(.degraded(degradation)) }

        // ── Discovery ────────────────────────────────────────────────────────────
        let discovery = await scanner.discovery.discover(target, deadline: deadline, progress: progress)
        degradations.append(contentsOf: discovery.degradations)
        var facts = Dictionary(uniqueKeysWithValues: discovery.hosts.map { ($0.ip, $0) })
        var stages = discovery.timing.stages
        var outcome = discovery.outcome
        var peak = discovery.timing.peakConcurrency
        // Every capability any stage actually exercised, not only discovery's.
        //
        // This read `discovery.usedCapabilities` alone, which meant a --deep run that
        // scanned ports reported `["icmp_sweep", "neighbor_table"]` and never
        // `connect_scan` or `syn_scan`. The study's defect was an artifact claiming a
        // capability the binary did not have; this is the same field lying in the other
        // direction, and a capability list that omits what ran is no more checkable
        // than one that invents it.
        var exercised = discovery.usedCapabilities

        // ── Naming ───────────────────────────────────────────────────────────────
        if !facts.isEmpty, outcome == .complete, !deadline.isExpired {
            let resolution = await scanner.naming.resolveNames(
                for: facts.keys.sorted(), on: target, deadline: deadline, progress: progress
            )
            for (ip, candidates) in resolution.names {
                if var host = facts[ip] {
                    // Every candidate, winners and losers. The "Known by" card is built
                    // entirely from the losers.
                    host.allNames = (host.allNames + candidates).sorted()
                    facts[ip] = host
                    progress(.hostUpdated(host))
                } else if target.network.contains(ip) {
                    // A host the sweep never heard from that a name source did. That is
                    // positive evidence of a device; dropping it for tidy stage
                    // boundaries would report the network as emptier than it is.
                    let host = HostFacts(ip: ip, allNames: Array(candidates))
                    facts[ip] = host
                    progress(.hostFound(host))
                }
            }
            for (ip, mac) in resolution.hardware where facts[ip]?.mac == nil {
                facts[ip]?.mac = mac
            }
            // This machine's own row. Bonjour resolves the local host to 127.0.0.1 and
            // the ledger remaps it onto the scanning interface — but the sweep leaves
            // its own address out of the neighbour-derived hosts, so without this the
            // one device we know most about is the row with no hardware address.
            if facts[target.interface.address]?.mac == nil,
               let hardware = target.interface.hardwareAddress {
                facts[target.interface.address]?.mac = hardware
            }
            stages.append(resolution.timing)
            degradations.append(contentsOf: resolution.degradations)
            if resolution.outcome == .cancelled { outcome = .cancelled }
        }

        // ── Deep scan, only when asked ───────────────────────────────────────────
        if deepScan, !facts.isEmpty, outcome == .complete, !deadline.isExpired {
            let result = await scanner.ports.scan(
                facts.keys.sorted(),
                ports: .commonServices,
                // A ceiling, not a fixed wait: the engine narrows it per host from that
                // host's own measured round trips.
                perHostDeadline: .milliseconds(600),
                deadline: deadline,
                progress: progress
            )
            for (ip, observations) in result.ports { facts[ip]?.ports = observations }
            for (ip, fingerprint) in result.fingerprints { facts[ip]?.osFingerprint = fingerprint }
            exercised.formUnion(result.usedCapabilities)
            stages.append(contentsOf: result.timing.stages)
            degradations.append(contentsOf: result.degradations)
            if result.outcome != .complete { outcome = result.outcome }
            peak = max(peak, result.timing.peakConcurrency)
        }

        // A stage interrupted before it reported itself still took time. Reporting zero
        // elapsed over a device list that plainly has entries would be a lie in the one
        // field meant to be checkable.
        if stages.isEmpty { stages.append(StageTiming(stage: .discovery, elapsedMillis: 0)) }

        let finishedAt = Timestamp.now
        // History supplies first-seen. `Device(observing:…)` defaults it to `lastSeen`,
        // which is right on a first-ever run and wrong on every one after it.
        let firstSeen = await store.firstSeen(for: Array(facts.values), in: target.network)
        let devices = facts.values
            .map {
                Device(
                    observing: $0,
                    in: target.network,
                    firstSeen: firstSeen[$0.ip] ?? finishedAt,
                    lastSeen: finishedAt
                )
            }
            .sorted { $0.ip < $1.ip }

        let report = ScanReport(
            run: ScanRun(
                id: runID,
                startedAt: startedAt,
                finishedAt: finishedAt,
                target: target.network,
                interface: target.interface.name,
                engine: EngineDescriptor(
                    name: scanner.discovery.descriptor.name,
                    kind: scanner.discovery.descriptor.kind,
                    // What was exercised, not what was advertised.
                    capabilities: exercised
                ),
                outcome: Task.isCancelled ? .cancelled : outcome,
                timing: Timing(
                    stages: stages,
                    counters: ProbeCounterSnapshot(
                        probesSent: stages.reduce(0) { $0 + $1.probesSent },
                        repliesSeen: stages.reduce(0) { $0 + $1.repliesSeen },
                        peakConcurrency: peak,
                        inFlight: 0
                    )
                )
            ),
            devices: devices,
            degradations: degradations
        )

        let events = await store.record(report)
        return CompletedScan(report: report, events: events)
    }
}

extension CapturePolicy {
    /// The policy this launch should use, honouring `ZHEN_CAPTURE`.
    ///
    /// `ZHEN_CAPTURE=direct` forces the pre-helper behaviour: open `/dev/bpf*` in
    /// this process, or do without.
    ///
    /// It exists because the helper cannot be verified without a baseline. Kernel ARP
    /// and the sweep's ARP are the same shape on the wire — both 42 bytes, both from
    /// this machine's hardware address, both asking about the same addresses — so the
    /// only honest way to attribute ARP to the sweep is to run the same scan on the same
    /// segment with the sweep off and subtract. This is the switch that turns it off,
    /// and `Scripts/verify-helper.sh` is the caller.
    ///
    /// It also answers "does it still work without the helper", which is the first
    /// question anybody with a misbehaving daemon will have.
    public static var fromEnvironment: CapturePolicy {
        ProcessInfo.processInfo.environment["ZHEN_CAPTURE"] == "direct"
            ? .directOnly : .helperThenDirect
    }
}
