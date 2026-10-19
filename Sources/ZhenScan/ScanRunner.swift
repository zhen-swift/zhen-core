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

// Guarded like every file in `ZhenDarwin`, which this imports. The guard is per file
// rather than in the manifest because SPM can conditionalise a target's DEPENDENCIES and
// not its existence — a target always compiles, so a target that cannot compile
// everywhere has to say so here. On Linux this module is empty, which is correct: it is
// the app's adapter, and the app runs on Apple platforms only — macOS, and iPadOS with
// the unprivileged composition `DarwinScanner.make` assembles there.
//
// It was not guarded until the reorganisation moved this target into a package whose CI
// builds on Linux. It has always been Apple-only; only the check is new.
#if canImport(Darwin)
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
    ///   - ports: which of the hosts that answered to probe for ports — none, all, or
    ///     only those history has never seen. Was `deepScan: Bool`, which could not say
    ///     the third.
    ///   - progress: display only. Lossy by design, and nothing here is load-bearing.
    ///   - reach: how long to wait for each address. The default waits longer for what
    ///     this network's history says usually answers; see `ReachPlan`.
    ///   - settings: the constants behind `reach`.
    /// - Returns: the artifact and the events it implies. Never throws — a deadline hit
    ///   and a cancellation are both normal returns carrying real partial results.
    public func run(
        network: IPv4Network? = nil,
        budget: Duration,
        ports: PortStage,
        progress: ProgressSink,
        reach: SweepReach = .default,
        settings: ReachSettings = ReachSettings()
    ) async -> CompletedScan {
        let startedAt = Timestamp.now
        let scanStart = MonotonicInstant.now
        let runID = UUID()
        var target = ScanTarget(network: network ?? interface.network, interface: interface)
        // The plan, from this network's history, before the sweep. Every device the
        // store holds contributes its samples; only one seen inside
        // `settings.expectedWindow` makes its address expected — retention governs the
        // event log, not this (F3; questions, Q1).
        target.reach = ReachPlan.make(
            addresses: target.resolvedAddresses, network: target.network,
            devices: await store.devices(), policy: reach, settings: settings, now: .now
        )
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
                    let host = HostFacts(ip: ip, allNames: Array(candidates), foundAt: .now)
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

        // History supplies first-seen. `Device(observing:…)` defaults it to `lastSeen`,
        // which is right on a first-ever run and wrong on every one after it.
        //
        // Asked before the port stage rather than after, because it is also what decides
        // which hosts are new — and the port stage adds ports and a fingerprint, never an
        // identifier, so the answer is the same on either side of it.
        let firstSeen = await store.firstSeen(for: Array(facts.values), in: target.network)

        // ── Deep scan, only when asked, and only of whom it was asked for ────────
        let probed = ports.targets(among: Array(facts.keys), known: firstSeen)
        if !probed.isEmpty, outcome == .complete, !deadline.isExpired {
            let result = await scanner.ports.scan(
                probed.map(IPAddress.v4),
                ports: .commonServices,
                // A ceiling, not a fixed wait: the engine narrows it per host from that
                // host's own measured round trips.
                perHostDeadline: .milliseconds(600),
                deadline: deadline,
                progress: progress
            )
            for (ip, observations) in result.ipv4Hosts { facts[ip]?.ports = observations }
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
        // Fused, so a host found at a v4 address and at link-local v6 ones is one
        // device. The rule, and why two v4 records never fuse, is on `Device.fusing`.
        let devices = Device.fusing(facts.values
            .map {
                Device(
                    observing: $0,
                    in: target.network,
                    firstSeen: firstSeen[$0.ip] ?? finishedAt,
                    lastSeen: finishedAt,
                    scanStart: scanStart
                )
            })

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
                ),
                neighborWatch: discovery.neighborWatch,
                reach: (discovery.reach ?? target.reach).map {
                    ReachReport(plan: $0, found: Set(devices.flatMap(\.ipv4Addresses)), historyRead: true)
                }
            ),
            devices: devices,
            degradations: degradations
        )

        let events = await store.record(report)
        return CompletedScan(report: report, events: events)
    }

    /// Sweeps only `addresses`, waiting `wait` for each, and extends the latest run with
    /// whatever answers.
    ///
    /// "Where's my phone?" A scan ends when the addresses history expects have had their
    /// wait; a phone in deep power save can need longer than any wait worth imposing on
    /// every scan. This asks again, of those addresses only, for as long as the person is
    /// willing to wait — and what it finds belongs to the run it extends, not to a new
    /// one. A new run of six addresses would mark the rest of the network absent, the bug
    /// `recordPorts` was built to avoid. See `HistoryStore.recordExtension`.
    ///
    /// The sweep is the ordinary ICMP sweep with a `.fixed(wait)` plan over the named
    /// addresses (`ScanTarget.addresses`), so every address gets `wait` and the attempts
    /// that wait earns, spread across it. No naming, no ports: a found device keeps the
    /// names and ports history already holds.
    ///
    /// - Parameters:
    ///   - addresses: what to ask again — usually the latest run's `expected_missing`.
    ///     Addresses outside the latest run's network are ignored.
    ///   - wait: how long each address is waited for, from its first transmission.
    ///   - settings: the constants behind the attempt count. The command line passes the
    ///     ones its flags set.
    ///   - progress: display only.
    /// - Returns: what was found, what is still missing, and the events. With no run to
    ///   extend, nothing is swept and `runID` is nil.
    public func lookLonger(
        _ addresses: [IPv4Address],
        wait: Duration,
        settings: ReachSettings = ReachSettings(),
        progress: ProgressSink = .ignore
    ) async -> CompletedExtension {
        guard let run = await store.latestRun() else {
            return CompletedExtension(
                runID: nil, found: [], missing: addresses, events: [],
                discovery: DiscoveryResult(hosts: [], degradations: [Degradation(
                    stage: .setup,
                    reason: "There is no earlier scan to look longer for, so nothing was swept.",
                    recoverable: true
                )], outcome: .complete)
            )
        }
        // F5 (questions, Q12): the latest run's network only means something on the link
        // it was scanned from. A runner on another interface would read a neighbour table
        // that knows nothing of it and report everyone still missing, as though it had
        // looked. So it says why and sweeps nothing.
        guard run.interface == interface.name else {
            return CompletedExtension(
                runID: run.id, found: [], missing: addresses, events: [],
                discovery: DiscoveryResult(hosts: [], degradations: [Degradation(
                    stage: .setup,
                    reason: "The latest scan went out of \(run.interface), and this one would ask on \(interface.name), which cannot see that network. Nothing was swept.",
                    recoverable: false
                )], outcome: .complete)
            )
        }
        let asked = Array(Set(addresses.filter(run.target.contains))).sorted()
        guard !asked.isEmpty else {
            return CompletedExtension(
                runID: run.id, found: [], missing: [], events: [],
                discovery: DiscoveryResult(hosts: [], outcome: .complete)
            )
        }
        let plan = ReachPlan(policy: .fixed(wait), settings: settings)
        let target = ScanTarget(
            network: run.target, interface: interface, addresses: asked, reach: plan
        )
        // The wait, plus the slack a sweep needs to open its socket and read the table
        // twice; the plan, not this, is what ends it.
        let deadline = Deadline(after: wait + .seconds(2))
        let discovery = await scanner.discovery.discover(target, deadline: deadline, progress: progress)
        // The sweep reports table-only hosts anywhere in the network; only the asked
        // addresses are this extension's business.
        let wanted = Set(asked)
        let hosts = discovery.hosts.filter { wanted.contains($0.ip) }
        let firstSeen = await store.firstSeen(for: hosts, in: run.target)
        let now = Timestamp.now
        let devices = hosts.map {
            Device(observing: $0, in: run.target, firstSeen: firstSeen[$0.ip] ?? now, lastSeen: now)
        }
        let events = await store.recordExtension(devices, of: run.id)
        let answered = Set(hosts.map(\.ip))
        return CompletedExtension(
            runID: run.id, found: devices,
            missing: asked.filter { !answered.contains($0) },
            events: events, discovery: discovery
        )
    }

    /// Probes ports on addresses already known, and keeps what answered — without a run.
    ///
    /// The other half of `HistoryStore.recordPorts`. A port probe of one device used to go
    /// through `run`, which records a run, and a run of one address made every other device
    /// read as gone; the app's answer was a store that refused to record, which kept the
    /// network honest and lost the ports at relaunch. This never discovers, never names,
    /// and never records a run: it probes, then folds the ports into the devices history
    /// already holds.
    ///
    /// - Parameters:
    ///   - addresses: what to probe. Discovery is not run, so an address that answers no
    ///     ping is still probed.
    ///   - spec: which ports. Defaults to the common set the deep stage uses.
    ///   - budget: the total time allowed.
    ///   - progress: display only.
    /// - Returns: what the engine observed, and the port events history derived from it.
    ///   Never throws; a deadline and a cancellation are normal returns.
    public func probePorts(
        _ addresses: [IPAddress],
        spec: PortSpec = .commonServices,
        budget: Duration,
        progress: ProgressSink
    ) async -> CompletedPortScan {
        let result = await scanner.ports.scan(
            addresses, ports: spec,
            // The ceiling `run` uses; the engine narrows it per host.
            perHostDeadline: .milliseconds(600),
            deadline: Deadline(after: budget),
            progress: progress
        )
        let events = await store.recordPorts(result, targeted: addresses, at: .now)
        return CompletedPortScan(result: result, events: events)
    }
}

/// What a port probe observed, plus the events history derived from it.
public struct CompletedPortScan: Sendable {
    /// What the engines observed, by host.
    public var result: PortScanResult
    /// The port events it implied for the devices history holds. Never a presence event.
    public var events: [DerivedEvent]

    /// Creates a value from its fields.
    public init(result: PortScanResult, events: [DerivedEvent]) {
        self.result = result
        self.events = events
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
    ///
    /// On iPadOS there is no helper to try, so it is `.directOnly`, which there means
    /// no capture device at all.
    public static var fromEnvironment: CapturePolicy {
        #if os(macOS)
        ProcessInfo.processInfo.environment["ZHEN_CAPTURE"] == "direct"
            ? .directOnly : .helperThenDirect
        #else
        .directOnly
        #endif
    }
}

#endif
