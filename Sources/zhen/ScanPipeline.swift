// ScanPipeline.swift — the scan, separated from argument parsing so it can be tested.
//
// ── The restructure this file exists for ────────────────────────────────────────
//
// An earlier version built the artifact out of the progress stream: it iterated
// `discovery.stream(...)` and accumulated devices, degradations and stage timings from
// the events it saw. That stream is `.bufferingNewest(4096)` by design, and core's own
// `ProbeStream` header says in as many words that the lossy policy is only safe because
// results travel in the terminal envelope and never in the progress channel.
//
// So the failure was not hypothetical. A large scan with a slow consumer — a terminal
// redrawing, an encoder running, anything — silently drops events, and a dropped
// `hostFound` is a device missing from a report that still says `outcome: complete`.
// The one artifact a user is meant to trust would have been quietly wrong, in the
// direction of claiming more certainty than it had.
//
// Now: `discover(_:deadline:progress:)` runs the sweep once and returns the complete
// envelope, while feeding the display through a sink whose events may be dropped
// freely. The renderer consumes the lossy side; the report is built from the return
// value. Nothing the display misses can reach the artifact.

import Foundation
import ZhenCore

/// Runs one scan and produces the artifact.
nonisolated struct ScanPipeline {
    /// The platform's engines.
    var scanner: PlatformScanner
    /// Where events and the finished report go.
    var renderer: any Renderer
    /// Whether to skip naming entirely.
    ///
    /// The fast path: what is on the network, not what it is called. It also exists
    /// because a timing comparison against a discovery-only scanner is meaningless
    /// otherwise — see `Study/PROTOCOL.md` section 2, where the matched configuration
    /// for H1 through H3 requires it.
    var discoveryOnly: Bool = false
    /// Whether to run the port stage.
    var deep: Bool
    /// Which ports, if `deep`.
    var ports: PortSpec
    /// Where this run is remembered, when there is anywhere to remember it.
    ///
    /// Optional because a scan with nowhere to write history is still a scan. The
    /// alternative — refusing to run over a missing home directory — would be the tool
    /// deciding its filing matters more than its job.
    var history: (any HistoryStore)?
    /// Whether history was read to build the plan, for `run.reach.history_read`.
    var historyRead: Bool = true
    /// The build, for `run.tool`. This binary's own unless a test pins it: the commit
    /// changes with every build, and a byte-for-byte gate cannot compare against that.
    var tool: RunTool? = ScanPipeline.buildTool

    /// This binary: `zhen`, its version, and the commit it was stamped with.
    static var buildTool: RunTool {
        RunTool(name: "zhen", version: Version.current, commit: Version.commit)
    }

    /// What the scan produced.
    struct Completed {
        /// The artifact.
        var report: ScanReport
        /// What the process should exit with.
        var status: ExitStatus
    }

    /// Runs the scan.
    ///
    /// - Parameters:
    ///   - target: what to scan.
    ///   - budget: the total time allowed.
    ///   - startedAt: the wall-clock stamp for the run, supplied so a test can pin it.
    ///   - runID: the run's identifier, likewise.
    func run(
        target: ScanTarget,
        budget: Duration,
        startedAt: Timestamp = .now,
        runID: UUID = UUID()
    ) async -> Completed {
        // Every host's `found_after_millis` is measured from here.
        let scanStart = MonotonicInstant.now
        // ── The stages ───────────────────────────────────────────────────────────
        //
        // Each is a function of the context that came before it. Adding a capability —
        // IPv6 adds two, Linux one, VLAN one — is a row in this array rather than
        // another branch in this method, which is the whole point of B1.
        //
        // **Order is behaviour, and it is not alphabetical.** Naming runs between
        // discovery and the port stage because it takes its slice of the budget first,
        // and the refusal notice runs before the port stage because it describes the
        // port stage not running. Reordering these changes the `stages` array in the
        // artifact, which is what the B1 gate catches.
        let pipeline: [any ScanStage] = [
            EngineNoticesStage(notices: scanner.notices, renderer: renderer),
            IPv6SolicitationStage(echo: scanner.ipv6Multicast),
            DiscoveryStage(engine: scanner.discovery, renderer: renderer),
            IPv6NeighborStage(cache: scanner.ipv6Neighbors, echo: scanner.ipv6Multicast),
            NamingStage(engine: scanner.naming, renderer: renderer,
                        discoveryOnly: discoveryOnly),
            DeepScanRefusalStage(deep: deep, renderer: renderer),
            PortScanStage(engine: scanner.ports, renderer: renderer,
                          deep: deep, ports: ports),
        ]

        var context = ScanContext(target: target, deadline: Deadline(after: budget))
        for stage in pipeline { context = await stage.run(context) }

        let facts = context.facts
        let ipv6Neighbors = context.ipv6Neighbors
        let ipv6Responders = context.ipv6Responders
        var stages = context.stages
        let degradations = context.degradations
        let outcome = context.outcome
        let peak = context.peakConcurrency
        let exercised = context.exercised

        // A stage that was interrupted before it reported itself still took time.
        // Reporting zero elapsed over a device list that plainly has entries in it
        // would be a lie in the one field meant to be checkable.
        if stages.isEmpty {
            stages.append(StageTiming(stage: .discovery, elapsedMillis: 0))
        }

        let finishedAt = Timestamp.now
        let timing = Timing(
            stages: stages,
            counters: ProbeCounterSnapshot(
                probesSent: stages.reduce(0) { $0 + $1.probesSent },
                repliesSeen: stages.reduce(0) { $0 + $1.repliesSeen },
                peakConcurrency: peak,
                inFlight: 0
            )
        )
        // Asked BEFORE the devices are built, and that ordering is the whole reason
        // the protocol has this method. `Device(observing:)` takes first-seen at
        // construction and defaults it to last-seen, which is right on a first-ever run
        // and silently wrong on every one after it — a device seen for a year would
        // claim to have arrived just now, and nothing would look wrong.
        let firstSeen = await history?.firstSeen(
            for: Array(facts.values), in: target.network
        ) ?? [:]
        // Fused, so a host found at a v4 address and at link-local v6 ones is one
        // device. The rule, and why two v4 records never fuse, is on `Device.fusing`.
        // The IPv6 cache's entries join here: an address whose MAC also answered on v4
        // becomes one more address of that device; one whose MAC did not is a device of
        // its own, reported with the cache as its only source.
        let devices = Device.fusing(facts.values
            .map {
                Device(
                    observing: $0, in: target.network,
                    firstSeen: firstSeen[$0.ip] ?? finishedAt, lastSeen: finishedAt,
                    scanStart: scanStart
                )
            } + ipv6Neighbors.map {
                Device(neighbor: $0, seen: finishedAt,
                       answeredEcho: ipv6Responders.contains($0.address))
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
                    // What was actually exercised, not what was advertised. A denied
                    // permission shows up here as a capability the engine claims and
                    // did not use.
                    capabilities: exercised
                ),
                outcome: outcome,
                mode: discoveryOnly ? .discoveryOnly : .full,
                timing: timing,
                neighborWatch: context.neighborWatch,
                reach: (context.reach ?? target.reach).map {
                    ReachReport(
                        plan: $0, found: Set(devices.flatMap(\.ipv4Addresses)),
                        historyRead: historyRead && history != nil
                    )
                },
                tool: tool
            ),
            devices: devices,
            degradations: degradations
        )
        // Recorded before the report is handed over, so a caller reading history
        // immediately after a scan sees this run in it. Its events are not rendered
        // here: `zhen events` is where the log is read, and a scan that printed a
        // timeline as well as a device table would be two commands wearing one name.
        _ = await history?.record(report)

        renderer.finish(report)
        return Completed(report: report, status: Self.status(for: report))
    }

    /// Asks again, for `wait`, about the latest run's expected-missing addresses, and
    /// extends that run with what answers.
    ///
    /// Discovery only, through the same stage a scan uses, so the display and the timing
    /// are a scan's. The artifact is a `ScanReport` of the extension: its own run id,
    /// `extends_run` naming the run it extended, the devices it found, and `run.reach`
    /// with `policy: fixed` and whoever is still missing. It is folded into history with
    /// `recordExtension`, never `record` — it is not a run, and recording it as one would
    /// mark everyone it did not ask about as gone.
    func lookLonger(
        extending latest: ScanRun, interface: NetworkInterface, wait: Duration,
        settings: ReachSettings, budget: Duration,
        startedAt: Timestamp = .now, runID: UUID = UUID()
    ) async -> Completed {
        let scanStart = MonotonicInstant.now
        let asked = latest.reach?.expectedMissing.filter(latest.target.contains) ?? []
        let plan = ReachPlan(policy: .fixed(wait), settings: settings, expected: Set(asked))
        var context = ScanContext(
            target: ScanTarget(network: latest.target, interface: interface, addresses: asked, reach: plan),
            deadline: Deadline(after: budget)
        )
        if !asked.isEmpty {
            let stages: [any ScanStage] = [
                EngineNoticesStage(notices: scanner.notices, renderer: renderer),
                DiscoveryStage(engine: scanner.discovery, renderer: renderer),
            ]
            for stage in stages { context = await stage.run(context) }
        }
        let wanted = Set(asked)
        let facts = context.facts.values.filter { wanted.contains($0.ip) }
        let finishedAt = Timestamp.now
        let firstSeen = await history?.firstSeen(for: Array(facts), in: latest.target) ?? [:]
        let devices = facts
            .map {
                Device(
                    observing: $0, in: latest.target,
                    firstSeen: firstSeen[$0.ip] ?? finishedAt, lastSeen: finishedAt,
                    scanStart: scanStart
                )
            }
            .sorted { $0.primaryAddress < $1.primaryAddress }
        let stages = context.stages.isEmpty
            ? [StageTiming(stage: .discovery, elapsedMillis: 0)] : context.stages
        let report = ScanReport(
            run: ScanRun(
                id: runID,
                startedAt: startedAt,
                finishedAt: finishedAt,
                target: latest.target,
                interface: interface.name,
                engine: EngineDescriptor(
                    name: scanner.discovery.descriptor.name,
                    kind: scanner.discovery.descriptor.kind,
                    capabilities: context.exercised
                ),
                outcome: context.outcome,
                mode: .discoveryOnly,
                timing: Timing(
                    stages: stages,
                    counters: ProbeCounterSnapshot(
                        probesSent: stages.reduce(0) { $0 + $1.probesSent },
                        repliesSeen: stages.reduce(0) { $0 + $1.repliesSeen },
                        peakConcurrency: context.peakConcurrency,
                        inFlight: 0
                    )
                ),
                neighborWatch: context.neighborWatch,
                reach: ReachReport(
                    plan: context.reach ?? plan, found: Set(devices.flatMap(\.ipv4Addresses)), historyRead: true
                ),
                extendsRun: latest.id,
                tool: tool
            ),
            devices: devices,
            degradations: context.degradations
        )
        _ = await history?.recordExtension(devices, of: latest.id)
        renderer.finish(report)
        return Completed(report: report, status: Self.status(for: report))
    }

    /// The process exit code for a finished run.
    ///
    /// Derived from the degradations as well as the outcome. An earlier version read
    /// only the termination reason, which made exit 69 unreachable at runtime: the
    /// engine detected a denied Local Network permission, emitted the degradation, the
    /// CLI wrote it into the report — and then exited 0 with an empty device list, so
    /// a script had no way to tell a denied permission from an empty network.
    ///
    /// A recoverable degradation does not change the status. Those are things that went
    /// wrong and may not next time — a busy BPF node, an unreadable ARP table — and a
    /// scan that otherwise worked should not report failure for them.
    static func status(for report: ScanReport) -> ExitStatus {
        if report.degradations.contains(where: { !$0.recoverable }) { return .unavailable }
        return report.run.outcome.status
    }
}
