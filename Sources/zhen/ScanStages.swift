// ScanStages.swift — the seven jobs `ScanPipeline.run` was doing in one function body.
//
// `IPV6-plan.md`'s code-quality section names this as the single responsibility
// violation in the codebase, and the reason it matters is not tidiness:
//
//     every capability on the roadmap adds another branch to it. IPv6 adds two,
//     Linux adds one, VLAN adds one. Fix it before, not after.
//
// ── Why stages RETURN a context rather than mutate one ────────────────────────
//
// `inout` across an `await` is legal and is a trap waiting for the first stage that
// wants to run concurrently with another. Returning a value keeps each stage a pure
// function of what came before it, which is also what makes a stage testable without
// standing up the whole pipeline.
//
// ── What this deliberately does NOT do ────────────────────────────────────────
//
// It does not reorder anything, skip anything, or tidy a guard. B1's gate is that the
// artifact is byte-identical before and after, and the fastest way to fail it is to
// improve something on the way past. The local-hardware patch in particular stays
// INSIDE the naming stage rather than becoming the eighth stage the plan's seven-job
// count implies: its guard is naming's guard, and naming can set `outcome` to
// `.cancelled`, so a separate stage re-evaluating that condition would run in cases the
// original did not.

import Foundation
import ZhenCore

/// Everything a stage reads and everything it may change.
///
/// The target and the deadline are fixed for the run; everything else accumulates.
nonisolated struct ScanContext: Sendable {
    let target: ScanTarget
    let deadline: Deadline

    var facts: [IPv4Address: HostFacts] = [:]
    /// IPv6 neighbours from the kernel's cache, on the scanned interface. Kept apart from
    /// `facts` because `HostFacts` is one v4 address; these meet the v4 hosts at report
    /// assembly, through `Device.fusing`.
    var ipv6Neighbors: [IPv6NeighborEntry] = []
    /// The `ff02::1` solicitation, started beside the v4 sweep and collected after it.
    var solicitation: Task<IPv6Solicitation, Never>?
    /// Closes the solicitation's window. `IPv6NeighborStage` yields it once the v4 sweep
    /// has ended (F8).
    var closeSolicitation: AsyncStream<Void>.Continuation?
    /// The window the solicitation was asked for, for `run.ipv6_window`.
    var ipv6Window: IPv6Window = .default
    /// `run.ipv6_window`. Nil when there is no IPv6 engine: nothing was sent and nothing
    /// failed, so there is no window to report.
    var ipv6WindowReport: IPv6WindowReport?
    /// Every v6 address that answered an echo this scan sent. Their devices are reported
    /// as `probe_reply` rather than `neighbor_table`: the cache only supplied the MAC.
    var ipv6Responders: Set<IPv6Address> = []
    var stages: [StageTiming] = []
    var degradations: [Degradation] = []
    var outcome: Outcome = .complete
    /// Carried from the engines rather than restated. Peak concurrency is the one number
    /// in the artifact that describes the SCANNER rather than the network, and it is only
    /// worth anything if it is measured.
    var peakConcurrency: Int = 0
    /// Every capability any stage actually exercised, not only discovery's.
    var exercised: EngineCapabilities = []
    /// What the discovery sweep's neighbour watch did, for `run.neighbor_watch`.
    var neighborWatch: NeighborWatchReport?
    /// The reach plan as the sweep resolved it at its start, for `run.reach`. Nil when
    /// no engine read it; the report then falls back to the target's.
    var reach: ReachPlan?

    /// The hosts, in the order every stage iterates them.
    var sortedAddresses: [IPv4Address] { facts.keys.sorted() }
}

/// One job in a scan.
nonisolated protocol ScanStage: Sendable {
    func run(_ context: ScanContext) async -> ScanContext
}

// MARK: - The stages

/// Reads the IPv6 neighbour cache for the scanned interface.
///
/// No `StageTiming`: it sends nothing and takes a sysctl's worth of time, and a stage in
/// the artifact's `stages` is a claim that probing happened. A failure to read the cache
/// is a degradation, not an error — the scan is complete without it, as it was before.
/// D2′: one echo to `ff02::1`, started before the v4 sweep so its window runs inside the
/// sweep's rather than after it. Collected by `IPv6NeighborStage`.
///
/// F8: the window used to be a fixed 2 s, and the scan waited for it, so every scan lasted
/// about 2 s however fast its sweep was (questions, Q18). By default it now closes when
/// the v4 sweep ends, but no sooner than 500 ms (2.5× the slowest reply P2 saw, a
/// sleeping phone's radio at 200 ms) and no later than 2 s (`IPv6Window.default`).
nonisolated struct IPv6SolicitationStage: ScanStage {
    let echo: any IPv6MulticastEcho
    var window: IPv6Window = .default

    func run(_ context: ScanContext) async -> ScanContext {
        var context = context
        context.ipv6Window = window
        // `--ipv6-window 0`: no echo. The neighbour cache is still read.
        guard let bounds = window.bounds else { return context }
        let echo = echo
        let interface = context.target.interface.name
        let remaining = context.deadline.remaining
        let floor = min(bounds.floor, remaining)
        let cap = min(bounds.cap, remaining)
        let (closing, close) = AsyncStream<Void>.makeStream()
        context.closeSolicitation = close
        context.solicitation = Task {
            await echo.solicitAllNodes(on: interface, floor: floor, cap: cap, closing: closing)
        }
        return context
    }
}

nonisolated struct IPv6NeighborStage: ScanStage {
    let cache: any IPv6NeighborCache
    var echo: any IPv6MulticastEcho = NoIPv6MulticastEcho()

    func run(_ context: ScanContext) async -> ScanContext {
        var context = context
        let interface = context.target.interface.name
        // This stage runs right after discovery, so the v4 sweep has ended: close the
        // window. The floor and the cap are the echo's to apply.
        context.closeSolicitation?.yield()
        context.closeSolicitation?.finish()
        let solicitation = await context.solicitation?.value ?? IPv6Solicitation()
        if context.solicitation == nil, context.ipv6Window == .off {
            context.ipv6WindowReport = IPv6WindowReport(window: .off, listened: nil)
        } else if solicitation.sent > 0 || solicitation.failure != nil {
            context.ipv6WindowReport = IPv6WindowReport(window: context.ipv6Window, listened: solicitation.listened)
        }
        if let failure = solicitation.failure {
            context.degradations.append(Degradation(
                stage: .discovery,
                reason: "The IPv6 all-nodes echo could not be sent (\(failure)), so hosts that only IPv6 reaches were not asked.",
                recoverable: true
            ))
        }
        let responders = solicitation.responders
        var followedUp = 0, followUpReplies = 0

        do {
            var entries = try await neighbours(on: interface)
            // A responder the cache has no MAC for cannot be joined to its v4 device, and
            // reporting it alone risks the one failure Q2's gate names: a host counted
            // twice. A unicast echo makes the kernel resolve it; then read again.
            let known = Set(entries.map(\.address))
            let unknown = responders.filter { !known.contains($0) }
            if !unknown.isEmpty, !context.deadline.isExpired {
                let budget = min(Duration.seconds(1), context.deadline.remaining)
                let echo = echo
                followUpReplies = await withTaskGroup(of: Bool.self) { group in
                    for address in unknown {
                        group.addTask { await echo.echo(address, on: interface, within: budget) }
                    }
                    var count = 0
                    for await replied in group where replied { count += 1 }
                    return count
                }
                followedUp = unknown.count
                entries = try await neighbours(on: interface)
            }
            let learned = Set(entries.map(\.address))
            let unmatched = responders.filter { !learned.contains($0) }
            if !unmatched.isEmpty {
                let one = unmatched.count == 1
                context.degradations.append(Degradation(
                    stage: .discovery,
                    reason: "\(unmatched.count) host\(one ? "" : "s") answered over IPv6 but "
                        + "the neighbour cache never learned \(one ? "its" : "their") hardware "
                        + "address, so \(one ? "it" : "they") cannot be matched to a v4 device "
                        + "and \(one ? "is" : "are") not reported: "
                        + unmatched.map(\.description).joined(separator: ", ") + ".",
                    recoverable: true
                ))
            }
            context.ipv6Neighbors = entries
        } catch {
            context.degradations.append(Degradation(
                stage: .discovery,
                reason: "The IPv6 neighbour cache could not be read (\(error)), so hosts known only over IPv6 are missing and no device carries a v6 address.",
                recoverable: true
            ))
        }
        context.ipv6Responders = Set(responders)

        // The packets are discovery's, so they are counted in its stage rather than in a
        // stage of their own that every schema-3 reader would have to learn the name of.
        let sent = solicitation.sent + followedUp
        if sent > 0, let index = context.stages.firstIndex(where: { $0.stage == .discovery }) {
            context.stages[index].probesSent += sent
            context.stages[index].repliesSeen += responders.count + followUpReplies
        }
        return context
    }

    private func neighbours(on interface: String) async throws(PlatformError) -> [IPv6NeighborEntry] {
        try await cache.ipv6Entries().filter {
            // This machine's own addresses are permanent entries; they are not
            // neighbours, and reporting them would add this Mac to its own scan.
            !$0.isPermanent && $0.address.zone == interface
        }
    }
}

/// What the engines said at construction, before anything ran.
nonisolated struct EngineNoticesStage: ScanStage {
    let notices: [Degradation]
    let renderer: any Renderer

    func run(_ context: ScanContext) async -> ScanContext {
        var context = context
        for notice in notices {
            context.degradations.append(notice)
            renderer.handle(.degraded(notice))
        }
        return context
    }
}

/// The sweep.
nonisolated struct DiscoveryStage: ScanStage {
    let engine: any HostDiscovery
    let renderer: any Renderer

    func run(_ context: ScanContext) async -> ScanContext {
        // The display is fed by a lossy stream; the artifact comes back as a value.
        let (events, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let target = context.target
        let deadline = context.deadline
        let renderer = renderer
        let engine = engine
        let discovery = await withTaskGroup(of: DiscoveryResult?.self) { group in
            group.addTask {
                // Display only. Every event here is allowed to be dropped, which is
                // precisely why the artifact does not come from here.
                for await event in events { renderer.handle(event) }
                return nil
            }
            group.addTask {
                let result = await engine.discover(target, deadline: deadline, progress: sink)
                finish()
                return result
            }
            var found: DiscoveryResult?
            for await value in group where value != nil { found = value }
            return found ?? DiscoveryResult()
        }

        var context = context
        context.degradations.append(contentsOf: discovery.degradations)
        // Assigned, not merged: discovery is the first stage to produce any of these.
        context.facts = Dictionary(uniqueKeysWithValues: discovery.hosts.map { ($0.ip, $0) })
        context.stages = discovery.timing.stages
        context.outcome = discovery.outcome
        context.peakConcurrency = discovery.timing.peakConcurrency
        context.exercised = discovery.usedCapabilities
        context.neighborWatch = discovery.neighborWatch
        context.reach = discovery.reach
        return context
    }
}

/// Names, the hosts only a name source heard from, and this machine's own hardware.
///
/// Between discovery and the deep scan, and unconditional: a device list without names is
/// a list of addresses, which is the thing this tool exists not to produce. It takes its
/// own slice of what is left and never the whole of it, so `--deep` still has a budget.
///
/// Under `--discovery-only` the stage is not started, so nothing is appended to `stages`
/// and the naming entry is ABSENT from the artifact rather than present and zeroed. A
/// stage that ran and found nothing is a different fact from a stage that never ran.
nonisolated struct NamingStage: ScanStage {
    let engine: any NameResolving
    let renderer: any Renderer
    let discoveryOnly: Bool

    func run(_ context: ScanContext) async -> ScanContext {
        guard !discoveryOnly, !context.facts.isEmpty,
              context.outcome == .complete, !context.deadline.isExpired
        else { return context }

        let resolution = await engine.resolveNames(
            for: context.sortedAddresses,
            on: context.target,
            deadline: context.deadline,
            progress: ProgressSink { renderer.handle($0) }
        )

        var context = context
        for (ip, candidates) in resolution.names {
            if var host = context.facts[ip] {
                // Every candidate, winners and losers. The "Known by" panel is built
                // entirely out of the losers, and the cascade picks the winner at read
                // time — so appending them all is not laziness, it is the feature.
                host.allNames = (host.allNames + candidates).sorted()
                context.facts[ip] = host
                renderer.handle(.hostUpdated(host))
            } else if context.target.network.contains(ip) {
                // A host the sweep never heard from, that a name source did. It is real
                // — a Bonjour address record and an SSDP or NBSTAT datagram are all
                // positive evidence — and dropping it would report the network as
                // emptier than it is for the sake of tidy stage boundaries.
                let host = HostFacts(ip: ip, allNames: Array(candidates), foundAt: .now)
                context.facts[ip] = host
                renderer.handle(.hostFound(host))
            }
        }
        for (ip, mac) in resolution.hardware where context.facts[ip]?.mac == nil {
            context.facts[ip]?.mac = mac
        }
        // This machine's own hardware address, for the row the loopback remap created.
        // Bonjour resolves the local host to 127.0.0.1 and the ledger remaps it onto the
        // scanning interface's address — but the sweep deliberately leaves its own
        // address out of the neighbour-derived hosts, so without this the one device we
        // know the most about is the one row with no MAC in it.
        //
        // Inside this stage on purpose. See the file header: its guard is this stage's
        // guard, and naming can set `outcome`, so a separate stage would re-evaluate a
        // condition that has already moved.
        if context.facts[context.target.interface.address]?.mac == nil,
           let hardware = context.target.interface.hardwareAddress {
            context.facts[context.target.interface.address]?.mac = hardware
        }
        context.stages.append(resolution.timing)
        context.degradations.append(contentsOf: resolution.degradations)
        if resolution.outcome == .cancelled { context.outcome = .cancelled }
        return context
    }
}

/// Says so when `--deep` was asked for and the port stage will not run.
///
/// This guard used to be silent. A partial discovery skipped port scanning entirely — no
/// degradation, no stage entry, nothing in the artifact saying the stage had been asked
/// for and declined — and the port matrix made the silence visible for the first time:
/// every cell became a dash with nothing explaining why.
nonisolated struct DeepScanRefusalStage: ScanStage {
    let deep: Bool
    let renderer: any Renderer

    func run(_ context: ScanContext) async -> ScanContext {
        guard deep, !context.facts.isEmpty,
              !(context.outcome == .complete && !context.deadline.isExpired)
        else { return context }

        let cause = context.deadline.isExpired
            ? "the scan's budget was spent before it could start"
            : "discovery did not finish (\(context.outcome.rawValue))"
        let skipped = Degradation(
            stage: .deepScan,
            reason: "Ports were not scanned: \(cause). "
                + "The hosts are reported from discovery alone, so nothing here says "
                + "whether a port is open, closed or filtered — that is absent because "
                + "it was not attempted, not because nothing answered.",
            recoverable: true)
        var context = context
        context.degradations.append(skipped)
        // Appended AND handed to the renderer. Without the second half it reaches the
        // artifact and never the terminal, and a person running `--deep` sees a device
        // table with no ports and nothing saying why.
        renderer.handle(.degraded(skipped))
        return context
    }
}

/// The port scan.
nonisolated struct PortScanStage: ScanStage {
    let engine: any PortScanning
    let renderer: any Renderer
    let deep: Bool
    let ports: PortSpec

    func run(_ context: ScanContext) async -> ScanContext {
        guard deep, !context.facts.isEmpty,
              context.outcome == .complete, !context.deadline.isExpired
        else { return context }

        let (portEvents, portSink, portFinish) = ProbeStream.sinking(buffering: .progress)
        let targets = context.sortedAddresses.map(IPAddress.v4)
        let deadline = context.deadline
        let renderer = renderer
        let engine = engine
        let ports = ports
        let result = await withTaskGroup(of: PortScanResult?.self) { group in
            group.addTask {
                for await event in portEvents { renderer.handle(event) }
                return nil
            }
            group.addTask {
                let scanned = await engine.scan(
                    targets,
                    ports: ports,
                    // A ceiling, not a fixed wait: the engine narrows it per host from
                    // that host's own measured round trips.
                    perHostDeadline: .milliseconds(600),
                    deadline: deadline,
                    progress: portSink
                )
                portFinish()
                return scanned
            }
            var found: PortScanResult?
            for await value in group where value != nil { found = value }
            return found ?? PortScanResult()
        }

        var context = context
        for (ip, observations) in result.ipv4Hosts { context.facts[ip]?.ports = observations }
        for (ip, fingerprint) in result.fingerprints {
            context.facts[ip]?.osFingerprint = fingerprint
        }
        context.exercised.formUnion(result.usedCapabilities)
        context.stages.append(contentsOf: result.timing.stages)
        context.degradations.append(contentsOf: result.degradations)
        if result.outcome != .complete { context.outcome = result.outcome }
        context.peakConcurrency = max(context.peakConcurrency, result.timing.peakConcurrency)
        return context
    }
}
