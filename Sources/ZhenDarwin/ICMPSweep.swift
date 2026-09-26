// ICMPSweep.swift — the discovery engine, and where the speed claim is actually made.
//
// The structure is: send to everything, listen, retransmit what did not answer, stop.
// What makes it fast is not the sending — any scanner can send fast — it is how long it
// is willing to wait, and that is where a conventional scanner loses on a LAN.
//
// nmap waits a fixed interval per host, tuned for the internet. On a quiet /24 where
// live hosts answer in a few hundred microseconds, almost the whole wall clock is spent
// waiting out that interval on the two hundred addresses where nothing exists. So this
// sweep does not use a fixed interval: it measures, with `RTTEstimator`, and the wait
// collapses toward the real round trip as soon as the first few hosts answer.
//
// ── Two budgets, because there are two questions ─────────────────────────────────
//
// A single timeout was answering both of them and doing neither well. Splitting it is
// arithmetic, not taste:
//
//   RETRANSMIT — "how long before I ask again?" A lost frame costs one packet to
//   resend, so being wrong here is cheap and the budget should be tight. It is driven
//   from a LOW quantile of observed round trips, and it is paid once per retransmission
//   per address: 244 dead addresses × 2 retransmissions, so every millisecond of it
//   costs 488 milliseconds of nothing.
//
//   TAIL — "how long before I say nobody is home?" This one genuinely needs the tail of
//   the distribution, because the slowest live host on the network defines it. But it
//   is asked ONCE, at the end, and it overlaps every address simultaneously — so the
//   sweep pays it a single time rather than once per attempt per host.
//
// The previous version used one number for both: the network estimator's srtt + 4·rttvar,
// which tracks the maximum, applied as the expiry of every individual probe. With a
// 600 ms host on the network that pinned it near the ceiling, and 244 dead addresses
// each waited it out three times — roughly 3 × 600 ms of wall clock spent on addresses
// that were never going to answer, to accommodate one host that answers in 600 ms once.
//
// Keeping expired probes matchable is what makes the tail window safe. A probe whose
// retransmit window closed is not forgotten; its token still identifies exactly which
// transmission a late reply answers, so a straggler arriving during the tail is timed
// correctly rather than counted as a stray.
//
// Note what the per-host estimator can and cannot do here. It cannot inform the
// retransmit schedule, because a host that has never answered has no per-host history —
// and "hosts that have not answered" is precisely the population discovery is asking
// about. Network-wide quantiles are the only prior available. The per-host estimates
// earn their keep in the artifact and in the port scan, where the host has by then
// demonstrably answered something.
//
// The timeout is PER HOST, and that is the part that matters. An earlier version ran a
// single global round wait, which meant the sweep waited the same interval for every
// address — so a 180 ms Wi-Fi device on a network whose other hosts answer in 0.4 ms
// was missed on every single run, deterministically, because the global wait had
// converged on the fast majority. Each host now carries its own `RTTEstimator` and its
// own expiry, and a host is retransmitted when ITS timeout passes, not when a round
// ends.
//
// Two estimators, doing different jobs:
//
//   * a per-host estimator sets that host's timeout and produces the RTT in the
//     artifact. It is the whole adaptive mechanism.
//   * a network-wide estimator seeds the FIRST probe to a host, which by definition has
//     no history. With no samples at all it starts at `RTTEstimator.defaultInitial`;
//     after a handful of replies it is asking for a few multiples of the real round
//     trip instead of a second.
//
// Karn's rule keys off the PROBE, not the clock. Each transmission carries its own
// token and its own send instant, so a reply is attributed to the exact transmission it
// answers — a straggler from the first attempt arriving after a second has gone out is
// still a clean sample of the first, and is used. Reading a round-scoped flag at reply
// time instead, as an earlier version did, meant a sweep could accept no samples at all
// and the estimator never learned anything.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Unprivileged host discovery: an ICMP echo sweep plus the kernel's neighbour table.
public struct ICMPSweepEngine: HostDiscovery {
    /// How this engine identifies itself in the artifact.
    public let descriptor = EngineDescriptor(
        name: "unprivileged-icmp",
        kind: .unprivileged,
        capabilities: [.icmpSweep, .neighborTable]
    )

    /// How many times an unanswered address is probed before it is called silent.
    ///
    /// Three total attempts. One is too few on a LAN with any Wi-Fi in it — a single
    /// dropped frame would report a live host as absent — and beyond three the returns
    /// vanish while the wall clock does not.
    public var attempts: Int
    /// How many probes may be outstanding. Derived by the caller from the granted
    /// descriptor limit and measured RTT, never chosen.
    public var concurrency: Int
    /// Reads the ARP cache, so discovery still reports hosts when ICMP is blocked.
    public var neighbors: any NeighborCache
    /// Platform-specific remediation for the denial heuristic.
    public var advice: ProbePermissionAdvice
    /// How far apart the transmissions to one address are placed.
    ///
    /// Correction C8 of the study: three transmissions spaced by a low quantile of RTT
    /// span less than a Wi-Fi power-save outage, so one outage takes all three. See
    /// `SweepSpacing` for the measurement and for why the default costs nothing.
    public var spacing: SweepSpacing
    /// Whether the sweep's two budgets are separately chosen, and whether the
    /// retransmit interval is measured or imposed.
    ///
    /// The default splits them, which is the behaviour everything else in this file
    /// argues for. The other cases exist so that argument can be tested against the
    /// same scanner with the split removed — see ``SweepBudgets``.
    public var budgets: SweepBudgets

    /// Creates the engine.
    public init(
        attempts: Int = 3,
        concurrency: Int = 256,
        neighbors: any NeighborCache = DarwinNeighborCache(),
        advice: ProbePermissionAdvice = .appleLocalNetwork,
        spacing: SweepSpacing = .spreadIntoTail,
        budgets: SweepBudgets = .split
    ) {
        self.attempts = attempts
        self.concurrency = concurrency
        self.neighbors = neighbors
        self.advice = advice
        self.spacing = spacing
        self.budgets = budgets
    }

    /// Terminal form, with an optional observer.
    ///
    /// This is the primary implementation: it produces the complete envelope AND feeds
    /// the display, in one sweep. `stream(_:deadline:)` is built on top of it. The
    /// inverse arrangement — running the sweep for the stream and collecting the
    /// artifact from what the stream emitted — is what the progress channel's
    /// `.bufferingNewest` policy makes unsafe, since a slow consumer would silently
    /// drop devices out of the report.
    public func discover(
        _ target: ScanTarget, deadline: Deadline, progress: ProgressSink
    ) async -> DiscoveryResult {
        await run(target, deadline: deadline, sink: progress)
    }

    /// Streaming form: hosts as they answer.
    public func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task { [self] in
            _ = await run(target, deadline: deadline, sink: sink)
            finish()
        }
        return AsyncStream { continuation in
            Task {
                for await event in stream { continuation.yield(event) }
                continuation.finish()
            }
            // Cancelling the consumer tears the sweep down rather than leaving it
            // running with nowhere to report to. `onTermination` fires on both a normal
            // finish and a consumer walking away, which is exactly the lifetime the
            // socket needs.
            continuation.onTermination = { _ in work.cancel() }
        }
    }

    private func run(
        _ target: ScanTarget, deadline: Deadline, sink: ProgressSink
    ) async -> DiscoveryResult {
        sink(.stageStarted(.discovery))
        let watch = Stopwatch()
        let counters = ProbeCounters()
        var degradations: [Degradation] = []
        var used: EngineCapabilities = []

        // Reported in the artifact so the trade between the two budgets is checkable
        // from the output rather than taken on trust. Defaulted for the early-return
        // paths, which never got as far as measuring anything.
        var retransmitBudget = Duration.zero
        var tailBudget = Duration.zero
        var spreadBudget = Duration.zero

        func finished(
            _ hosts: [HostFacts], _ outcome: Outcome
        ) -> DiscoveryResult {
            let snapshot = counters.snapshot()
            let stage = StageTiming(
                stage: .discovery,
                elapsedMillis: watch.elapsedMillis,
                probesSent: snapshot.probesSent,
                repliesSeen: snapshot.repliesSeen,
                hostsFound: hosts.count,
                retransmitBudgetMillis: retransmitBudget > .zero ? retransmitBudget.milliseconds : nil,
                tailBudgetMillis: tailBudget > .zero ? tailBudget.milliseconds : nil,
                spacingPolicy: retransmitBudget > .zero ? spacing.name : nil,
                budgetPolicy: retransmitBudget > .zero ? budgets.name : nil,
                spreadBudgetMillis: retransmitBudget > .zero ? spreadBudget.milliseconds : nil,
                spacingJitter: retransmitBudget > .zero ? spacing.jitter : nil
            )
            sink(.stageFinished(stage))
            return DiscoveryResult(
                hosts: hosts.sorted { $0.ip < $1.ip },
                degradations: degradations,
                usedCapabilities: used,
                outcome: outcome,
                timing: Timing(stages: [stage], counters: snapshot)
            )
        }

        func degrade(_ degradation: Degradation) {
            degradations.append(degradation)
            sink(.degraded(degradation))
        }

        // A target too wide to enumerate refuses here rather than sweeping nothing and
        // reporting success. Core makes that a value; this just relays it.
        guard let addresses = target.resolution.addresses else {
            if let refusal = target.resolution.refusal { degrade(refusal) }
            return finished([], .complete)
        }

        // The neighbour table first: free, instant, needs no permission, and it is the
        // control for the denial heuristic below.
        var neighborsByIP: [IPv4Address: MACAddress] = [:]
        do {
            for entry in try await neighbors.entries() where entry.isComplete {
                guard target.network.contains(entry.ip) else { continue }
                neighborsByIP[entry.ip] = entry.mac
            }
            used.insert(.neighborTable)
        } catch {
            degrade(Degradation(
                stage: .discovery,
                reason: "The system's neighbour table could not be read, so hardware addresses and vendors will be missing.",
                recoverable: true
            ))
        }

        let socket: ICMPSocket
        do {
            socket = try ICMPSocket()
        } catch {
            degrade(Degradation(
                stage: .discovery,
                reason: "An ICMP socket could not be opened (\(error)). Only the neighbour table is available, so hosts that have not recently exchanged traffic with this machine will be missing.",
                recoverable: false
            ))
            var hosts: [HostFacts] = []
            for (ip, mac) in neighborsByIP.sorted(by: { $0.key < $1.key }) {
                let host = HostFacts(ip: ip, mac: mac)
                hosts.append(host)
                sink(.hostFound(host))
            }
            return finished(hosts, .complete)
        }

        let state = SweepState(
            pending: addresses,
            neighbors: neighborsByIP,
            attempts: attempts,
            counters: counters,
            spacing: spacing,
            budgets: budgets
        )
        let replies = await socket.replies()

        // One reader for the whole sweep, independent of the sender. Replies to the
        // first attempt keep arriving during the second and must not be discarded
        // because the attempt that sent them has ended.
        let reader = Task {
            for await reply in replies {
                if let event = await state.record(reply) { sink(event) }
            }
        }

        var attempted = 0
        var delivered = 0

        // ── Phase one: transmit, on the tight budget ────────────────────────────
        //
        // Expiry-driven. Each tick asks which probes are due — never sent, or sent and
        // past the retransmit interval — and sends exactly those. The interval is a low
        // quantile of measured round trips, so the whole transmit phase costs roughly
        // (attempts - 1) × that interval regardless of how many addresses are dead.
        while !Task.isCancelled, !deadline.isExpired {
            let due = await state.dueProbes(limit: concurrency)
            if due.isEmpty {
                if await state.isSettled { break }
                // Nothing is due yet, so sleep until something is — bounded, so a
                // cancellation or the overall deadline is still noticed promptly.
                let nap = await state.timeUntilNextExpiry() ?? .milliseconds(5)
                try? await Task.sleep(for: min(max(nap, .milliseconds(1)), .milliseconds(10)))
                continue
            }
            let sent = await socket.sendRound(due)
            for event in await state.recordSends(sent) { sink(event) }
            attempted += due.count
            delivered += sent.count
        }

        // ── Phase two: one tail wait, for the whole network at once ──────────────
        //
        // Every address has now been asked as many times as it is going to be. This is
        // the single expensive wait, and it overlaps all of them: a host that takes 600
        // milliseconds to answer its first probe is caught here, and the 244 addresses
        // that will never answer cost nothing extra because they are waiting in
        // parallel with it.
        //
        // Replies arriving now land on probes whose retransmit window has closed. They
        // are still matched exactly — the token says which transmission they answer —
        // which is what makes waiting here worth doing rather than merely patient.
        tailBudget = await state.tailBudget()
        spreadBudget = await state.spreadBudget()
        // Anchored to the last TIGHT transmission rather than to the last transmission
        // of any kind. That is the whole reason spreading the final transmission costs
        // nothing: it is sent INTO this window rather than before it, so the instant
        // the sweep stops listening is the instant it would have stopped anyway. See
        // SweepSpacing for the measurement.
        if let tailEnd = await state.declarationInstant() {
            while !Task.isCancelled, !deadline.isExpired, MonotonicInstant.now < tailEnd {
                if await state.everyoneAnswered { break }
                try? await Task.sleep(for: .milliseconds(10))
            }
        }
        retransmitBudget = await state.retransmitBudget()

        reader.cancel()
        await socket.stop()

        // Re-read the neighbour table now the sweep has finished.
        //
        // It was read once at the start, before this sweep's own probes had been sent —
        // and a probe to a host the kernel has no ARP entry for is exactly what causes
        // it to acquire one. So the first scan of a session reported hosts with no
        // hardware address that the second scan, moments later, reported with one, and
        // `identityStability` fell from `weak` to `ephemeral` purely because of scan
        // order. Two consecutive scans of an unchanged network disagreed about it.
        //
        // Cheap: one sysctl over a table of a few kilobytes, once, after all the
        // probing is done.
        if let refreshed = try? await neighbors.entries() {
            for entry in refreshed where entry.isComplete {
                guard target.network.contains(entry.ip) else { continue }
                neighborsByIP[entry.ip] = entry.mac
            }
        }

        var hosts = await state.discovered().map { host -> HostFacts in
            // Attach anything the refreshed table now knows.
            guard host.mac == nil, let mac = neighborsByIP[host.ip] else { return host }
            var updated = host
            updated.mac = mac
            return updated
        }
        let strays = await state.lateReplies
        if strays > 0 {
            // Replies arriving after their probe expired mean the per-host budgets were
            // too tight for this network, and the hosts that sent them may be reported
            // absent. Better to say so than to let the number vanish.
            degrade(Degradation(
                stage: .discovery,
                reason: "\(strays) repl\(strays == 1 ? "y" : "ies") arrived after the probe that asked for them had timed out. Those hosts were still identified — the token on each probe says which transmission it answers — but the per-host timeouts are running tight for this network.",
                recoverable: true
            ))
        }
        let snapshot = counters.snapshot()
        if snapshot.repliesSeen > 0 { used.insert(.icmpSweep) }

        // Hosts the ARP cache knows that never answered a probe are still real — a
        // firewalled host ignoring ICMP is exactly what a neighbour-table cross-check
        // is for, and dropping it would report the network as emptier than it is.
        let answered = Set(hosts.map(\.ip))
        for (ip, mac) in neighborsByIP.sorted(by: { $0.key < $1.key }) {
            guard target.network.contains(ip), ip != target.interface.address else { continue }
            guard !answered.contains(ip) else { continue }
            // Marked, because this host never answered anything. A reader reconciling
            // the artifact against a packet capture will find no frame from it and
            // needs to know that is expected rather than a phantom.
            let host = HostFacts(ip: ip, mac: mac, discoveredVia: [.neighborTable])
            hosts.append(host)
            sink(.hostFound(host))
        }

        // This machine's own address, marked wherever it ended up in the list.
        //
        // It is a real host on the segment and it is reported, but it is the one
        // address whose evidence a packet capture can never show: a probe a host sends
        // to itself is answered inside the kernel and never reaches the interface.
        // Measured — three pings to this machine's own address returned three replies
        // and `tcpdump` on that interface captured nothing at all. Without this mark,
        // anyone checking the artifact against a capture finds one host too many and
        // no explanation, which is precisely what happened to a study that then spent a
        // day deciding whether the scanner was inventing hosts.
        for index in hosts.indices where hosts[index].ip == target.interface.address {
            hosts[index].discoveredVia.insert(.localInterface)
        }

        // A probe the kernel refused to send is not a host that failed to answer, and
        // the difference matters: an unroutable target makes every `sendto` fail, which
        // would otherwise produce an empty device list, an outcome of `.complete`, and
        // no explanation at all.
        if attempted > 0, delivered * 2 < attempted {
            degrade(Degradation(
                stage: .discovery,
                reason: delivered == 0
                    ? "No probe could be sent to \(target.network) at all — the system has no route to it from \(target.interface.name). Nothing was measured, so an empty result here means the scan did not happen rather than that the network is empty."
                    : "Only \(delivered) of \(attempted) probes could be sent to \(target.network); the rest were refused by the system. The result is incomplete for reasons that have nothing to do with which hosts are present.",
                recoverable: delivered > 0
            ))
        }

        if let denial = LocalNetworkDenialHeuristic.evaluate(
            repliesSeen: snapshot.repliesSeen,
            probesSent: snapshot.probesSent,
            neighborEntries: neighborsByIP.count,
            advice: advice
        ) {
            degrade(denial)
        }

        let settled = await state.isSettled
        let outcome: Outcome = Task.isCancelled ? .cancelled
            : (deadline.isExpired && !settled ? .deadlineExpired : .complete)
        return finished(hosts, outcome)
    }
}

/// One outstanding transmission.
private struct InFlight {
    var address: IPv4Address
    /// Which attempt this was for that host, counting from zero. Karn's rule reads
    /// this, at reply time, from the probe that was actually answered.
    var transmission: Int
    var sentAt: MonotonicInstant
    var expiresAt: MonotonicInstant
    /// Whether its window has already closed.
    ///
    /// Expired probes are kept rather than deleted, because the token identifies the
    /// exact transmission and a late reply is therefore still an EXACT measurement of a
    /// live host. Deleting them meant a host that answered a little slower than its
    /// budget allowed was reported absent while its reply sat in the buffer being
    /// counted as a stray — the host was there, we had proof, and we threw it away.
    var expired = false
}

/// The mutable state of one sweep.
///
/// An actor because the reader task and the send loop touch it concurrently by design.
/// It holds no descriptor and does no I/O — the socket is the actor next door — so the
/// hops are cheap relative to the network on the other side of them.
actor SweepState {
    /// What is known about each address.
    private struct Host {
        var estimator = RTTEstimator()
        var transmissions = 0
        var facts: HostFacts?
        /// The token of the transmission currently outstanding, if any.
        var outstanding: UInt32?
    }

    private var hosts: [IPv4Address: Host] = [:]
    private var order: [IPv4Address]
    private var inFlight: [UInt32: InFlight] = [:]
    /// Probes handed to the socket but not yet confirmed sent.
    private var assigned: [UInt32: (address: IPv4Address, transmission: Int)] = [:]
    /// Replies that arrived before their send was recorded.
    ///
    /// This is a real race, not a theoretical one: a whole /24 is handed to the socket
    /// in one batch that takes about ten milliseconds, and a host on the same switch
    /// answers in four hundred microseconds — so its reply is read, decoded and
    /// delivered here while the batch is still being sent. Dropping those replies made
    /// the fastest hosts on the network the ones most likely to be reported absent.
    ///
    /// Stashing rather than timestamping optimistically, because the alternative — 
    /// arming the probe at assignment time with a provisional instant — would measure
    /// the batch position as though it were network latency, which is the same
    /// measurement error this file has already been fixed for once.
    private var unmatched: [UInt32: ICMPReply] = [:]
    /// The two budgets, and the two estimators behind them.
    ///
    /// In core rather than here since the layer-2 sweep needed the same schedule: one
    /// timing model, two engines, so `budget_policy` in the artifact means the same
    /// thing whichever engine wrote it.
    private var clock: SweepClock
    /// When the most recent probe went out.
    private(set) var lastTransmissionAt: MonotonicInstant?
    /// When the most recent probe that was NOT the deliberately-late final transmission
    /// went out, which is where the tail window starts.
    ///
    /// Anchoring the declaration instant here rather than on `lastTransmissionAt` is
    /// what lets the final transmission be spread into the tail window for free: it is
    /// sent inside a window the sweep was already going to spend waiting.
    private(set) var lastTightTransmissionAt: MonotonicInstant?
    private var unsent: [IPv4Address]
    private let neighbors: [IPv4Address: MACAddress]
    private let attempts: Int
    private let counters: ProbeCounters
    private let spacing: SweepSpacing
    /// The spread, and the reply allowance it was bought from, decided once.
    ///
    /// Both are functions of the estimators, and the estimators move as the sweep
    /// learns. Recomputing them meant the gap armed on one transmission was bought from
    /// one allowance while the declaration instant was floored by another — and when
    /// the second was the larger, the sweep waited out a difference that no probe was
    /// waiting on. Caught on a real network, where discovery ran a hundred milliseconds
    /// longer than the schedule it had actually armed.
    ///
    /// Frozen at first USE rather than at construction, which is when the second
    /// transmission is armed: by then the first wave's replies are in and the
    /// estimators have evidence, whereas at construction they have none.
    private var frozenSpread: Duration?
    private var frozenAllowance: Duration?
    private var nextToken: UInt32 = 1
    private var nextSequence: UInt16 = 0

    init(
        pending: [IPv4Address],
        neighbors: [IPv4Address: MACAddress],
        attempts: Int,
        counters: ProbeCounters,
        spacing: SweepSpacing = .spreadIntoTail,
        budgets: SweepBudgets = .split
    ) {
        self.spacing = spacing
        self.clock = SweepClock(budgets: budgets)
        self.order = pending
        self.unsent = pending.reversed()   // popped from the end, so probes go out in address order
        self.neighbors = neighbors
        self.attempts = attempts
        self.counters = counters
        for address in pending { hosts[address] = Host() }
    }

    /// Whether every address has either answered or exhausted its attempts.
    ///
    /// Expired probes do not count as outstanding: their window has closed and the
    /// sweep is not waiting on them, even though they are kept so a late reply can
    /// still be attributed.
    var isSettled: Bool {
        unsent.isEmpty && !inFlight.values.contains { !$0.expired }
    }

    /// How long an unanswered probe waits before being resent.
    ///
    /// The median of observed round trips, doubled. Half the responsive hosts on this
    /// network answer inside it, and the ones that do not are covered by the tail —
    /// so being wrong costs one extra packet rather than a missed host, which is what
    /// lets it be this tight.
    ///
    /// With no samples yet it is 100 ms: long enough that the first replies have a
    /// chance to arrive and inform the estimate, short enough that a sweep of an empty
    /// network is not waiting on a guess.
    ///
    /// Under ``SweepBudgets/shared`` there is no separate interval to compute: the tail's
    /// number answers both questions, which is the whole of what that ablation changes.
    /// Under ``SweepBudgets/fixedRetransmit(_:)`` the stated value is returned as given —
    /// not clamped to the 25–150 ms range the adaptive path uses, because those bounds
    /// exist to keep a *measurement* sane and there is no measurement here. Clamping an
    /// imposed value would silently produce a scan the operator did not ask for, and the
    /// artifact would report the clamped number as though it had been chosen.
    func retransmitBudget() -> Duration { clock.retransmitBudget() }

    /// How long the sweep waits at the end before calling the silent addresses absent.
    ///
    /// The tail — srtt + 4·rttvar, which is what Jacobson's estimator is for — because
    /// the slowest live host defines it and missing that host is the failure this whole
    /// budget exists to prevent. Paid once for the entire sweep.
    func tailBudget() -> Duration { clock.tailBudget() }

    /// How long a reply is expected to take, on the estimator's own evidence.
    ///
    /// The same quantity `tailBudget()` is built from, but WITHOUT the 250 ms floor
    /// that budget puts under it. The difference between the two is the sweep's slack:
    /// on a LAN answering in a millisecond the floor is what binds, and those spare
    /// milliseconds are time the sweep spends waiting for nothing. `spreadBudget()`
    /// spends them instead.
    func replyAllowance() -> Duration { clock.replyAllowance() }

    /// How far the final transmission is pushed out beyond the retransmit interval.
    ///
    /// Only ever as much as the tail window can absorb, so the sweep finishes when it
    /// would have finished anyway — correction C8's fix is bought out of slack rather
    /// than out of wall clock. Divided by the scatter's upper bound so that even a gap
    /// scattered upward still fits inside the slack; a gap that overshot would be
    /// waited out by `declarationInstant()` and would then cost real time.
    ///
    /// Zero when there is no slack — a network whose tail budget is genuinely the tail
    /// of its RTT distribution rather than the floor. On such a network this reports
    /// zero rather than pretending, and the artifact says so.
    func spreadBudget() -> Duration {
        if let frozenSpread { return frozenSpread }
        // No spread without evidence, and no freezing either.
        //
        // The spread is bought out of the gap between the tail budget and what a reply
        // actually needs, and before anything has answered both of those are guesses
        // the estimators shipped with rather than measurements. Freezing on the guesses
        // spread the schedule by 280 ms on a network that turned out to have no slack
        // at all — measured on 10.10.20.0/24, where the fastest host answers in 152 ms
        // and so the first retransmission is armed before any reply has arrived.
        //
        // Two samples rather than one, so a single outlier cannot set the schedule for
        // the whole sweep.
        guard clock.sampleCount >= 2 else { return .zero }
        let allowance = replyAllowance()
        let value = computedSpread(allowance: allowance)
        frozenSpread = value
        frozenAllowance = allowance
        return value
    }

    private func computedSpread(allowance: Duration) -> Duration {
        guard spacing.spreadCeiling > .zero, attempts >= 2 else { return .zero }
        let headroom = tailBudget() - allowance
        guard headroom > .zero else { return .zero }
        let affordable = min(headroom / (1 + spacing.jitter), spacing.spreadCeiling)
        // Only if it materially widens the schedule.
        //
        // C8's premise is that the k transmissions span less than an outage. On a
        // network whose retransmit interval has risen toward its ceiling that premise
        // has already stopped holding — three transmissions 150 ms apart span 300 ms
        // by themselves — and a spread shorter than the span the schedule already has
        // widens nothing worth having.
        //
        // Measured on 10.10.20.0/24, where the fastest host answers in 152 ms: the
        // spread was 178 ms against a span of 300 ms, bought nothing, and cost 90 to
        // 230 ms of discovery time. The transmit phase ran longer, so more late replies
        // landed inside it, so the tail estimate grew, so the wait after it grew too —
        // a feedback path the simulator does not model and the network exposed.
        //
        // Comparing against the span rather than against a fixed millisecond count
        // keeps this a statement about the schedule instead of a second tuned constant.
        let span = Duration.seconds(0) + retransmitBudget() * Double(attempts - 1)
        guard affordable > span else { return .zero }
        return affordable
    }

    /// When the sweep may stop listening.
    ///
    /// The tail window measured from the last TIGHT transmission, which is the instant
    /// the sweep would have reached with no spreading at all. Floored by the last
    /// transmission plus its own reply allowance, so a scattered final gap that
    /// overshot the anchor is waited out rather than having its reply discarded — that
    /// floor is the safety valve, and it is the only path by which spreading can cost
    /// wall clock.
    func declarationInstant() -> MonotonicInstant? {
        let anchor = lastTightTransmissionAt ?? lastTransmissionAt
        let anchored = anchor?.advanced(by: tailBudget())
        // The allowance the spread was bought from, not whatever the estimator says
        // now. Using the current one lets a tail that grew during the sweep charge the
        // whole sweep for a gap that was sized against a smaller one.
        let allowance = max(frozenAllowance ?? replyAllowance(), retransmitBudget())
        let late = lastTransmissionAt?.advanced(by: allowance)
        switch (anchored, late) {
        case let (a?, l?): return Swift.max(a, l)
        case let (a?, nil): return a
        case let (nil, l?): return l
        case (nil, nil): return nil
        }
    }

    /// How long transmission `index` waits before the next one is due.
    ///
    /// The long gap is the one that LEADS TO the final transmission, so it is armed on
    /// the second-to-last. The final transmission's own window is the retransmit
    /// interval: nothing follows it, so holding it open longer schedules nothing and
    /// only delays `isSettled`.
    ///
    /// Scattered per host, deterministically from the address, because a gap fixed
    /// across every host can land on a periodic power-save cycle and put every
    /// transmission to a host at the same phase of it.
    func gap(afterTransmission index: Int, address: IPv4Address,
             base: Duration) -> Duration {
        guard index == attempts - 2 else { return base }
        let spread = spreadBudget()
        guard spread > base else { return base }
        return spread * spacing.scatter(for: address)
    }

    /// Whether every address has answered.
    var everyoneAnswered: Bool { hosts.values.allSatisfy { $0.facts != nil } }

    /// How long until the earliest outstanding probe expires.
    func timeUntilNextExpiry() -> Duration? {
        guard let soonest = inFlight.values.filter({ !$0.expired }).map(\.expiresAt).min()
        else { return nil }
        let now = MonotonicInstant.now
        return soonest > now ? soonest.duration(since: now) : .zero
    }

    /// Probes that should go out now: never-sent addresses, and outstanding probes past
    /// their own expiry that have attempts left.
    ///
    /// A linear pass over what is outstanding. At a /24 that is a few hundred
    /// comparisons per tick and free; at a /16 it is the point where the hashed timing
    /// wheel the bibliography describes starts to matter, and this is where it would go.
    /// - Parameter now: the moment to judge expiry against. Injectable so a test can
    ///   advance the clock instead of sleeping through a real timeout.
    func dueProbes(limit: Int, now: MonotonicInstant = .now) -> [ProbeAssignment] {
        var due: [ProbeAssignment] = []

        // Expired transmissions first, so a host that lost a frame is retried before
        // the sweep moves on to addresses nobody has looked at yet.
        for (token, probe) in inFlight where !probe.expired && probe.expiresAt <= now {
            inFlight[token]?.expired = true
            counters.probeCompleted()
            guard var host = hosts[probe.address] else { continue }
            host.outstanding = nil
            // No backoff on the retransmit interval, and this is the whole point of
            // splitting the budget. Backoff widens a window in response to evidence of
            // slowness; silence is evidence of ABSENCE, and the retransmit exists to
            // recover a LOST FRAME, which is recovered by asking again rather than by
            // waiting longer. Slowness is the tail's problem, and the tail is paid once.
            //
            // The per-host estimator still records the retransmission, because its
            // backoff is what governs that host's timeout in the port scan and, later,
            // across runs — it just no longer governs this schedule.
            if host.facts != nil || neighbors[probe.address] != nil {
                host.estimator.recordRetransmission()
            }
            hosts[probe.address] = host
            if host.transmissions < attempts {
                due.append(assign(probe.address))
                if due.count >= limit { return due }
            }
        }

        while due.count < limit, let address = unsent.popLast() {
            due.append(assign(address))
        }
        return due
    }

    private func assign(_ address: IPv4Address) -> ProbeAssignment {
        let token = nextToken
        nextToken &+= 1
        let sequence = nextSequence
        nextSequence &+= 1
        var host = hosts[address] ?? Host()
        let transmission = host.transmissions
        host.transmissions += 1
        host.outstanding = token
        hosts[address] = host
        assigned[token] = (address, transmission)
        return ProbeAssignment(address: address, sequence: sequence, token: token)
    }

    /// Records when each probe actually went out, and arms its expiry.
    ///
    /// The timeout is that host's own: its estimator once it has samples, the network's
    /// current estimate for a first probe. This is the adaptive mechanism, and it is
    /// per host rather than per sweep so a slow device is not judged by a fast one.
    func recordSends(_ instants: [UInt32: MonotonicInstant]) -> [ProbeEvent] {
        var events: [ProbeEvent] = []
        // Snapshotted ONCE, before any stashed reply is folded in.
        //
        // Computing it per probe inside the loop was subtly wrong in a way that only
        // showed up against a real network: draining a stashed reply updates the
        // estimators, so probes later in the same batch got a different budget from
        // probes earlier in it — and since the batch is a dictionary, WHICH addresses
        // got which budget varied between runs. A timeout that depends on hash order is
        // not a timeout, it is a coin flip with a unit.
        let budget = retransmitBudget()
        // Asked for lazily: `gap` only consults it when arming the transmission before
        // the final one, and asking here would freeze it during the first wave, before
        // a single reply has taught the estimators anything.
        for (token, instant) in instants {
            guard let assignment = assigned.removeValue(forKey: token) else { continue }
            let gap = gap(
                afterTransmission: assignment.transmission,
                address: assignment.address,
                base: budget
            )
            inFlight[token] = InFlight(
                address: assignment.address,
                transmission: assignment.transmission,
                sentAt: instant,
                expiresAt: instant.advanced(by: gap)
            )
            if lastTransmissionAt.map({ instant > $0 }) ?? true { lastTransmissionAt = instant }
            if assignment.transmission < attempts - 1,
               lastTightTransmissionAt.map({ instant > $0 }) ?? true {
                lastTightTransmissionAt = instant
            }
            counters.probeSent()
            // A reply that beat this registration is waiting; fold it in now, with the
            // arrival time it was actually stamped with.
            if let early = unmatched.removeValue(forKey: token), let event = record(early) {
                events.append(event)
            }
        }
        // Anything still assigned was refused by the kernel. The attempt is spent —
        // requeuing it instead looped forever against an address the kernel will keep
        // refusing, and the sweep ran to its full deadline every time. `send` already
        // retries EAGAIN internally, so reaching here means a real refusal.
        for (token, assignment) in assigned {
            if hosts[assignment.address]?.outstanding == token {
                hosts[assignment.address]?.outstanding = nil
            }
        }
        assigned.removeAll()
        return events
    }

    /// Folds one reply into the state, returning the event to emit.
    func record(_ reply: ICMPReply) -> ProbeEvent? {
        // Matched on the token from the payload, which is unique per transmission and
        // 32 bits wide. The 16-bit sequence field wraps inside a /16 sweep and would
        // attribute a reply to the wrong host.
        guard let probe = inFlight[reply.token] else {
            // Arrived before its own send was registered. Hold it — see `unmatched`.
            if assigned[reply.token] != nil { unmatched[reply.token] = reply } else { strayReplies += 1 }
            return nil
        }
        guard probe.address == reply.source else { strayReplies += 1; return nil }
        // Late, but attributed exactly, which is why expired probes are kept in
        // `inFlight` at all. This is the only place that can know: by the time the
        // sweep ends the probe is gone and nothing downstream can tell a prompt reply
        // from one that arrived after its window closed.
        //
        // The counter was declared, documented, and read to raise a degradation — and
        // never incremented anywhere, so that degradation could not fire. Meanwhile
        // `strayReplies`, which IS incremented, was read by nothing. The two were
        // crossed, and the symptom was silence: a network whose per-host budgets are
        // too tight looked exactly like one where everything answered promptly.
        if probe.expired { lateReplies += 1 }
        inFlight[reply.token] = nil
        counters.replySeen()
        counters.probeCompleted()

        var host = hosts[reply.source] ?? Host()
        host.outstanding = nil
        let isFirstReply = host.facts == nil

        // Measured against the instant THIS transmission went out, not the host's most
        // recent send, so a straggler is timed correctly rather than against a probe it
        // did not answer.
        let elapsed = reply.receivedAt.duration(since: probe.sentAt)
        // Karn's first rule, keyed off the probe. A reply to a first transmission is
        // unambiguous however many attempts have since gone out.
        let ambiguous = probe.transmission > 0
        host.estimator.record(elapsed, wasRetransmitted: ambiguous)
        if !ambiguous {
            // Two estimators, two jobs. `network` tracks the tail and sets the
            // end-of-sweep wait; `quantiles` tracks the low end and sets the retransmit
            // interval. Feeding one structure to both questions is what made the sweep
            // spend the slowest host's latency on every dead address, three times each.
            clock.record(elapsed)
        }

        let facts = HostFacts(
            ip: reply.source,
            mac: neighbors[reply.source],
            ttl: reply.ttl,
            rtt: host.estimator.sample,
            discoveredVia: [.probeReply]
        )
        host.facts = facts
        hosts[reply.source] = host
        return isFirstReply ? .hostFound(facts) : .hostUpdated(facts)
    }

    /// The expiry each outstanding probe was armed with, keyed by address.
    ///
    /// Test support. The property that matters is that this is a function of the
    /// measurements alone — asserting it from the outside is the only way to catch a
    /// budget that has quietly become a function of hash order again.
    /// Only the probe that is actually outstanding for each address.
    ///
    /// Expired probes are kept in `inFlight` so a late reply can still be attributed,
    /// and once the gaps differ between transmissions an address can hold an expired
    /// probe armed with one gap and a live probe armed with another. Keying both by
    /// address made which one won a function of dictionary iteration order, which is
    /// the same defect this accessor exists to catch.
    func armedBudgets() -> [IPv4Address: Duration] {
        var result: [IPv4Address: Duration] = [:]
        for probe in inFlight.values where !probe.expired {
            result[probe.address] = probe.expiresAt.duration(since: probe.sentAt)
        }
        return result
    }

    /// Everything that answered, in address order.
    func discovered() -> [HostFacts] {
        order.compactMap { hosts[$0]?.facts }
    }

    /// Replies that decoded cleanly and matched no probe this sweep is still holding.
    ///
    /// Expired probes are KEPT in `inFlight` so a late reply can still be attributed,
    /// so this is not lateness — that is `lateReplies`. What lands here is a second
    /// reply to a probe already answered and removed, or a reply whose source is not
    /// the address its token was issued for.
    ///
    /// This description used to be the one below, which is how the two counters came to
    /// be crossed: the degradation about tight budgets read `lateReplies`, nothing
    /// incremented `lateReplies`, and nothing read this.
    private(set) var strayReplies = 0

    /// Replies that arrived after their own probe's window closed but were still
    /// attributed exactly, because the token says which transmission they answer.
    ///
    /// These are hosts that WERE found — the count is a signal that the per-host budgets
    /// are running tight for this network, not that anything was lost.
    private(set) var lateReplies = 0
}

#endif
