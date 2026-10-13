// BPFSweep.swift — the privileged engine, and the one capability it adds.
//
// `EngineKind.privilegedBPF` was declared from the start and nothing constructed it.
// The measurement study ran zhen under `sudo` and under the owner's account, each
// under its own packet capture with the neighbour table flushed first, and the two runs
// were indistinguishable on the wire: 253 ARP requests and 20 ICMP echoes against 253
// and 19, no TCP in either, the same nine hosts. The ARP in both was the kernel
// resolving next-hop for the ICMP datagrams rather than either run sweeping layer 2 —
// it was one engine, run twice. That is why hypothesis H3 was withdrawn from the
// protocol on 2026-09-12, and this file is the hole it was withdrawn around.
//
// ── What ARP buys ───────────────────────────────────────────────────────────────
//
// Every host with a hardware address must answer an ARP request for its own address.
// Not "usually", not "unless firewalled": a host that does not answer cannot receive a
// frame, so refusing is indistinguishable from being absent and no stack does it. That
// obligation is stronger than anything ICMP can appeal to, and it is the whole reason
// `sudo nmap -sn` reaches hosts an unprivileged sweep does not. Gate 0.3 of the study
// measured privileged nmap at recall 1.00 on all ten testbed responders — including the
// ICMP-filtered one and the two that answer at 500 ms, which the unprivileged engine
// misses on every cold-cache run.
//
// ── What it does not do ─────────────────────────────────────────────────────────
//
// It does not read the kernel's neighbour table. That is `neighborTable`, the
// unprivileged engine has it, and the difference between the two is the whole reason
// `EngineCapabilities` has both members — see `ARPFrame.swift`. It launches nothing:
// no `arp`, no `ping`, no subprocess of any kind, which is the property the entire
// project exists to demonstrate.
//
// ── Why no round trip is reported ───────────────────────────────────────────────
//
// An ARP reply carries no token, no sequence and no echo of the request. Attribution is
// by sender address alone, and there is exactly one outstanding request per address, so
// *presence* is unambiguous. *Timing* is not: the kernel ARPs for its own reasons, and
// when this engine runs beside the ICMP sweep — which is the normal case, because
// composition is the point — the kernel is resolving next-hop for those very datagrams.
// A reply arriving after our request may be answering the kernel's, so an interval
// measured from our transmission is an upper bound on one round trip and not a
// measurement of any.
//
// So `HostFacts.rtt` is left nil here and the ICMP engine's sample, which has a token
// behind it, is the one that reaches the artifact. The intervals are still fed to the
// `SweepClock`, because a schedule that adapts is the mechanism under test and a sample
// that is occasionally short makes the sweep ask again sooner rather than declare
// absence earlier — the tail's floor is what bounds that, and it does not move.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Privileged host discovery: a layer-2 ARP sweep over `/dev/bpf*`.
public struct BPFDiscoveryEngine: HostDiscovery {
    /// How this engine identifies itself in the artifact.
    ///
    /// `arpSweep` and nothing else. It puts ARP on the wire and reads the answers; it
    /// does not read the neighbour table, does not probe ICMP and does not scan ports.
    public let descriptor = EngineDescriptor(
        name: "bpf-arp",
        kind: .privilegedBPF,
        capabilities: [.arpSweep]
    )

    /// How many times an unanswered address is asked before it is called silent.
    ///
    /// Three, matching the ICMP sweep. ARP is a single frame on the local segment with
    /// no routing and no fragmentation, so the loss it has to survive is the radio's.
    public var attempts: Int
    /// How many frames are written per round before the loop checks the clock again.
    public var concurrency: Int
    /// Which budgets exist and how the retransmit interval is chosen.
    ///
    /// The same policy type the ICMP sweep takes, honoured through the same
    /// `SweepClock`, so a run under `--shared-budget` means one thing regardless of
    /// which engine produced it.
    public var budgets: SweepBudgets
    /// Where a capture device comes from.
    ///
    /// The engine cannot tell a descriptor this process opened from one a root daemon
    /// opened and passed over XPC, and that indistinguishability is the helper's whole
    /// claim. Defaults to a direct open, so nothing that does not ask for a helper gets
    /// one.
    public var capture: CaptureSource = .direct

    /// Creates the engine.
    public init(
        attempts: Int = 3,
        concurrency: Int = 256,
        budgets: SweepBudgets = .split,
        capture: CaptureSource = .direct
    ) {
        self.attempts = attempts
        self.concurrency = concurrency
        self.budgets = budgets
        self.capture = capture
    }

    /// Terminal form, with an optional observer.
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
        var retransmitBudget = Duration.zero
        var tailBudget = Duration.zero

        func finished(_ hosts: [HostFacts], _ outcome: Outcome) -> DiscoveryResult {
            let snapshot = counters.snapshot()
            let stage = StageTiming(
                stage: .discovery,
                elapsedMillis: watch.elapsedMillis,
                probesSent: snapshot.probesSent,
                repliesSeen: snapshot.repliesSeen,
                hostsFound: hosts.count,
                retransmitBudgetMillis: retransmitBudget > .zero ? retransmitBudget.milliseconds : nil,
                tailBudgetMillis: tailBudget > .zero ? tailBudget.milliseconds : nil,
                budgetPolicy: retransmitBudget > .zero ? budgets.name : nil
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

        guard let addresses = target.resolution.addresses else {
            if let refusal = target.resolution.refusal { degrade(refusal) }
            return finished([], .complete)
        }

        // An ARP request needs a sender hardware address to be answered to. Without
        // one there is nothing to build a frame from, and a sweep that sent frames with
        // a zero source would be answered into the void.
        guard let senderMAC = target.interface.hardwareAddress else {
            degrade(Degradation(
                stage: .discovery,
                reason: """
                    \(target.interface.name) has no hardware address, so no ARP request \
                    can be built for it and the layer-2 sweep did not run. This is normal \
                    for a tunnel or a point-to-point link; the unprivileged sweep is \
                    unaffected.
                    """,
                recoverable: true
            ))
            return finished([], .complete)
        }
        let senderIP = target.interface.address

        // Our own address is never asked about. An ARP request whose sender and target
        // protocol addresses are equal is a gratuitous ARP — the frame a host sends to
        // announce itself or to probe for a conflict — and broadcasting 254 of those
        // with one aimed at ourselves would put a duplicate-address warning in other
        // machines' logs for no discovery value at all.
        let probeList = addresses.filter { $0 != senderIP }

        let device: BPFDevice
        do {
            device = try await capture.open(
                interface: target.interface.name, filter: BPFFilter.arp()
            )
        } catch {
            // Never a hard failure. A busy device, a missing grant and a tunnel
            // interface are all ordinary states of a machine, and the composite above
            // still has the unprivileged half.
            degrade(Degradation(
                stage: .discovery,
                reason: error.reason,
                recoverable: error != .notPrivileged
            ))
            return finished([], .complete)
        }

        let state = ARPSweepState(
            pending: probeList, attempts: attempts, counters: counters, budgets: budgets
        )
        let frames = await device.frames()
        // One reader for the whole sweep, independent of the sender. Replies to the
        // first round keep arriving during the second and must not be dropped because
        // the round that asked for them has ended.
        //
        // The device yields frames rather than parsed messages because the SYN scan
        // reads the same device type and decodes TCP; the ARP decode is this engine's
        // own business and happens here.
        let reader = Task {
            for await frame in frames {
                guard let message = ARPFrame.parse(frame.span) else { continue }
                if let event = await state.record(message, at: .now) { sink(event) }
            }
        }

        var attempted = 0
        var delivered = 0

        // ── Transmit, on the tight budget ───────────────────────────────────────
        while !Task.isCancelled, !deadline.isExpired {
            let due = await state.dueProbes(limit: concurrency)
            if due.isEmpty {
                if await state.isSettled { break }
                let nap = await state.timeUntilNextExpiry() ?? .milliseconds(5)
                try? await Task.sleep(for: min(max(nap, .milliseconds(1)), .milliseconds(10)))
                continue
            }
            let sent = await device.send(due.map {
                ARPFrame.request(target: $0, senderMAC: senderMAC, senderIP: senderIP)
            })
            await state.recordSends(Array(due.prefix(sent)), at: .now)
            attempted += due.count
            delivered += sent
        }

        // ── One tail wait, for the whole segment at once ────────────────────────
        tailBudget = await state.tailBudget()
        if let end = await state.declarationInstant() {
            while !Task.isCancelled, !deadline.isExpired, MonotonicInstant.now < end {
                if await state.everyoneAnswered { break }
                try? await Task.sleep(for: .milliseconds(5))
            }
        }
        retransmitBudget = await state.retransmitBudget()

        reader.cancel()
        await device.stop()

        let hosts = await state.discovered()
        let snapshot = counters.snapshot()
        if snapshot.repliesSeen > 0 { used.insert(.arpSweep) }

        // A frame the kernel refused is not a host that stayed quiet, and the two
        // produce identical evidence — an address with no answer — so the difference
        // has to come from the send path or it is lost.
        if attempted > 0, delivered * 2 < attempted {
            degrade(Degradation(
                stage: .discovery,
                reason: delivered == 0
                    ? "No ARP request could be written to \(target.interface.name) at all. Nothing was measured, so an empty result here means the layer-2 sweep did not happen rather than that the segment is empty."
                    : "Only \(delivered) of \(attempted) ARP requests could be written to \(target.interface.name); the rest were refused. The layer-2 result is incomplete for reasons that have nothing to do with which hosts are present.",
                recoverable: delivered > 0
            ))
        }

        // Frames went out and nothing came back. On a segment with anything on it at
        // all that is not a quiet network, it is a sweep that is not being heard — the
        // most likely cause being 802.1Q tags, which move the ethertype past the offset
        // both the kernel filter and the parser read.
        if delivered > 0, snapshot.repliesSeen == 0 {
            degrade(Degradation(
                stage: .discovery,
                reason: """
                    \(delivered) ARP requests went out on \(target.interface.name) and \
                    nothing answered. Either the segment is empty, or its frames carry \
                    802.1Q VLAN tags — this sweep reads the ethertype at offset 12 and a \
                    tag moves it to 16, so a tagged segment answers into a filter that \
                    never matches.
                    """,
                recoverable: true
            ))
        }

        let settled = await state.isSettled
        let outcome: Outcome = Task.isCancelled ? .cancelled
            : (deadline.isExpired && !settled ? .deadlineExpired : .complete)
        return finished(hosts, outcome)
    }
}

/// The mutable state of one ARP sweep.
///
/// Smaller than `SweepState` because ARP is a smaller problem. There is no token and no
/// sequence number: exactly one request per address is outstanding at a time and a
/// reply names its own sender, so the matching that ICMP needs a 32-bit token for is
/// done by the address itself. What it keeps is the same: when each address was last
/// asked, how many times, and the one clock that answers both budget questions.
actor ARPSweepState {
    private struct Host {
        var transmissions = 0
        var sentAt: MonotonicInstant?
        var expiresAt: MonotonicInstant?
        var mac: MACAddress?
        var answered = false
    }

    private var hosts: [IPv4Address: Host] = [:]
    private var order: [IPv4Address]
    private var clock: SweepClock
    private let attempts: Int
    private let counters: ProbeCounters
    private(set) var lastTransmissionAt: MonotonicInstant?

    init(
        pending: [IPv4Address],
        attempts: Int,
        counters: ProbeCounters,
        budgets: SweepBudgets = .split
    ) {
        self.order = pending
        self.attempts = attempts
        self.counters = counters
        self.clock = SweepClock(budgets: budgets)
        for address in pending { hosts[address] = Host() }
    }

    /// How long an unanswered request waits before being resent.
    func retransmitBudget() -> Duration { clock.retransmitBudget() }
    /// How long the sweep waits at the end before calling the silent addresses absent.
    func tailBudget() -> Duration { clock.tailBudget() }

    /// Whether every address has answered or run out of attempts.
    var isSettled: Bool {
        !hosts.values.contains { host in
            !host.answered && (host.transmissions < attempts || host.expiresAt != nil)
        }
    }

    /// Whether every address answered, which lets the tail wait end early.
    var everyoneAnswered: Bool { !hosts.values.contains { !$0.answered } }

    /// When the sweep may stop listening.
    ///
    /// The tail window measured from the last transmission. One anchor rather than the
    /// ICMP sweep's two, because this sweep does not spread its final transmission into
    /// the tail — and that is a gap rather than a decision, so it is written down as
    /// one.
    ///
    /// `SweepSpacing` exists because of correction C8 in the study: three transmissions
    /// spaced by a low quantile of RTT span less than a Wi-Fi power-save outage, so one
    /// outage takes all three and the host is reported absent. **ARP is subject to
    /// exactly that**, for exactly that reason — a station asleep on its DTIM cycle
    /// answers no frame of any kind — and it is visible on the network this was
    /// developed against: of seven hosts that answer ARP, the two slowest answer at 258
    /// and 332 ms, and repeated runs of this engine alone return seven, seven, five.
    ///
    /// It is not implemented here because doing it honestly means lifting the spread
    /// arithmetic out of `SweepState` the way `SweepClock` lifted the budgets, and that
    /// is a change to the sweep the study measured rather than an addition beside it.
    /// The composite is why it can wait: the ICMP sweep does spread, and the union is
    /// what the product reports, so a host this engine drops is not a host the scan
    /// loses.
    func declarationInstant() -> MonotonicInstant? {
        lastTransmissionAt?.advanced(by: clock.tailBudget())
    }

    /// How long until the next outstanding request is due to be resent.
    func timeUntilNextExpiry() -> Duration? {
        let now = MonotonicInstant.now
        let next = hosts.values.compactMap(\.expiresAt).min()
        guard let next else { return nil }
        return next > now ? next.duration(since: now) : .zero
    }

    /// The addresses that should be asked now: never asked, or asked and past their
    /// window.
    ///
    /// Returned in address order so a sweep is reproducible. Dictionary iteration order
    /// is not stable across runs, and a schedule that depends on it produced budgets
    /// that differed between two sweeps of an unchanged network — a bug this codebase
    /// has already had once, in the ICMP sweep, and has a test for.
    func dueProbes(limit: Int) -> [IPv4Address] {
        let now = MonotonicInstant.now
        var due: [IPv4Address] = []
        due.reserveCapacity(min(limit, order.count))
        for address in order {
            guard due.count < limit else { break }
            guard let host = hosts[address], !host.answered else { continue }
            guard host.transmissions < attempts else { continue }
            if let expiry = host.expiresAt {
                if expiry <= now { due.append(address) }
            } else if host.sentAt == nil {
                due.append(address)
            }
        }
        return due
    }

    /// Records which requests actually reached the kernel.
    ///
    /// Only the delivered ones. An address whose frame was refused has not been asked,
    /// and arming a timer for it would count a send that never happened as silence.
    func recordSends(_ delivered: [IPv4Address], at instant: MonotonicInstant) {
        let window = clock.retransmitBudget()
        for address in delivered {
            guard var host = hosts[address] else { continue }
            host.transmissions += 1
            host.sentAt = instant
            host.expiresAt = host.transmissions >= attempts ? nil : instant.advanced(by: window)
            hosts[address] = host
            counters.probeSent()
            counters.probeCompleted()
        }
        if !delivered.isEmpty { lastTransmissionAt = instant }
    }

    /// Folds in one ARP frame.
    ///
    /// Only replies count. A request seen on the segment carries a real sender address
    /// too, and taking it would turn this from a sweep into a passive listener whose
    /// results depend on what the neighbours happened to be doing — two runs of an
    /// unchanged network would disagree, and neither would be wrong.
    ///
    /// A reply from an address this sweep is not asking about is dropped rather than
    /// reported: the frame is evidence of a host, but of one outside the target, and a
    /// scan of 192.168.1.0/24 that reported a host on 10.0.0.5 would be answering a
    /// question nobody asked.
    func record(_ message: ARPFrame.Message, at instant: MonotonicInstant) -> ProbeEvent? {
        guard message.isReply else { return nil }
        guard var host = hosts[message.senderIP] else { return nil }
        counters.replySeen()

        // Fed to the clock, never to the artifact. See the note at the top of this file
        // on why an ARP interval schedules the sweep and does not describe a host.
        if let sentAt = host.sentAt, instant > sentAt {
            clock.record(instant.duration(since: sentAt))
        }

        let isNew = !host.answered
        host.answered = true
        host.mac = message.senderMAC
        host.expiresAt = nil
        hosts[message.senderIP] = host
        guard isNew else { return nil }
        return .hostFound(HostFacts(ip: message.senderIP, mac: message.senderMAC, discoveredVia: [.arpReply]))
    }

    /// Everything that answered.
    func discovered() -> [HostFacts] {
        hosts
            .filter { $0.value.answered }
            .map { HostFacts(ip: $0.key, mac: $0.value.mac, discoveredVia: [.arpReply]) }
            .sorted { $0.ip < $1.ip }
    }
}

#endif
