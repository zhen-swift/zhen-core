// SYNScan.swift — half-open port scanning over the BPF path.
//
// `EngineCapabilities.synScan` was declared with nothing constructing it, which is the
// same shape of defect the measurement study found in `arpSweep` and which cost that
// study a withdrawn hypothesis: a capability the artifact reports and the binary does
// not have. This is the engine that makes the claim true.
//
// ── What "half-open" buys, and what it does not ─────────────────────────────────
//
// It is not stealth. Every stack that is looking logs a half-open probe, and saying
// otherwise would be the sort of claim this project exists not to make. What it buys is
// that the far-side *application* is never involved: a connect scan completes the
// handshake, so the listener accepts a connection, often logs it, sometimes writes a
// banner, and waits for a request that never comes. A SYN scan costs the target one
// packet and one reply.
//
// It also answers on ports a connect scan cannot reach politely — the verdict comes
// from the stack rather than from `connect(2)`, so a listener with a full accept
// backlog still says "open" instead of timing out into `.filtered`.
//
// The full mechanics, including the RST our own kernel sends and why we must not
// suppress it, are in `IPv4Packet.swift`.
//
// ── Why this needs the neighbour table, and does not claim it ───────────────────
//
// A frame written to a BPF device is written whole: this engine builds the Ethernet
// header itself, so it needs the target's hardware address for the layer-2
// destination. On a local segment that is the host's own MAC, and the kernel already
// knows it — discovery just probed every one of these hosts, so the entry is fresh.
//
// Reading it for that is **next-hop resolution, not discovery**, and the engine does
// not claim `EngineCapabilities.neighborTable` for it. That capability means "the
// kernel's neighbour table, read as a discovery source" — reporting a host because the
// table knows it. Nothing here reports a host at all; the targets were decided before
// this stage began. The distinction is exactly the one the study had to settle with a
// packet capture, and it is worth keeping sharp in the direction that costs us
// something as well as in the direction that flatters us.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Privileged port scanning by half-open SYN probe.
public struct SYNScanEngine: PortScanning {
    /// How this engine identifies itself in the artifact.
    ///
    /// `synScan` and nothing else. It does not connect, does not read banners and does
    /// not fingerprint; those are `TCPConnectScanEngine` and `BannerProbe`, and a
    /// composite is what runs them together.
    public let descriptor = EngineDescriptor(
        name: "bpf-syn",
        kind: .privilegedBPF,
        capabilities: [.synScan]
    )

    /// How many SYNs are written per round before the loop checks the clock.
    public var concurrency: Int
    /// How many times an unanswered port is probed before it is called filtered.
    ///
    /// Two, not the sweep's three. A SYN is a single frame on a local segment and the
    /// population is ports rather than addresses — a /24 at 36 ports is nine thousand
    /// probes, so a third attempt costs three thousand frames for the same marginal
    /// recovery a second one already bought.
    public var attempts: Int
    /// Enumerates interfaces, so the engine can find the one that reaches its targets.
    public var interfaces: any InterfaceProvider
    /// Supplies the layer-2 destination for each target.
    public var neighbors: any NeighborCache
    /// Which budgets exist and how the retransmit interval is chosen. The same policy
    /// type both sweeps take, honoured through the same `SweepClock`.
    public var budgets: SweepBudgets
    /// Where a capture device comes from.
    ///
    /// The engine cannot tell a descriptor this process opened from one a root daemon
    /// opened and passed over XPC. Defaults to a direct open.
    public var capture: CaptureSource = .direct

    /// Creates the engine.
    public init(
        concurrency: Int = 256,
        attempts: Int = 2,
        interfaces: any InterfaceProvider = DarwinInterfaceProvider(),
        neighbors: any NeighborCache = DarwinNeighborCache(),
        budgets: SweepBudgets = .split,
        capture: CaptureSource = .direct
    ) {
        self.capture = capture
        self.concurrency = concurrency
        self.attempts = attempts
        self.interfaces = interfaces
        self.neighbors = neighbors
        self.budgets = budgets
    }

    /// Terminal form, with an optional observer.
    public func scan(
        _ targets: [IPv4Address],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> PortScanResult {
        let watch = Stopwatch()
        let counters = ProbeCounters()
        progress(.stageStarted(.deepScan))
        var degradations: [Degradation] = []
        var used: EngineCapabilities = []

        func finished(
            _ observations: [IPv4Address: [PortObservation]], _ outcome: Outcome
        ) -> PortScanResult {
            let snapshot = counters.snapshot()
            let stage = StageTiming(
                stage: .deepScan,
                elapsedMillis: watch.elapsedMillis,
                probesSent: snapshot.probesSent,
                repliesSeen: snapshot.repliesSeen
            )
            progress(.stageFinished(stage))
            return PortScanResult(
                ports: observations, degradations: degradations,
                usedCapabilities: used, outcome: outcome,
                timing: Timing(stages: [stage], counters: snapshot)
            )
        }

        func degrade(_ degradation: Degradation) {
            degradations.append(degradation)
            progress(.degraded(degradation))
        }

        guard !targets.isEmpty, !ports.ports.isEmpty else { return finished([:], .complete) }

        // The interface that can reach the targets, rather than whichever one the
        // default route uses. They are usually the same and are not always: a scan of a
        // second segment on a multi-homed machine has to send from the leg attached to
        // it, and a SYN sent from the wrong source address is answered to somewhere
        // this process is not listening.
        guard let interface = Self.interface(reaching: targets, from: interfaces) else {
            degrade(Degradation(
                stage: .deepScan,
                reason: """
                    No interface on this machine has an address on the same segment as \
                    the hosts being scanned, so no layer-2 frame can be addressed to \
                    them and the half-open scan did not run.
                    """,
                recoverable: true
            ))
            return finished([:], .complete)
        }
        guard let senderMAC = interface.hardwareAddress else {
            degrade(Degradation(
                stage: .deepScan,
                reason: """
                    \(interface.name) has no hardware address, so no Ethernet frame can \
                    be built for it and the half-open scan did not run. This is normal \
                    for a tunnel or a point-to-point link.
                    """,
                recoverable: true
            ))
            return finished([:], .complete)
        }

        // Layer-2 destinations. Discovery has just probed every one of these hosts, so
        // the kernel's entry is both present and fresh; a target without one cannot be
        // addressed and is named rather than silently dropped.
        var hardware: [IPv4Address: MACAddress] = [:]
        do {
            for entry in try await neighbors.entries() where entry.isComplete {
                hardware[entry.ip] = entry.mac
            }
        } catch {
            degrade(Degradation(
                stage: .deepScan,
                reason: "The neighbour table could not be read, so no layer-2 destination is known for any target and the half-open scan did not run.",
                recoverable: true
            ))
            return finished([:], .complete)
        }
        // This machine's own address cannot be probed this way, and the failure is
        // silent rather than loud: a frame written to a BPF device goes out of the
        // interface, and an interface does not receive its own transmission. So every
        // port on ourselves answers nothing and would be reported `filtered` — a
        // positive claim, made about a host whose ports we never actually asked.
        //
        // Dropped rather than mis-answered. Scanning our own ports is a reasonable
        // thing to want and `--deep` without root still does it; doing it over BPF
        // would need a loopback path this engine does not have.
        let local = interface.address
        let probeable = targets.filter { $0 != local }
        let addressable = probeable.filter { hardware[$0] != nil }
        let unaddressable = probeable.filter { hardware[$0] == nil }
        if targets.contains(local) {
            degrade(Degradation(
                stage: .deepScan,
                reason: """
                    \(local) is this machine's own address, and a half-open scan cannot \
                    reach it: the probe is written to the wire, and an interface does \
                    not receive its own frames. Its ports were not probed rather than \
                    being reported as filtered. A scan without sudo reaches them over a \
                    full connect instead.
                    """,
                recoverable: true
            ))
        }
        if !unaddressable.isEmpty {
            degrade(Degradation(
                stage: .deepScan,
                reason: """
                    \(unaddressable.count) host\(unaddressable.count == 1 ? " has" : "s have") no \
                    entry in the neighbour table, so no frame could be addressed to \
                    \(unaddressable.count == 1 ? "it" : "them") and \
                    \(unaddressable.count == 1 ? "its" : "their") ports were not probed: \
                    \(unaddressable.map(\.description).sorted().joined(separator: ", ")).
                    """,
                recoverable: true
            ))
        }
        guard !addressable.isEmpty else { return finished([:], .complete) }

        // One source port for the whole scan, which is what the kernel filter matches
        // on. Random rather than fixed so two scans running at once do not read each
        // other's replies, and high so it does not collide with a listener.
        let sourcePort = UInt16.random(in: 40_000...60_000)
        // Drawn once for the scan. Without it the sequence cookie is a pure function of
        // the target and port, so two scans of one network send identical sequences and
        // a late reply from the earlier one matches a probe in the later one.
        let salt = UInt32.random(in: UInt32.min...UInt32.max)

        let device: BPFDevice
        do {
            device = try await capture.open(
                interface: interface.name, filter: BPFFilter.tcpDestinedTo(port: sourcePort)
            )
        } catch {
            degrade(Degradation(
                stage: .deepScan,
                reason: error.reason,
                recoverable: error != .notPrivileged
            ))
            return finished([:], .complete)
        }

        let state = SYNScanState(
            targets: addressable, ports: ports.ports,
            attempts: attempts, counters: counters, budgets: budgets, salt: salt
        )
        let frames = await device.frames()
        let reader = Task {
            for await frame in frames {
                guard let segment = IPv4Packet.parse(frame.span) else { continue }
                guard segment.destinationPort == sourcePort else { continue }
                await state.record(segment, at: .now)
            }
        }

        var attempted = 0
        var delivered = 0
        while !Task.isCancelled, !deadline.isExpired {
            let due = await state.dueProbes(limit: concurrency)
            if due.isEmpty {
                if await state.isSettled { break }
                let nap = await state.timeUntilNextExpiry() ?? .milliseconds(5)
                try? await Task.sleep(for: min(max(nap, .milliseconds(1)), .milliseconds(10)))
                continue
            }
            // Paired rather than mapped, so a probe with no hardware address is
            // skipped instead of defaulting. Defaulting it to the broadcast address
            // would put a SYN in front of every host on the segment — the state is
            // built only from addressable targets so this cannot fire today, and a
            // fallback that floods the network if an invariant ever slips is not a
            // fallback worth having.
            var batch: [[UInt8]] = []
            var attempting: [SYNProbe] = []
            for probe in due {
                guard let targetMAC = hardware[probe.ip] else { continue }
                attempting.append(probe)
                batch.append(IPv4Packet.syn(
                    target: probe.ip,
                    targetMAC: targetMAC,
                    port: probe.port,
                    senderMAC: senderMAC,
                    senderIP: interface.address,
                    sourcePort: sourcePort,
                    identifier: UInt16.random(in: 1...UInt16.max),
                    salt: salt
                ))
            }
            let sent = await device.send(batch)
            await state.recordSends(Array(attempting.prefix(sent)), at: .now)
            attempted += attempting.count
            delivered += sent
        }

        // One tail wait for the whole scan, exactly as both sweeps do. A port that
        // answers slowly is caught here and the thousands that will never answer cost
        // nothing extra, because they are waiting in parallel with it.
        if let end = await state.declarationInstant() {
            while !Task.isCancelled, !deadline.isExpired, MonotonicInstant.now < end {
                if await state.everyoneAnswered { break }
                try? await Task.sleep(for: .milliseconds(5))
            }
        }

        reader.cancel()
        await device.stop()

        let snapshot = counters.snapshot()
        if snapshot.repliesSeen > 0 { used.insert(.synScan) }

        if attempted > 0, delivered * 2 < attempted {
            degrade(Degradation(
                stage: .deepScan,
                reason: delivered == 0
                    ? "No SYN could be written to \(interface.name) at all. Every port below is reported as not probed rather than as filtered, because nothing was asked."
                    : "Only \(delivered) of \(attempted) SYN probes could be written to \(interface.name); the rest were refused. The port results are incomplete for reasons that have nothing to do with the hosts.",
                recoverable: delivered > 0
            ))
        }

        let settled = await state.isSettled
        let outcome: Outcome = Task.isCancelled ? .cancelled
            : (deadline.isExpired && !settled ? .deadlineExpired : .complete)
        // A cancelled scan reports nothing rather than a wall of `.filtered`. Silence
        // we stopped waiting for is not evidence of a closed port, and manufacturing it
        // would let Ctrl-C write port facts into the history.
        let observations = Task.isCancelled ? [:] : await state.observations()
        return finished(observations, outcome)
    }

    /// Streaming form: port verdicts as the hosts they belong to are finished.
    ///
    /// Built on the terminal form rather than the other way round, for the reason
    /// `HostDiscovery` documents at length: the progress channel is `.bufferingNewest`
    /// and may drop, so an artifact assembled from it would report `.complete` over a
    /// port list with holes in it.
    public func stream(
        _ targets: [IPv4Address],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task { [self] in
            let result = await scan(targets, ports: ports,
                                    perHostDeadline: perHostDeadline, deadline: deadline,
                                    progress: sink)
            for (ip, observations) in result.ports.sorted(by: { $0.key < $1.key }) {
                sink(.hostUpdated(HostFacts(ip: ip, ports: observations)))
            }
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

    /// The interface whose network contains every target, or the primary one.
    ///
    /// Static and pure so the choice can be tested without a network.
    static func interface(
        reaching targets: [IPv4Address], from provider: any InterfaceProvider
    ) -> NetworkInterface? {
        guard let all = try? provider.interfaces() else { return nil }
        if let exact = all.first(where: { candidate in
            targets.allSatisfy { candidate.network.contains($0) }
        }) {
            return exact
        }
        return try? provider.primaryInterface()
    }
}

/// One probe: a host and a port.
struct SYNProbe: Sendable, Hashable {
    var ip: IPv4Address
    var port: UInt16
}

/// The mutable state of one half-open scan.
///
/// Keyed by the sequence cookie rather than by a probe table, because that is what the
/// reply carries: a SYN-ACK or RST echoes our sequence plus one in its acknowledgement
/// field, so the answer names its own question. The source address is checked as well,
/// since the cookie is a 32-bit hash over a larger space and the pair is what makes it
/// unambiguous.
actor SYNScanState {
    private struct Pending {
        var probe: SYNProbe
        var transmissions = 0
        var expiresAt: MonotonicInstant?
        var sentAt: MonotonicInstant?
        var verdict: PortState?
        var rtt: Duration?
    }

    private var pending: [UInt32: Pending] = [:]
    private var order: [UInt32] = []
    private var clock: SweepClock
    private let attempts: Int
    private let counters: ProbeCounters
    /// The per-scan value mixed into every cookie, so a reply from a previous scan
    /// cannot be matched to a probe in this one.
    private let salt: UInt32
    private(set) var lastTransmissionAt: MonotonicInstant?

    init(
        targets: [IPv4Address], ports: [UInt16],
        attempts: Int, counters: ProbeCounters, budgets: SweepBudgets,
        salt: UInt32 = 0
    ) {
        self.attempts = attempts
        self.counters = counters
        self.salt = salt
        self.clock = SweepClock(budgets: budgets)
        // One flat list across the whole cross product rather than a loop per host.
        // Per-host serialisation is a structural reason conventional scanners are slow:
        // with every probe in one pool a fully filtered host costs the same wall clock
        // as one port on it instead of costing its port count.
        for ip in targets {
            for port in ports {
                let key = IPv4Packet.cookie(target: ip, port: port, salt: salt)
                // A cookie collision would make two probes indistinguishable. At a /24
                // by 36 ports that is nine thousand draws from 2^32 and the chance is
                // about one in half a million, but the handling is free: the loser is
                // dropped rather than overwriting, so a collision costs one unprobed
                // port and never a wrong verdict on another one.
                guard pending[key] == nil else { continue }
                pending[key] = Pending(probe: SYNProbe(ip: ip, port: port))
                order.append(key)
            }
        }
    }

    /// Whether every probe has a verdict or has run out of attempts.
    var isSettled: Bool {
        !pending.values.contains { $0.verdict == nil && ($0.transmissions < attempts || $0.expiresAt != nil) }
    }

    /// Whether every probe has a verdict, which lets the tail wait end early.
    var everyoneAnswered: Bool { !pending.values.contains { $0.verdict == nil } }

    /// When the scan may stop listening.
    func declarationInstant() -> MonotonicInstant? {
        lastTransmissionAt?.advanced(by: clock.tailBudget())
    }

    /// How long until the next outstanding probe is due to be resent.
    func timeUntilNextExpiry() -> Duration? {
        let now = MonotonicInstant.now
        guard let next = pending.values.compactMap(\.expiresAt).min() else { return nil }
        return next > now ? next.duration(since: now) : .zero
    }

    /// The probes that should be sent now, in a stable order.
    func dueProbes(limit: Int) -> [SYNProbe] {
        let now = MonotonicInstant.now
        var due: [SYNProbe] = []
        due.reserveCapacity(min(limit, order.count))
        for key in order {
            guard due.count < limit else { break }
            guard let entry = pending[key], entry.verdict == nil else { continue }
            guard entry.transmissions < attempts else { continue }
            if let expiry = entry.expiresAt {
                if expiry <= now { due.append(entry.probe) }
            } else if entry.sentAt == nil {
                due.append(entry.probe)
            }
        }
        return due
    }

    /// Records which probes actually reached the kernel.
    func recordSends(_ delivered: [SYNProbe], at instant: MonotonicInstant) {
        let window = clock.retransmitBudget()
        for probe in delivered {
            let key = IPv4Packet.cookie(target: probe.ip, port: probe.port, salt: salt)
            guard var entry = pending[key], entry.probe == probe else { continue }
            entry.transmissions += 1
            entry.sentAt = instant
            entry.expiresAt = entry.transmissions >= attempts
                ? nil : instant.advanced(by: window)
            pending[key] = entry
            counters.probeSent()
            counters.probeCompleted()
        }
        if !delivered.isEmpty { lastTransmissionAt = instant }
    }

    /// Folds in one TCP segment.
    ///
    /// The acknowledgement field carries our sequence plus one, so subtracting one
    /// recovers the cookie and the cookie names the probe. The source address is then
    /// checked against the probe's target: without that, a segment from an unrelated
    /// host whose acknowledgement happened to collide would decide a port.
    func record(_ segment: IPv4Packet.Segment, at instant: MonotonicInstant) {
        let key = segment.acknowledgement &- 1
        guard var entry = pending[key] else { return }
        guard entry.probe.ip == segment.source else { return }
        guard entry.probe.port == segment.sourcePort else { return }
        guard entry.verdict == nil else { return }

        // A SYN-ACK is an open port. A RST is a closed one — the host is there and
        // said no, which is strictly more information than silence and must never be
        // collapsed into it.
        let verdict: PortState
        if segment.isSynAck {
            verdict = .open
        } else if segment.isReset {
            verdict = .closed
        } else {
            // Neither. Something answered on our port that is not an answer to a SYN;
            // it decides nothing and the probe stays outstanding.
            return
        }

        counters.replySeen()
        entry.verdict = verdict
        entry.expiresAt = nil
        if let sentAt = entry.sentAt, instant > sentAt {
            let elapsed = instant.duration(since: sentAt)
            entry.rtt = elapsed
            clock.record(elapsed)
        }
        pending[key] = entry
    }

    /// Every verdict, grouped by host.
    ///
    /// A probe that was sent its full quota and never answered is `.filtered`: we asked
    /// and heard silence. A probe that was never sent at all has no entry, because
    /// "not asked" and "asked and silent" are different facts and only one of them is
    /// evidence about the port.
    func observations() -> [IPv4Address: [PortObservation]] {
        var byHost: [IPv4Address: [PortObservation]] = [:]
        for key in order {
            guard let entry = pending[key] else { continue }
            let state: PortState
            if let verdict = entry.verdict {
                state = verdict
            } else if entry.transmissions > 0 {
                state = .filtered
            } else {
                continue
            }
            byHost[entry.probe.ip, default: []].append(PortObservation(
                port: entry.probe.port,
                proto: .tcp,
                state: state,
                service: nil,
                rtt: entry.rtt.map { RTTSample(millis: $0.milliseconds) }
            ))
        }
        for ip in byHost.keys {
            byHost[ip]?.sort { ($0.port, $0.proto.rawValue) < ($1.port, $1.proto.rawValue) }
        }
        return byHost
    }
}

#endif
