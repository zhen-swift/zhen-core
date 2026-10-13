// TCPConnectScan.swift — non-blocking connect, and the three-valued answer it gives.
//
// The state machine is fixed by the platform: `O_NONBLOCK`, `connect`, `EINPROGRESS`,
// wait for writability, then `getsockopt(SO_ERROR)` for the verdict. Doing it any other
// way means blocking in `connect`, and a blocked descriptor on the cooperative pool
// does not slow the scan down, it stops it.
//
// What matters as much as the mechanics is refusing to collapse the answer:
//
//   ECONNREFUSED  → .closed.   A RST came back. The host is THERE and said no. This is
//                              positive information and it is strictly more than
//                              silence.
//   SO_ERROR == 0 → .open.
//   nothing       → .filtered. Says only that nothing came back in time.
//
// A naive scanner reports "not open" for the last two together and throws away the only
// signal separating a live host behind a firewall from an address with nothing on it.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Unprivileged port scanning by full TCP connect.
public struct TCPConnectScanEngine: PortScanning {
    /// How this engine identifies itself in the artifact.
    public let descriptor = EngineDescriptor(
        name: "tcp-connect",
        kind: .unprivileged,
        capabilities: [.connectScan]
    )

    /// How many probes may be in flight. Derived from the granted descriptor limit —
    /// this is the stage that actually consumes descriptors, one per port per host.
    public var concurrency: Int

    /// Creates the engine.
    public init(concurrency: Int = 256) {
        self.concurrency = concurrency
    }

    /// Terminal form, with an optional observer.
    ///
    /// - Parameters:
    ///   - targets: the hosts to probe. Discovery has already established these are
    ///     worth probing; a port scan does not rediscover.
    ///   - ports: which ports to try, in probe order.
    ///   - perHostDeadline: the CEILING on a per-host budget, not the budget itself.
    ///     The actual wait comes from that host's `RTTEstimator`, which learns from the
    ///     ports already probed on it. Spending this interval on every port of every
    ///     host is precisely the fixed-timeout behaviour this file's header criticises,
    ///     and an earlier version of this engine did exactly that — it took the
    ///     parameter and never built an estimator at all.
    ///   - deadline: the budget for the whole stage.
    ///   - progress: display only. Everything load-bearing is in the return value.
    public func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> PortScanResult {
        let watch = Stopwatch()
        let counters = ProbeCounters()
        progress(.stageStarted(.deepScan))

        // Per-host estimators, shared across that host's ports. The first port probed
        // on a host has no history and gets `perHostDeadline` as its ceiling; every
        // port after it waits on what that host has actually shown, which on a LAN
        // collapses from hundreds of milliseconds to single digits after one reply.
        let estimators = HostEstimators(ceiling: perHostDeadline)

        // One flat work list rather than a loop over hosts. Per-host serialization is
        // one of the structural reasons a conventional scanner is slow: with the whole
        // cross product in one pool, a host that is entirely filtered costs the same
        // wall clock as one port on it, instead of costing its port count.
        let probes = targets.flatMap { ip in ports.ports.map { Probe(ip: ip, port: $0) } }

        let run = await boundedPool(
            over: probes,
            concurrency: concurrency,
            deadline: deadline
        ) { probe -> ProbeOutcome<PortObservation> in
            counters.probeSent()
            defer { counters.probeCompleted() }
            let budget = min(await estimators.budget(for: probe.ip), deadline.remaining)
            let observed = await Self.probe(probe, budget: budget)
            switch observed {
            case .cancelled:
                // A cancelled probe learned nothing. Reporting `.filtered` would be a
                // positive claim — "we asked and heard silence" — manufactured out of
                // the fact that we stopped asking, so Ctrl-C would fabricate port
                // evidence for every host it interrupted.
                return .silent
            case .observed(let observation, let rtt):
                if observation.state != .filtered { counters.replySeen() }
                if let rtt { await estimators.record(rtt, for: probe.ip) }
                return .observed(observation)
            }
        }

        var byHost: [IPAddress: [PortObservation]] = [:]
        for (probe, observation) in run.results {
            byHost[probe.ip, default: []].append(observation)
        }
        for ip in byHost.keys {
            byHost[ip]?.sort { ($0.port, $0.proto.rawValue) < ($1.port, $1.proto.rawValue) }
        }
        let snapshot = counters.snapshot()
        let stage = StageTiming(
            stage: .deepScan,
            elapsedMillis: watch.elapsedMillis,
            probesSent: snapshot.probesSent,
            repliesSeen: snapshot.repliesSeen
        )
        progress(.stageFinished(stage))
        return PortScanResult(
            ports: byHost,
            degradations: [],
            usedCapabilities: descriptor.capabilities,
            // The pool knows why it stopped; the artifact should say the same thing.
            outcome: run.termination.outcome,
            timing: Timing(stages: [stage], counters: snapshot)
        )
    }

    /// Streaming form.
    public func stream(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task { [self] in
            sink(.stageStarted(.deepScan))
            let result = await scan(targets, ports: ports,
                                    perHostDeadline: perHostDeadline, deadline: deadline,
                                    progress: sink)
            for (ip, observations) in result.ipv4Hosts {
                sink(.hostUpdated(HostFacts(ip: ip, ports: observations)))
            }
            for stage in result.timing.stages { sink(.stageFinished(stage)) }
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

    /// One address and port to probe.
    struct Probe: Sendable, Hashable {
        var ip: IPAddress
        var port: UInt16
    }

    /// What one probe learned, keeping "cancelled" distinct from "silent".
    enum Probed: Sendable {
        /// The probe ran to a conclusion.
        case observed(PortObservation, rtt: Duration?)
        /// The probe was abandoned. Not evidence about the port.
        case cancelled
    }

    /// Probes one port.
    ///
    /// The descriptor is an `OwnedDescriptor` and this is where that type earns itself:
    /// there are tens of thousands of these, every early return is a place a raw `Int32`
    /// would leak, and a leak here exhausts the process limit and fails the scan rather
    /// than merely wasting memory. `consuming close()` makes a second close a compile
    /// error on every one of those paths.
    static func probe(_ probe: Probe, budget: Duration) async -> Probed {
        let raw = socket(socketFamily(probe.ip), SOCK_STREAM, IPPROTO_TCP)
        guard raw >= 0 else {
            // Out of descriptors, almost certainly. Reported as filtered rather than
            // invented as closed: we learned nothing about the port.
            return .observed(PortObservation(port: probe.port, state: .filtered), rtt: nil)
        }
        guard setNonBlocking(raw) else {
            _ = Darwin.close(raw)
            return .observed(PortObservation(port: probe.port, state: .filtered), rtt: nil)
        }
        // Do not linger on close. Tens of thousands of sockets in TIME_WAIT would
        // exhaust the ephemeral port range long before the scan finished.
        var linger = linger(l_onoff: 1, l_linger: 0)
        _ = unsafe setsockopt(raw, SOL_SOCKET, SO_LINGER, &linger,
                              socklen_t(MemoryLayout<linger>.size))

        let watch = Stopwatch()
        let started = withSocketAddress(probe.ip, port: probe.port) { addr, length in
            unsafe connect(raw, addr, length)
        }

        if started == 0 {
            // Connected without waiting — a loopback or an already-cached path.
            _ = Darwin.close(raw)
            return .observed(
                PortObservation(port: probe.port, state: .open,
                                rtt: RTTSample(measured: watch.elapsed)),
                rtt: watch.elapsed
            )
        }
        if errno != EINPROGRESS {
            let state = Self.state(for: errno)
            _ = Darwin.close(raw)
            return .observed(
                PortObservation(port: probe.port, state: state,
                                rtt: state == .closed ? RTTSample(measured: watch.elapsed) : nil),
                rtt: state == .closed ? watch.elapsed : nil
            )
        }

        // From here the descriptor belongs to the readiness source, which closes it in
        // its cancel handler. Nothing below may close it, and nothing below does.
        switch await Readiness.connectOutcome(owning: raw, within: budget) {
        case .cancelled:
            return .cancelled
        case .timedOut:
            // Silence. Not "closed" — we do not know whether anything is there.
            return .observed(PortObservation(port: probe.port, state: .filtered), rtt: nil)
        case .resolved(let failure):
            let elapsed = watch.elapsed
            if failure == 0 {
                return .observed(
                    PortObservation(port: probe.port, state: .open,
                                    rtt: RTTSample(measured: elapsed)),
                    rtt: elapsed
                )
            }
            let state = Self.state(for: failure)
            return .observed(
                PortObservation(
                    port: probe.port,
                    state: state,
                    // A refusal is a real round trip and worth timing; silence is not.
                    rtt: state == .closed ? RTTSample(measured: elapsed) : nil
                ),
                rtt: state == .closed ? elapsed : nil
            )
        }
    }

    /// Maps a connect failure to a port state.
    ///
    /// The `ECONNREFUSED` line is the one that matters: a RST is the host telling us it
    /// exists. Host- and network-unreachable are `.filtered` because they say something
    /// about the path rather than the port, and reporting them as closed would claim
    /// knowledge of a host we never reached.
    static func state(for code: Int32) -> PortState {
        switch code {
        case 0: .open
        case ECONNREFUSED: .closed
        default: .filtered
        }
    }
}

/// Per-host round-trip estimates, shared across that host's ports.
///
/// The reason this exists at all: without it the deep scan spends the caller's fixed
/// budget on every port of every host, which is exactly the behaviour that makes a
/// conventional scanner slow on a LAN. A host that refused port 22 in 0.4 ms has told
/// us what it costs to talk to, and ports 80 and 443 should not each be given six
/// hundred milliseconds to say the same thing.
actor HostEstimators {
    private var estimators: [IPAddress: RTTEstimator] = [:]
    private let ceiling: Duration

    init(ceiling: Duration) {
        self.ceiling = ceiling
    }

    /// The budget for the next probe to a host.
    ///
    /// `perHostDeadline` acts as the ceiling and as the opening guess. Once a host has
    /// answered anything — open or refused — its own estimate takes over.
    func budget(for address: IPAddress) -> Duration {
        guard let estimator = estimators[address], estimator.acceptedSamples > 0 else {
            return ceiling
        }
        return min(estimator.timeout(ceiling: ceiling), ceiling)
    }

    /// Folds in a completed round trip.
    ///
    /// Only conclusive probes are recorded. A timeout is not a round-trip sample — it
    /// is the absence of one — and feeding it in would teach the estimator that this
    /// host is exactly as slow as the budget we happened to give it.
    func record(_ sample: Duration, for address: IPAddress) {
        var estimator = estimators[address] ?? RTTEstimator()
        estimator.record(sample)
        estimators[address] = estimator
    }
}

#endif
