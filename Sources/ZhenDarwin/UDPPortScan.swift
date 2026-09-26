// UDPPortScan.swift — UDP ports, with the fourth state.
//
// Three outcomes, and they are the whole design:
//
//   a datagram back from the port      open           something is listening
//   ICMP port-unreachable               closed         the host said no one is
//   silence                             open_filtered  and NEVER filtered
//
// Silence on TCP is `filtered` because a live TCP stack answers every SYN. Silence on UDP
// is not evidence of anything: an open port ignoring a request it did not understand and
// a firewall dropping it look identical from here. Calling it `filtered` would under-report
// in exactly the direction `Ports.swift` warns about, and this project spent a schema bump
// on `open_filtered` so that it would not have to.
//
// Other ICMP errors — host or network unreachable, administratively prohibited — are
// `filtered`: they are a positive statement about the path, not silence.
//
// ── Why each probe owns a connected socket ───────────────────────────────────────────
//
// See `UDPProbe`. An unconnected socket never learns of an ICMP error; a connected one
// has the kernel hand it over as ECONNREFUSED. That needs no privilege — which is why this
// engine is available without the helper, like the connect scan.
//
// ── What this engine cannot fix ──────────────────────────────────────────────────────
//
// Hosts rate-limit ICMP port-unreachable — Linux to about one a second by default. A
// rate-limited "closed" arrives as silence and is reported `open_filtered`, which is
// honest (we do not know) and lossy (a second scan might know). No concurrency setting
// changes a limit enforced at the target.

#if canImport(Darwin)
import Darwin
import Dispatch
import ZhenCore

public struct DarwinUDPPortScan: PortScanning {
    public let descriptor = EngineDescriptor(
        name: "udp",
        kind: .unprivileged,
        capabilities: [.udpScan]
    )

    /// Probes in flight. Far below the TCP engine's, because the constraint is not our
    /// descriptors but the target's ICMP budget: more closed ports probed per second than
    /// the target will answer turns `closed` into `open_filtered`.
    public var concurrency: Int

    public init(concurrency: Int = 32) {
        self.concurrency = concurrency
    }

    /// Probes `ports.udpPorts`. `ports.ports`, the TCP list, is not this engine's.
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
        let probes = targets.flatMap { ip in ports.udpPorts.map { Probe(ip: ip, port: $0) } }
        let run = await boundedPool(
            over: probes,
            concurrency: concurrency,
            deadline: deadline
        ) { probe -> ProbeOutcome<PortObservation> in
            counters.probeSent()
            defer { counters.probeCompleted() }
            let outcome = await Self.probe(probe, budget: min(perHostDeadline, deadline.remaining))
            guard let observation = outcome else { return .silent }
            if observation.state != .openFiltered { counters.replySeen() }
            return .observed(observation)
        }

        var byHost: [IPv4Address: [PortObservation]] = [:]
        for (probe, observation) in run.results {
            byHost[probe.ip, default: []].append(observation)
        }
        for ip in byHost.keys { byHost[ip]?.sort(by: PortObservation.canonicalOrder) }

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
            usedCapabilities: descriptor.capabilities,
            outcome: run.termination.outcome,
            timing: Timing(stages: [stage], counters: snapshot)
        )
    }

    public func stream(
        _ targets: [IPv4Address],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task { [self] in
            let result = await scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                                    deadline: deadline, progress: sink)
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

    struct Probe: Sendable, Hashable {
        var ip: IPv4Address
        var port: UInt16
    }

    /// How one probe ended, before it is an observation.
    enum Ending: Sendable, Equatable {
        case answered([UInt8])
        case refused
        case unreachable
        case silent
        case cancelled
    }

    /// Probes one port. Nil when nothing was learned — the socket could not be opened,
    /// or the probe was cancelled — which is not the same as silence and is not reported
    /// as it.
    static func probe(_ probe: Probe, budget: Duration) async -> PortObservation? {
        guard let socket = try? UDPProbe(connectingTo: probe.ip, port: probe.port,
                                         queue: ReadinessQueue.shared)
        else { return nil }
        let request = UDPPayloads.payload(for: probe.port)
        let bytes = request?.bytes ?? []
        let watch = Stopwatch()
        let ending = await Self.exchange(socket, bytes, within: budget)
        socket.stop()
        return Self.observation(for: ending, port: probe.port, payload: request,
                                elapsed: watch.elapsed)
    }

    /// Sends the request, again at 40% of the budget, and waits for the first event.
    ///
    /// Twice because UDP is lossy and a single lost datagram would otherwise become
    /// `open_filtered` on a port that is plainly open. Not more: a host answering neither
    /// has had its chance, and every resend is another ICMP the target may rate-limit.
    static func exchange(_ socket: UDPProbe, _ bytes: [UInt8], within budget: Duration) async -> Ending {
        let events = socket.events()
        if socket.send(bytes) == ECONNREFUSED { return .refused }
        return await withTaskGroup(of: Ending.self) { group in
            group.addTask {
                for await event in events {
                    switch event {
                    case .datagram(let datagram): return .answered(datagram.payload)
                    case .refused: return .refused
                    case .unreachable: return .unreachable
                    }
                }
                return .cancelled
            }
            group.addTask {
                let resendAt = budget * 0.4
                try? await Task.sleep(for: resendAt)
                if Task.isCancelled { return .cancelled }
                // An ICMP error that arrived since the first send can surface HERE rather
                // than on the reader, and a send that consumes it is the only one that
                // will ever see it.
                if socket.send(bytes) == ECONNREFUSED { return .refused }
                try? await Task.sleep(for: budget - resendAt)
                return Task.isCancelled ? .cancelled : .silent
            }
            let first = await group.next() ?? .cancelled
            group.cancelAll()
            return first
        }
    }

    /// Turns an ending into what the report says. The three-outcome rule lives here and
    /// nowhere else.
    static func observation(
        for ending: Ending, port: UInt16, payload: UDPPayload?, elapsed: Duration
    ) -> PortObservation? {
        switch ending {
        case .answered(let reply):
            // Any datagram from the connected peer is a listener. Whether it is also the
            // service the payload spoke to is a separate question, answered only by the
            // recognizer and never by the port number.
            let service = payload.flatMap { payload in
                payload.recognizes(reply)
                    ? ServiceIdentity(name: payload.service, evidence: .protocolHandshake)
                    : nil
            }
            return PortObservation(port: port, proto: .udp, state: .open, service: service,
                                   rtt: RTTSample(measured: elapsed))
        case .refused:
            return PortObservation(port: port, proto: .udp, state: .closed,
                                   rtt: RTTSample(measured: elapsed))
        case .unreachable:
            return PortObservation(port: port, proto: .udp, state: .filtered)
        case .silent:
            return PortObservation(port: port, proto: .udp, state: .openFiltered)
        case .cancelled:
            return nil
        }
    }
}
#endif
