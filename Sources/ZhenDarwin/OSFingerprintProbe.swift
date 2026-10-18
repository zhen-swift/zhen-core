// OSFingerprintProbe.swift — one SYN per host, read for everything it discloses.
//
// `EngineCapabilities.osFingerprint` was declared with nothing constructing it. This
// constructs it, and the first thing to say is what it is not: it is not nmap's
// fingerprinting, which sends sixteen probes with deliberately malformed flag
// combinations and matches against a database two decades old. It sends one well-formed
// SYN carrying a full option block, reads the SYN-ACK, and matches what came back
// against the handful of stack lineages in `StackSignatures`.
//
// That is enough to separate Linux from Darwin from Windows from a small embedded
// stack, because those four differ in which TCP options they echo and in what order
// they place them — which is a property of the stack's source, not of its tuning. It is
// not enough to name a version, and the model deliberately has nowhere to put one.
//
// ── Why one probe and not sixteen ──────────────────────────────────────────────
//
// The sixteen exist to separate stacks that agree on everything a legal packet can
// reveal, by seeing how they mishandle illegal ones. That is a real technique and it
// has a real cost: several of those probes crash embedded stacks, which on a home
// network means the camera or the thermostat, and `Study/THEORY.md` already ranks
// fingerprinting below fused identity for exactly the hosts most likely to fall over.
// A scanner whose default reboots a doorbell is not a scanner anyone should run.
//
// So: one legal SYN, to a port already known open. The distinguishing power is lower
// and the failure mode is that a host reports `unmatched`, carrying its features for a
// reader to judge — rather than that it reports nothing because it stopped responding.
//
// ── Why it needs an open port ──────────────────────────────────────────────────
//
// A closed port answers with a RST, and a RST carries no options and a window of zero:
// there is nothing in it to fingerprint. The SYN-ACK from an open port is the only
// packet in this exchange that discloses the stack's preferences, so the probe runs
// after the port scan and only against hosts that have one.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Fingerprints a host's TCP stack from a single SYN-ACK.
public struct OSFingerprintProbe: Sendable {
    /// How this identifies itself in a composition's capability set.
    public static let capability: EngineCapabilities = [.osFingerprint]

    /// How long one host's probe may take.
    public var budget: Duration
    /// Enumerates interfaces, to find the one that reaches the targets.
    public var interfaces: any InterfaceProvider
    /// Supplies the layer-2 destination.
    public var neighbors: any NeighborCache
    /// Where a capture device comes from.
    ///
    /// The engine cannot tell a descriptor this process opened from one a root daemon
    /// opened and passed over XPC. Defaults to a direct open.
    public var capture: CaptureSource = .direct

    /// Creates the probe.
    public init(
        budget: Duration = .milliseconds(1500),
        interfaces: any InterfaceProvider = DarwinInterfaceProvider(),
        neighbors: any NeighborCache = DarwinNeighborCache(),
        capture: CaptureSource = .direct
    ) {
        self.budget = budget
        self.interfaces = interfaces
        self.neighbors = neighbors
        self.capture = capture
    }

    /// What one host's probe produced, or why it produced nothing.
    public struct Outcome: Sendable {
        /// Fingerprints by host, for the hosts that answered.
        public var fingerprints: [IPv4Address: OSFingerprint]
        /// Anything worth saying about the ones that did not.
        public var degradations: [Degradation]
        /// Set when at least one host was fingerprinted.
        public var used: EngineCapabilities
    }

    /// Fingerprints each host, using one port already known to be open on it.
    ///
    /// - Parameter openPorts: a port per host that the scan found open. A host with no
    ///   open port cannot be fingerprinted by this method and is simply absent from the
    ///   result — there is no SYN-ACK to read.
    public func fingerprint(
        _ openPorts: [IPv4Address: UInt16], deadline: Deadline
    ) async -> Outcome {
        var degradations: [Degradation] = []
        guard !openPorts.isEmpty, !deadline.isExpired else {
            return Outcome(fingerprints: [:], degradations: [], used: [])
        }

        let targets = Array(openPorts.keys)
        guard let interface = SYNScanEngine.interface(reaching: targets, from: interfaces),
              let senderMAC = interface.hardwareAddress
        else {
            return Outcome(fingerprints: [:], degradations: [], used: [])
        }

        var hardware: [IPv4Address: MACAddress] = [:]
        if let entries = try? await neighbors.entries() {
            for entry in entries where entry.isComplete { hardware[entry.ip] = entry.mac }
        }

        let sourcePort = UInt16.random(in: 40_000...60_000)
        let salt = UInt32.random(in: UInt32.min...UInt32.max)
        let device: BPFDevice
        do {
            device = try await capture.open(
                interface: interface.name, filter: BPFFilter.tcpDestinedTo(port: sourcePort)
            )
        } catch {
            return Outcome(
                fingerprints: [:],
                degradations: [Degradation(
                    stage: .deepScan, reason: error.reason,
                    recoverable: error != .notPrivileged
                )],
                used: []
            )
        }

        let collector = FingerprintCollector(expected: openPorts, salt: salt)
        let frames = await device.frames()
        let reader = Task {
            for await frame in frames {
                guard let segment = IPv4Packet.parse(frame[frame.indices].span),
                      segment.destinationPort == sourcePort,
                      segment.isSynAck
                else { continue }
                // Read from the same frame the verdict came from. Re-reading the
                // headers here rather than carrying them through `Segment` keeps the
                // scan's parse — which runs nine thousand times — free of fields only
                // this path needs.
                guard let header = IPv4Packet.header(frame[frame.indices].span) else { continue }
                await collector.record(segment, header: header,
                                       options: IPv4Packet.options(frame[frame.indices].span))
            }
        }

        // One SYN per host, all at once. There are as many of these as there are hosts
        // with an open port, which on a consumer segment is a handful.
        var sent = 0
        var frames_: [[UInt8]] = []
        for (ip, port) in openPorts.sorted(by: { $0.key < $1.key }) {
            guard let targetMAC = hardware[ip], ip != interface.address else { continue }
            frames_.append(IPv4Packet.syn(
                target: ip, targetMAC: targetMAC, port: port,
                senderMAC: senderMAC, senderIP: interface.address,
                sourcePort: sourcePort,
                identifier: UInt16.random(in: 1...UInt16.max),
                salt: salt,
                options: IPv4Packet.fingerprintOptions(
                    timestamp: UInt32.random(in: 1...UInt32.max)
                )
            ))
        }
        sent = await device.send(frames_)

        // One wait for all of them, bounded by whichever runs out first.
        let stop = MonotonicInstant.now.advanced(by: min(budget, deadline.remaining))
        while !Task.isCancelled, MonotonicInstant.now < stop {
            if await collector.count == sent { break }
            try? await Task.sleep(for: .milliseconds(5))
        }

        reader.cancel()
        await device.stop()

        let fingerprints = await collector.fingerprints
        if sent > 0, fingerprints.isEmpty {
            degradations.append(Degradation(
                stage: .deepScan,
                reason: """
                    \(sent) stack-fingerprint probe\(sent == 1 ? "" : "s") went out and \
                    nothing answered, so no operating system could be inferred. The port \
                    states and any service names are unaffected.
                    """,
                recoverable: true
            ))
        }
        return Outcome(
            fingerprints: fingerprints,
            degradations: degradations,
            used: fingerprints.isEmpty ? [] : Self.capability
        )
    }
}

/// Accumulates one SYN-ACK per host and turns it into a fingerprint.
actor FingerprintCollector {
    private let expected: [IPv4Address: UInt16]
    private let salt: UInt32
    private(set) var fingerprints: [IPv4Address: OSFingerprint] = [:]

    init(expected: [IPv4Address: UInt16], salt: UInt32) {
        self.expected = expected
        self.salt = salt
    }

    /// How many hosts have answered.
    var count: Int { fingerprints.count }

    /// Folds in one SYN-ACK.
    ///
    /// Matched the same way the scan matches: the acknowledgement recovers the cookie,
    /// and the source address and port are checked against the probe it names. A stray
    /// SYN-ACK from an unrelated connection cannot contribute a fingerprint.
    func record(
        _ segment: IPv4Packet.Segment, header: IPv4Packet.Header, options: [IPv4Packet.Option]
    ) {
        guard let port = expected[segment.source], port == segment.sourcePort else { return }
        guard segment.acknowledgement &- 1
            == IPv4Packet.cookie(target: segment.source, port: port, salt: salt) else { return }
        guard fingerprints[segment.source] == nil else { return }

        var mss: UInt16?
        var scale: UInt8?
        var sack = false
        var timestamps = false
        var order: [String] = []
        for option in options {
            order.append(String(option.kind))
            switch option.kind {
            case IPv4Packet.Option.maximumSegmentSize where option.value.count >= 2:
                mss = UInt16(option.value[0]) << 8 | UInt16(option.value[1])
            case IPv4Packet.Option.windowScale where option.value.count >= 1:
                scale = option.value[0]
            case IPv4Packet.Option.sackPermitted:
                sack = true
            case IPv4Packet.Option.timestamps:
                timestamps = true
            default:
                break
            }
        }

        let features = TCPStackFeatures(
            observedTTL: header.ttl,
            initialTTL: TCPStackFeatures.inferInitialTTL(from: header.ttl),
            dontFragment: header.dontFragment,
            window: header.window,
            maximumSegmentSize: mss,
            windowScale: scale,
            sackPermitted: sack,
            timestamps: timestamps,
            optionOrder: order.joined(separator: "-")
        )
        fingerprints[segment.source] = StackSignatures.match(features)
    }
}

#endif
