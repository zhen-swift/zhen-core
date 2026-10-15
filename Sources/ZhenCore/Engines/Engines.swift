// Engines.swift — the protocol surface consumers program against.
//
// Two protocols, because privilege changes how discovery and port scanning work and
// changes nothing else in the pipeline. Nothing downstream may branch on which
// implementation it received; that is what `capabilities` is for.
//
// ── Shape change from the original ───────────────────────────────────────────────
//
// The original protocols were `DiscoveryEngine.discover(network:interface:deadline:
// progress:)` and `PortScanEngine.scan(...)` — terminal only, with progress pushed
// through an injected sink. The brief supersedes that with a two-entry-point shape
// and both consumers' briefs are written against the new names, so the new shape
// wins. `ProgressSink` survives as the internal plumbing that `stream(_:deadline:)`
// is built out of, because an engine implementation still wants to emit from deep
// inside a probe loop without threading a continuation through every function.
//
// Two entry points rather than one, and expressing the terminal form as "collect the
// stream" would be the wrong default: the terminal form can batch aggressively and
// skip per-event allocation across 65,000 probes, and the streaming form cannot.
// They have genuinely different consumers — a live UI binds to the stream, a script
// redirecting to a file wants the envelope.

/// Whether an engine needs privileges, and how it got its results.
public enum EngineKind: String, Sendable, Hashable, CaseIterable, Codable {
    /// Runs as a normal user. The default, and it must stay fully functional —
    /// unprivileged ICMP datagram sockets are the reason this tool needs no password.
    case unprivileged = "unprivileged"
    /// Layer-2 sweep over BPF. Needs root, finds hosts that answer nothing else.
    case privilegedBPF = "privileged_bpf"
    /// Both, merged. Running as root must never find *fewer* hosts than running
    /// unprivileged, which an either/or branch would cause by losing ICMP-only
    /// hosts. Composition is the reason these are protocols.
    case composite = "composite"
}

/// What an engine can actually do.
///
/// An OptionSet so a surface can say "OS fingerprint unavailable — requires the
/// privileged engine" without knowing which engine is installed.
public struct EngineCapabilities: OptionSet, Sendable, Hashable, Codable {
    /// The underlying bitfield. Present because `OptionSet` requires it; the wire
    /// form is the name list, not this number.
    public let rawValue: Int
    /// Builds a capability set from a raw bitfield.
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// Layer-2 ARP sweep: this engine puts ARP requests on the wire itself.
    ///
    /// **Not the neighbour table.** Reading what the kernel already knows is
    /// `neighborTable`, and the two were the same member until 2026-09-12, when a
    /// packet capture taken for the measurement study showed the unprivileged engine
    /// claiming `arpSweep` while emitting no ARP of its own — the frames in the capture
    /// were the kernel resolving next-hop for the ICMP datagrams, which is a
    /// side-effect of a probe rather than a probe. A capability that overstates defeats
    /// the point of having capabilities: a surface that gates an ARP-sweep feature on
    /// this flag would enable it against an engine that will never send an ARP frame.
    ///
    /// No engine sets this today. It is what `BPFDiscoveryEngine` will claim.
    public static let arpSweep       = EngineCapabilities(rawValue: 1 << 0)
    /// ICMP echo sweep.
    public static let icmpSweep      = EngineCapabilities(rawValue: 1 << 1)
    /// Half-open SYN scanning.
    public static let synScan        = EngineCapabilities(rawValue: 1 << 2)
    /// TCP/IP stack fingerprinting.
    public static let osFingerprint  = EngineCapabilities(rawValue: 1 << 3)
    /// Full TCP connect scanning, which every engine can do.
    public static let connectScan    = EngineCapabilities(rawValue: 1 << 4)
    /// Banner grabbing on an established connection.
    public static let bannerProbe    = EngineCapabilities(rawValue: 1 << 5)
    /// The kernel's neighbour table, read as a discovery source.
    ///
    /// Worth advertising in its own right rather than folding into a probe capability:
    /// it is how a scan reports a host it never got an answer from, which is a thing a
    /// caller displaying results genuinely wants to know about them.
    public static let neighborTable  = EngineCapabilities(rawValue: 1 << 6)
    /// UDP port probing, with `open_filtered` for silence.
    public static let udpScan        = EngineCapabilities(rawValue: 1 << 7)

    /// Stable wire names, in bit order.
    static let names: [(EngineCapabilities, String)] = [
        (.arpSweep, "arp_sweep"),
        (.icmpSweep, "icmp_sweep"),
        (.synScan, "syn_scan"),
        (.osFingerprint, "os_fingerprint"),
        (.connectScan, "connect_scan"),
        (.bannerProbe, "banner_probe"),
        (.neighborTable, "neighbor_table"),
        (.udpScan, "udp_scan"),
    ]

    /// The capabilities present, as stable wire names.
    public var names: [String] {
        Self.names.filter { contains($0.0) }.map(\.1)
    }

    /// Encodes as an array of names rather than the raw bitfield.
    ///
    /// A bitfield in JSON is a number whose meaning lives in this source file: a
    /// consumer in another language reading `capabilities: 18` learns nothing, and a
    /// reordered case here silently changes what every archived report meant.
    /// `["icmp_sweep", "connect_scan"]` survives both.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let decoded = try container.decode([String].self)
        var result: EngineCapabilities = []
        let table = Dictionary(uniqueKeysWithValues: Self.names.map { ($0.1, $0.0) })
        for name in decoded {
            // An unknown capability is a document from a newer build. Ignore it
            // rather than failing: the report is still readable and the schema
            // version is the thing that guards a genuinely breaking change.
            if let capability = table[name] { result.insert(capability) }
        }
        self = result
    }

    /// Encodes to the wire form described above.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(names)
    }
}

/// Which ports to probe.
public struct PortSpec: Sendable, Hashable, Codable {
    /// The ports, in the order they will be probed.
    public var ports: [UInt16]

    /// Builds a spec from an explicit port list.
    /// UDP ports, in the order they will be probed. Empty unless a spec said `U:`.
    ///
    /// A separate list rather than a transport on each number, because the two are
    /// probed by different engines with different outcomes — `open_filtered` exists only
    /// on this side — and every existing reader of `ports` means TCP.
    public var udpPorts: [UInt16]

    public init(_ ports: [UInt16], udp udpPorts: [UInt16] = []) {
        self.ports = ports
        self.udpPorts = udpPorts
    }

    /// Every probe this spec asks for, both transports.
    public var probeCount: Int { ports.count + udpPorts.count }

    /// What a home LAN actually answers on. Deliberately small — a deep scan is a
    /// deliberate act, not the default, and 65,535 ports across a /24 is 16 million
    /// probes for almost no additional information.
    public static let commonServices = PortSpec([
        21, 22, 23, 25, 53, 80, 111, 139, 143, 443, 445, 515, 548, 554,
        631, 993, 995, 1900, 3128, 3306, 3389, 5000, 5060, 5353, 5432,
        5900, 7000, 8006, 8008, 8009, 8043, 8080, 8443, 8883, 9100, 32400,
    ])

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ports
        case udpPorts = "udp_ports"
    }

    /// Tolerates a spec encoded before `udp_ports` existed.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            try container.decode([UInt16].self, forKey: .ports),
            udp: try container.decodeIfPresent([UInt16].self, forKey: .udpPorts) ?? []
        )
    }
}

/// What to scan.
///
/// Carries the interface as well as the network because a multi-homed machine has to
/// bind to a specific address: an SSDP M-SEARCH sent from `INADDR_ANY` leaks out of a
/// VPN tunnel, and the results come back describing somebody else's network.
public struct ScanTarget: Sendable, Hashable, Codable {
    /// The network to sweep.
    public var network: IPv4Network
    /// The interface to send from.
    public var interface: NetworkInterface
    /// An explicit address list, overriding `network.hosts`. Absent means the whole
    /// network — which is the normal case; this exists for a rescan of specific
    /// hosts.
    public var addresses: [IPv4Address]?
    /// How long to wait for each address, and how often to ask it. Nil is study 1's
    /// schedule: one learned tail for the whole network.
    ///
    /// On the target rather than on an engine because it is a fact about THIS scan of
    /// THIS network — built from its history just before the sweep — and an engine is
    /// configured once and reused. Not encoded: a plan is an input the caller rebuilds,
    /// and what was used is reported as `run.reach`.
    public var reach: ReachPlan? = nil

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        network: IPv4Network, interface: NetworkInterface, addresses: [IPv4Address]? = nil,
        reach: ReachPlan? = nil
    ) {
        self.network = network
        self.interface = interface
        self.addresses = addresses
        self.reach = reach
    }

    /// Builds a target covering an interface's own network.
    public init(scanning interface: NetworkInterface) {
        self.init(network: interface.network, interface: interface)
    }

    /// The addresses that will actually be probed, or a refusal explaining why none
    /// will be.
    ///
    /// The safe entry point, and the reason it returns a sum type rather than an
    /// array: a network wider than `IPv4Network.minimumEnumerablePrefix` enumerates
    /// to nothing, and an engine that took that at face value would send zero probes
    /// and report `.complete` with an empty device list — telling a user with a /8
    /// that their network is empty. An empty array and a refusal are different
    /// answers and the type now says so.
    public var resolution: TargetResolution {
        if let addresses {
            // An explicit list is always honoured: a caller that named the addresses
            // has already decided what it wants probed, however wide the network is.
            return addresses.isEmpty
                ? .refused(Degradation(
                    stage: .setup,
                    reason: "This scan was given an empty address list, so there was nothing to probe.",
                    recoverable: false))
                : .addresses(addresses)
        }
        guard network.isEnumerable else {
            return .refused(Degradation(
                stage: .setup,
                reason: """
                    \(network) covers \(network.hostCount) addresses, which is too many to sweep \
                    in one pass. Narrow the target to a /\(IPv4Network.minimumEnumerablePrefix) or \
                    smaller, or split it into \(network.chunked().count) chunks and scan them in turn.
                    """,
                recoverable: false))
        }
        let hosts = network.hosts
        return hosts.isEmpty
            ? .refused(Degradation(
                stage: .setup,
                reason: "\(network) contains no scannable host addresses.",
                recoverable: false))
            : .addresses(hosts)
    }

    /// The addresses that will actually be probed, or an empty array if the target is
    /// refused.
    ///
    /// Kept for callers that have already checked `resolution`. Prefer `resolution`:
    /// this one cannot distinguish "nothing to scan" from "refused to scan".
    public var resolvedAddresses: [IPv4Address] {
        if case .addresses(let addresses) = resolution { return addresses }
        return []
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case network
        case interface
        case addresses
    }
}

/// What a `ScanTarget` resolves to: addresses to probe, or a reason none will be.
public enum TargetResolution: Sendable, Hashable {
    /// The addresses to probe. Never empty.
    case addresses([IPv4Address])
    /// Nothing will be probed, and this says why. The caller attaches the degradation
    /// to the run and reports an outcome that is honest about having done nothing —
    /// never `.complete` with an empty device list.
    case refused(Degradation)

    /// The addresses, or nil if the target was refused.
    public var addresses: [IPv4Address]? {
        if case .addresses(let addresses) = self { return addresses }
        return nil
    }

    /// The refusal, or nil if the target resolved.
    public var refusal: Degradation? {
        if case .refused(let degradation) = self { return degradation }
        return nil
    }
}

/// An envelope, not a throw.
///
/// A deadline hit is a normal return at every level. `throws` would be the wrong
/// shape because a thrown error discards the partial work of every sibling probe,
/// and partial results are the point rather than a failure mode.
public struct DiscoveryResult: Sendable, Hashable {
    /// What was found.
    public var hosts: [HostFacts]
    /// What did not work.
    public var degradations: [Degradation]
    /// Which capabilities were actually exercised — which can be less than the
    /// engine advertises, if BPF was busy and it fell back.
    public var usedCapabilities: EngineCapabilities
    /// How the run ended. `.deadlineExpired` here is a success carrying partial
    /// results.
    public var outcome: Outcome
    /// What it cost.
    public var timing: Timing
    /// What the neighbour watch did, for an engine that has one. Nil for an engine that
    /// never watches — the layer-2 sweep, a fixture — which is different from a watch
    /// that was switched off.
    public var neighborWatch: NeighborWatchReport?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        hosts: [HostFacts] = [],
        degradations: [Degradation] = [],
        usedCapabilities: EngineCapabilities = [],
        outcome: Outcome = .complete,
        timing: Timing = Timing(),
        neighborWatch: NeighborWatchReport? = nil
    ) {
        self.hosts = hosts
        self.degradations = degradations
        self.usedCapabilities = usedCapabilities
        self.outcome = outcome
        self.timing = timing
        self.neighborWatch = neighborWatch
    }
}

/// The port-scan equivalent of `DiscoveryResult`, and non-throwing for the same
/// reason.
public struct PortScanResult: Sendable, Hashable {
    /// Observations by host. A host with an entry whose states are all `.filtered`
    /// is different from a host with no entry at all, and both are different from a
    /// host whose ports are `.closed`.
    public var ports: [IPAddress: [PortObservation]]
    /// Stack fingerprints, for the hosts a fingerprint probe reached.
    ///
    /// Here rather than on `PortObservation` because a fingerprint describes the HOST,
    /// not a port — the port is only how the SYN-ACK was elicited. Absent for a host
    /// with no open port, because a RST carries no options and there is nothing in it
    /// to read.
    public var fingerprints: [IPv4Address: OSFingerprint]
    /// What did not work.
    public var degradations: [Degradation]
    /// Which capabilities were exercised.
    public var usedCapabilities: EngineCapabilities
    /// How the run ended.
    public var outcome: Outcome
    /// What it cost.
    public var timing: Timing

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        ports: [IPAddress: [PortObservation]] = [:],
        fingerprints: [IPv4Address: OSFingerprint] = [:],
        degradations: [Degradation] = [],
        usedCapabilities: EngineCapabilities = [],
        outcome: Outcome = .complete,
        timing: Timing = Timing()
    ) {
        self.ports = ports
        self.fingerprints = fingerprints
        self.degradations = degradations
        self.usedCapabilities = usedCapabilities
        self.outcome = outcome
        self.timing = timing
    }
}

extension PortScanResult {
    /// The hosts with a `HostFacts` shape — the v4 ones — in address order, for the
    /// progress events an engine emits. `HostFacts` is keyed by an IPv4 address; a v6
    /// host's observations are in `ports` and reach the artifact from there.
    public var ipv4Hosts: [(ip: IPv4Address, observations: [PortObservation])] {
        ports.compactMap { address, observations in
            address.v4.map { (ip: $0, observations: observations) }
        }
        .sorted { $0.ip < $1.ip }
    }
}

/// Targets split by whether an IPv4-only engine can probe them.
///
/// An engine given a target it cannot probe must say so. Leaving it out of `ports`
/// without a word is indistinguishable from a host that answered nothing, and doing
/// something other than what was asked without saying so is the one thing a scanner may
/// not do. So the unprobed targets become a degradation naming them, and with no v6
/// target in the list there is no degradation at all — a v4 run is unchanged.
public struct IPv4OnlyTargets: Sendable {
    /// The targets the engine will probe.
    public let probed: [IPv4Address]
    /// What the artifact says about the rest. Empty when there is no rest.
    public let degradations: [Degradation]

    /// - Parameters:
    ///   - targets: what the engine was asked to probe.
    ///   - engine: the engine's name as a person would say it, e.g. "the SYN scan".
    public init(_ targets: [IPAddress], engine: String) {
        probed = targets.compactMap(\.v4)
        let skipped = targets.filter { $0.v4 == nil }
        degradations = skipped.isEmpty ? [] : [Degradation(
            stage: .deepScan,
            reason: """
                \(engine) probes IPv4 only, so \(skipped.count) IPv6 \
                target\(skipped.count == 1 ? " was" : "s were") not scanned: \
                \(skipped.map(\.description).joined(separator: ", ")).
                """,
            recoverable: false
        )]
    }
}

extension PortScanResult {
    /// Two engines' results over the same targets, as one — how `zhen ports` reports a
    /// spec with both TCP and UDP in it.
    ///
    /// The worse outcome wins, so a UDP half cut short by the deadline is not reported
    /// as a complete run on the strength of a TCP half that finished. Observations are
    /// joined per host and put back in canonical order; stages are kept in the order the
    /// engines ran.
    public func combined(with other: PortScanResult) -> PortScanResult {
        var ports = self.ports
        for (host, observations) in other.ports {
            ports[host, default: []].append(contentsOf: observations)
        }
        for host in ports.keys { ports[host]?.sort(by: PortObservation.canonicalOrder) }
        let stages = timing.stages + other.timing.stages
        let elapsed = stages.reduce(0) { $0 + $1.elapsedMillis }
        let sent = timing.probesSent + other.timing.probesSent
        return PortScanResult(
            ports: ports,
            fingerprints: fingerprints.merging(other.fingerprints) { mine, _ in mine },
            degradations: degradations + other.degradations,
            usedCapabilities: usedCapabilities.union(other.usedCapabilities),
            outcome: Self.worse(outcome, other.outcome),
            timing: Timing(
                stages: stages,
                probesSent: sent,
                repliesSeen: timing.repliesSeen + other.timing.repliesSeen,
                peakConcurrency: max(timing.peakConcurrency, other.timing.peakConcurrency),
                effectiveProbesPerSecond: elapsed > 0 ? Double(sent) * 1000 / elapsed : 0
            )
        )
    }

    private static func worse(_ lhs: Outcome, _ rhs: Outcome) -> Outcome {
        func rank(_ outcome: Outcome) -> Int {
            switch outcome {
            case .complete: 0
            case .deadlineExpired: 1
            case .cancelled: 2
            }
        }
        return rank(lhs) >= rank(rhs) ? lhs : rhs
    }
}

/// Finds hosts.
///
/// Neither entry point throws and neither can fail: a probe that gets no answer is a
/// value, and a budget that expires is a normal return carrying what was gathered.
public protocol HostDiscovery: Sendable {
    /// Which engine this is and what it can do.
    var descriptor: EngineDescriptor { get }

    /// Terminal form: everything, once, when it is done or the budget expires.
    ///
    /// Free to batch aggressively and skip per-event allocation, which is why it is
    /// not implemented as "collect the stream".
    func discover(_ target: ScanTarget, deadline: Deadline) async -> DiscoveryResult

    /// Terminal form that also reports progress as it goes.
    ///
    /// This exists because the obvious composition — drive a live display from
    /// `stream(_:deadline:)` and build the artifact from what the display saw — is
    /// exactly the mistake the buffering policy is designed to make possible. The
    /// progress channel is `.bufferingNewest` and may drop events; that is only safe
    /// because results travel in the terminal envelope instead. A consumer that wants
    /// both a live display and a trustworthy artifact needs one call that provides
    /// both, or it will quietly build the artifact from the lossy channel and report
    /// `.complete` over a device list with holes in it.
    ///
    /// The sink is for display only. Nothing an implementation emits through it is
    /// load-bearing, and everything that matters is in the returned `DiscoveryResult`.
    func discover(
        _ target: ScanTarget, deadline: Deadline, progress: ProgressSink
    ) async -> DiscoveryResult

    /// Streaming form: hosts as they answer, which is what a live UI binds to and
    /// what makes the CLI feel instant.
    ///
    /// Never fails; degradations arrive as `.degraded` events. Implementations build
    /// the stream with `ProbeStream.make(buffering:)` so the backpressure policy is
    /// declared rather than defaulted, and set `continuation.onTermination` to close
    /// their sockets — it fires on consumer cancellation as well as normal
    /// completion, which is exactly the lifetime the sockets need.
    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent>
}

extension HostDiscovery {
    /// Discovers with no observer.
    ///
    /// Defaulted so a conformance only has to write the sink-carrying form, which is
    /// the one that can serve both consumers.
    public func discover(_ target: ScanTarget, deadline: Deadline) async -> DiscoveryResult {
        await discover(target, deadline: deadline, progress: .ignore)
    }
}

/// Probes ports on hosts already found.
public protocol PortScanning: Sendable {
    /// Which engine this is and what it can do.
    var descriptor: EngineDescriptor { get }

    /// Terminal form.
    ///
    /// - Parameters:
    ///   - targets: the hosts to probe. Discovery has already established these are
    ///     worth probing; a port scan does not rediscover.
    ///   - ports: which ports to try, in probe order.
    ///   - perHostDeadline: the starting per-host budget. An implementation with RTT
    ///     samples should narrow it per host from `RTTEstimator.timeout()` rather than
    ///     spending this on every host — waiting a fixed interval for a host that
    ///     answers in 400 microseconds is exactly why conventional scanners are slow
    ///     on a LAN.
    ///   - deadline: the budget for the whole stage, which bounds the sum of the
    ///     per-host budgets however many hosts there turn out to be.
    /// - Returns: an envelope. Never throws; an expired budget is a normal return
    ///   carrying whatever was observed.
    func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) async -> PortScanResult

    /// Terminal form that also reports progress. See `HostDiscovery` for why both
    /// exist as one call rather than as two the caller composes.
    func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> PortScanResult

    /// Streaming form: observations as they are made.
    ///
    /// - Parameters:
    ///   - targets: the hosts to probe.
    ///   - ports: which ports to try.
    ///   - perHostDeadline: the starting per-host budget.
    ///   - deadline: the budget for the whole stage.
    /// - Returns: a stream that never fails. Degradations arrive as `.degraded` events.
    func stream(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) -> AsyncStream<ProbeEvent>
}

extension PortScanning {
    /// Scans with no observer.
    public func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) async -> PortScanResult {
        await scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                   deadline: deadline, progress: .ignore)
    }
}

/// Which port-scanning mechanism a run should use.
///
/// The engine has always chosen for you: half-open where a capture device is available,
/// a full connection where it is not. That is the right default and it makes one thing
/// impossible — asking for a connect scan ON PURPOSE.
///
/// **Connect scan is not merely the fallback.** It is the permitted option on a network
/// where you may open sockets but not forge frames, it completes the handshake so a
/// banner comes for free rather than costing a second connection, and it is what an
/// unprivileged process can actually do. A tool that only reaches it by failing to find
/// privilege cannot be asked to measure it.
public enum PortScanType: String, Sendable, CaseIterable, Codable {
    /// Half-open. One SYN per port, no handshake completed, requires a capture device.
    case syn
    /// A full `connect()`. No privilege, and the handshake it completes is visible to
    /// the far side — which is the difference the two can be told apart by.
    case connect
    /// Today's behaviour exactly: `syn` where the capture device opened, `connect`
    /// otherwise.
    case auto
}
