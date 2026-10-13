// NameResolution.swift — the naming stage: its budget, its envelope, and the ledger
// that arbitrates between its three sources.
//
// ── The decision this file exists to hold ────────────────────────────────────────
//
// Naming is not a probe-and-wait. The ICMP sweep asks a closed question — it knows the
// 254 addresses it cares about, and every one of them either answers or does not, so
// "am I finished" has an answer. A browse has no such thing. mDNS keeps yielding for as
// long as anything is willing to talk, a sleeping device answers through a proxy
// seconds late, and there is no point at which the network says "that was all of them".
//
// So the budget is a product decision rather than a measurement, and it trades two
// things a user actually wants against each other: name more devices, or come back
// sooner. The numbers below are that trade, made once, in one place, with the reasoning
// attached — and reported in the artifact's timing so it can be argued with from the
// output rather than from this comment.

/// How the naming stage divides its time.
///
/// The split is deliberately arithmetic and deliberately in core: it is a decision, not
/// a platform detail, and a reviewer should be able to argue with it without reading
/// any socket code.
public struct NameBudget: Sendable, Hashable {
    /// The whole naming stage.
    public let stage: Deadline
    /// mDNS. Runs concurrently with SSDP.
    public let mdns: Deadline
    /// SSDP. Runs concurrently with mDNS.
    public let ssdp: Deadline
    /// How long the whole stage was granted, as a duration.
    ///
    /// Kept alongside the deadlines because a `Deadline` is a point on the monotonic
    /// clock and says nothing on its own about how much was allowed — and the ALLOWANCE
    /// is what belongs in the artifact. Reporting the trade is what makes it arguable
    /// from the output instead of from this file.
    public let stageAllowance: Duration
    /// How long mDNS and SSDP were each granted, concurrently.
    public let concurrentAllowance: Duration
    /// How long NetBIOS was granted, after them.
    public let netbiosAllowance: Duration

    /// The fraction of the remaining run budget the naming stage may take.
    ///
    /// Naming runs after discovery and before the deep scan, so it is spending time
    /// the deep scan might want. Forty percent leaves the majority of what is left for
    /// port probing when `--deep` is on, and is the whole of naming's plausible need
    /// when it is not, since the ceiling below binds first on any ordinary budget.
    public static let shareOfRemaining = 0.40

    /// The least time worth starting the stage with.
    ///
    /// Below roughly a second and a half, mDNS gets the cached answers the local
    /// responder already holds and nothing else, SSDP cannot both listen and fetch, and
    /// the stage reports a lot of unnamed devices that are in fact named. Under a very
    /// short `--deadline` the clamp to the parent still wins, so this is a floor on the
    /// ASK, not a promise: a two-second scan gets whatever two seconds leaves.
    public static let floor = Duration.milliseconds(1_500)

    /// The most time worth spending, however large the run budget is.
    ///
    /// The ceiling is the real decision, and it was set by measurement rather than by
    /// taste. On the reference network Bonjour delivers everything it is ever going to
    /// deliver inside about a second — the local responder answers from cache
    /// immediately and live devices reply to the multicast query in milliseconds — and
    /// the browse then goes quiet and stays quiet. Past that the curve is flat and the
    /// user is simply waiting; a `--deadline 60s` must not mean a minute of listening
    /// to silence.
    ///
    /// 4.5 seconds is where the arithmetic lands for the source that actually binds.
    /// mDNS stops early on quiescence and NetBIOS stops as soon as every host asked has
    /// answered, so neither of them spends its allowance on a quiet network. SSDP
    /// cannot: its listen window is protocol-bound, because `MX` tells devices to
    /// spread their replies uniformly across it and cutting the window short
    /// systematically loses whoever randomized into the second half. So the ceiling is
    /// chosen so that SSDP's 60% listen share comes out at about 1.9 seconds — which,
    /// with `MX` derived as the whole number of seconds in it, means the tool always
    /// listens comfortably longer than it asked the network to take.
    ///
    /// The cost of the whole naming stage on a network where only mDNS answers is then
    /// about 2.6 seconds, against roughly 0.4 for discovery. Naming is the expensive
    /// part of this scanner, and it is worth it: a device list without names is a list
    /// of addresses.
    public static let ceiling = Duration.milliseconds(4_500)

    /// The share of the naming budget mDNS and SSDP each receive.
    ///
    /// They run CONCURRENTLY — different sockets, different protocols, no contention —
    /// so both can hold seventy percent of the stage without the stage taking a
    /// hundred and forty percent of itself. Running them in sequence would be the
    /// obvious reading of "each source gets a slice" and would cost almost twice the
    /// wall clock for exactly the same names.
    public static let concurrentShare = 0.70

    /// The share left for NetBIOS, which starts only when the other two have finished.
    ///
    /// Thirty percent of a six-second stage is 1.8 seconds for one datagram per host to
    /// however few hosts are still unnamed — generous for a protocol whose entire
    /// exchange is a single round trip on a LAN.
    public static let netbiosShare = 0.30

    /// How long mDNS will sit with nothing new arriving before it gives up early.
    ///
    /// This is what makes the ceiling affordable. The budget is a ceiling rather than a
    /// fixed wait: a network that has gone quiet for this long has said what it is
    /// going to say, and continuing to hold the stage open is spending the user's
    /// wall clock on nothing. It is the same adaptive shape as the sweep's tail wait —
    /// measure, then stop — applied to a source that cannot be counted.
    public static let quietPeriod = Duration.milliseconds(700)

    /// The earliest mDNS may exit on quiescence.
    ///
    /// Without a floor, the gap between "browse started" and "first record arrives" is
    /// itself a quiet period, and the stage would exit before hearing anything at all
    /// on a network whose responder is slow to warm up.
    public static let quietFloor = Duration.milliseconds(500)

    /// Divides a run's remaining budget for the naming stage.
    ///
    /// - Parameter parent: the run's deadline. Every sub-budget is `clamped(to:)` it,
    ///   so no source can outlive the run however the fractions come out.
    public init(within parent: Deadline) {
        let remaining = parent.remaining
        let asked = remaining * Self.shareOfRemaining
        let wanted = min(max(asked, Self.floor), Self.ceiling)
        let stage = Deadline(after: wanted).clamped(to: parent)
        self.stage = stage
        self.mdns = stage.fraction(Self.concurrentShare).clamped(to: stage)
        self.ssdp = stage.fraction(Self.concurrentShare).clamped(to: stage)
        self.stageAllowance = min(wanted, remaining)
        self.concurrentAllowance = self.stageAllowance * Self.concurrentShare
        self.netbiosAllowance = self.stageAllowance * Self.netbiosShare
    }

    /// NetBIOS's slice, struck WHEN IT STARTS rather than when the stage began.
    ///
    /// A method rather than a stored deadline, and the difference is a bug that reached
    /// a live network. mDNS and SSDP begin immediately, so their deadlines can be struck
    /// up front. NetBIOS begins only after that concurrent phase returns — which may be
    /// 70% of the stage later — so a deadline struck at stage start for 30% of the stage
    /// HAD ALREADY EXPIRED by the time NetBIOS was reached, and the source never sent a
    /// single datagram. Nothing failed: the stage reported success, the timing looked
    /// reasonable, and one of the three name sources was simply never asked.
    ///
    /// Struck on entry, NetBIOS gets its allowance from that moment, still
    /// `clamped(to:)` the stage so it cannot overrun — and it inherits any time mDNS
    /// handed back by quiescing early, which is the right direction for the weakest
    /// source to be given slack.
    public func netbiosSlice() -> Deadline {
        Deadline(after: netbiosAllowance).clamped(to: stage)
    }

    /// Builds a budget from explicit deadlines, for a test that needs to pin them.
    public init(
        stage: Deadline,
        mdns: Deadline,
        ssdp: Deadline,
        stageAllowance: Duration = .zero,
        concurrentAllowance: Duration = .zero,
        netbiosAllowance: Duration = .zero
    ) {
        self.stage = stage
        self.mdns = mdns
        self.ssdp = ssdp
        self.stageAllowance = stageAllowance
        self.concurrentAllowance = concurrentAllowance
        self.netbiosAllowance = netbiosAllowance
    }
}

/// What the naming stage produced.
///
/// An envelope rather than a throw, for the same reason `DiscoveryResult` is one: a
/// budget that expires is a normal return carrying real partial names, and a source
/// that could not run is a `Degradation` rather than an error that would discard the
/// other two sources' work.
public struct NameResolution: Sendable {
    /// Every candidate found, by address, winners and losers together. The pipeline
    /// appends these to `HostFacts.allNames`; the cascade picks the winner at read
    /// time via `candidates.best`.
    public var names: [IPv4Address: [NameCandidate]]
    /// Hardware addresses learned along the way — an NBSTAT reply carries the adapter's
    /// MAC, which is occasionally one the ARP cache does not have.
    public var hardware: [IPv4Address: MACAddress]
    /// What did not work.
    public var degradations: [Degradation]
    /// How the stage ended. `.deadlineExpired` is a success carrying partial names.
    public var outcome: Outcome
    /// What it cost.
    public var timing: StageTiming

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        names: [IPv4Address: [NameCandidate]] = [:],
        hardware: [IPv4Address: MACAddress] = [:],
        degradations: [Degradation] = [],
        outcome: Outcome = .complete,
        timing: StageTiming = StageTiming(stage: .naming, elapsedMillis: 0)
    ) {
        self.names = names
        self.hardware = hardware
        self.degradations = degradations
        self.outcome = outcome
        self.timing = timing
    }
}

/// Turns addresses into names.
///
/// The stage-level protocol, alongside `HostDiscovery` and `PortScanning` rather than
/// among the platform primitives, because a conformance is a COMPOSITION of the three
/// sources — `ServiceBrowser`, `SSDPDiscovery`, `NetBIOSQuerying` — and the cascade
/// that arbitrates them, not a single capability.
public protocol NameResolving: Sendable {
    /// Which resolver this is, for the artifact.
    var descriptor: EngineDescriptor { get }

    /// Names what it can of `addresses`, within `deadline`.
    ///
    /// - Parameters:
    ///   - addresses: the hosts discovery found. Used to decide which hosts NetBIOS is
    ///     worth asking about; mDNS and SSDP are broadcast questions and hear from
    ///     whoever answers, so a name may come back for an address not in this list.
    ///   - target: what is being scanned. Carries the interface, which the SSDP socket
    ///     must bind to and which supplies the address that loopback remaps to.
    ///   - deadline: the run's budget. The stage takes its own slice of this via
    ///     `NameBudget`, and never the whole of it.
    ///   - progress: display only, and lossy. Nothing emitted here is load-bearing.
    /// - Returns: an envelope. Never throws.
    func resolveNames(
        for addresses: [IPv4Address],
        on target: ScanTarget,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> NameResolution
}

extension NameResolving {
    /// Resolves with no observer.
    public func resolveNames(
        for addresses: [IPv4Address], on target: ScanTarget, deadline: Deadline
    ) async -> NameResolution {
        await resolveNames(for: addresses, on: target, deadline: deadline, progress: .ignore)
    }
}

/// Accumulates name candidates from every source, keyed by address.
///
/// Deliberately a plain value type with no concurrency in it. The sources are
/// asynchronous and each has its own actor or queue where that is forced; the
/// ARBITRATION is pure arithmetic over what they returned, and making it an actor too
/// would add a hop per sighting to protect a computation that no longer races.
///
/// Its one rule: **nothing is ever discarded.** A losing candidate is the explanation
/// for why the winner won, the app's "Known by" panel is built entirely from them, and
/// a ledger that kept only the best name would silently destroy that feature while
/// every test of the winning name still passed.
public struct NameLedger: Sendable {
    private var candidates: [IPv4Address: [NameCandidate]] = [:]
    private var hardware: [IPv4Address: MACAddress] = [:]

    /// The address this machine sends from, which loopback sightings are remapped to.
    ///
    /// **The local machine resolves itself to 127.0.0.1 over mDNS.** Its own responder
    /// answers the address query from the loopback record, so this Mac's Bonjour name
    /// arrives attached to 127.0.0.1 — an address that is not on the scanned network,
    /// belongs to no device in the report, and would simply be dropped. The machine
    /// running the scan is then the one device on the network the scan cannot name,
    /// which is both wrong and the first thing anyone notices.
    public let localAddress: IPv4Address?

    /// Creates a ledger.
    ///
    /// - Parameter localAddress: this machine's address on the scanned interface.
    ///   Absent disables the remap, in which case loopback sightings are dropped.
    public init(localAddress: IPv4Address? = nil) {
        self.localAddress = localAddress
    }

    /// The address a sighting should be filed under, applying the loopback remap.
    ///
    /// Returns nil when the sighting cannot be attributed to any address in the report,
    /// which is a loopback sighting on a machine whose own address is unknown.
    public func attributed(_ ip: IPv4Address) -> IPv4Address? {
        guard ip.isLoopback else { return ip }
        return localAddress
    }

    /// Files one candidate against an address.
    ///
    /// Duplicates collapse: the same device answers the same browse on several
    /// interface indices, and `_device-info` in particular arrives two or three times
    /// per scan. An exact repeat carries no information, and letting it through would
    /// make the "known by" list a stutter.
    public mutating func record(_ candidate: NameCandidate, for ip: IPv4Address) {
        guard let address = attributed(ip) else { return }
        var existing = candidates[address] ?? []
        guard !existing.contains(candidate) else { return }
        existing.append(candidate)
        candidates[address] = existing
    }

    /// Files a hardware address learned by a name source.
    public mutating func record(mac: MACAddress, for ip: IPv4Address) {
        guard let address = attributed(ip) else { return }
        hardware[address] = mac
    }

    /// Whether an address has a candidate whose source stands on its own.
    ///
    /// This is the question NetBIOS is gated on, and it deliberately asks about
    /// SELF-SUFFICIENCY rather than about having any name at all. A host that reverse
    /// DNS called `10-10-20-24.lan` has a name and is not named; asking it for its
    /// NetBIOS name costs one datagram and may produce something a person recognises.
    public func isNamed(_ ip: IPv4Address) -> Bool {
        guard let found = candidates[ip] else { return false }
        return found.contains { $0.source.isSelfSufficient }
    }

    /// Addresses from `addresses` that nothing self-sufficient has named yet, in order.
    public func unnamed(among addresses: [IPv4Address]) -> [IPv4Address] {
        addresses.filter { !isNamed($0) }.sorted()
    }

    /// How many addresses have at least one candidate.
    public var namedCount: Int { candidates.count }

    /// The candidates, in canonical order per address so the artifact is stable.
    public var names: [IPv4Address: [NameCandidate]] {
        candidates.mapValues { $0.sorted() }
    }

    /// The hardware addresses learned.
    public var hardwareAddresses: [IPv4Address: MACAddress] { hardware }
}
