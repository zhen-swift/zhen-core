// ReachPlan.swift — how long to wait for each address, and how often to ask it.
//
// ── The fact this answers ─────────────────────────────────────────────────────────
//
// Study 1's default declared absence at about 0.37–0.41 s. Cold first contact with the
// testbed's slowest host is about 1.0 s, because the ARP and the echo are both delayed,
// so a cold scan missed it on one run in five — and every miss was `.12` or `.13`. The
// network-wide tail could not fix that by learning, because it is learned from replies
// that already arrived: a tail it has not seen, it cannot learn.
//
// History can. A network scanned before says which addresses usually answer and how
// long their first contact took when nothing was cached. So the wait becomes a property
// of the ADDRESS, not of the sweep: an address history expects is waited for up to a
// high percentile of this network's cold first-contact times, with more attempts — each
// transmission to an ARP-incomplete address is an ARP trigger, so the number of
// transmissions is the number of ARP attempts it gets. An address history has never
// seen keeps today's short learned wait. A network never scanned waits long everywhere,
// once, and that scan seeds the history.
//
// ── What is decided here and what is decided in the sweep ─────────────────────────
//
// The plan is built before the sweep, by a pure function of the target, history and a
// policy, so it can be tested on Linux. The learned tail is not known until replies
// arrive, so the plan cannot contain it: `wait(for:)` is the plan's own number, with
// zero meaning "the learned tail alone", and `wait(for:learnedTail:)` is what the sweep
// arms once it has one. Under `.history` an expected address's wait is FLOORED by the
// learned tail, so history can only lengthen a wait, never shorten it below what the
// sweep learned.
//
// Every constant is in `ReachSettings` and every one is a command-line flag, because
// study 2 freezes this binary and passes what phase 1 learns as flags. A constant that
// could only be moved by rebuilding would end the study.
//
// ── Cold and warm, per address (the fixes brief, F1) ──────────────────────────────
//
// Which samples an address is judged by depends on its own neighbour entry at the
// start of the sweep, not on the network. An address with no complete entry will need
// ARP before its echo, so the cold samples are the ones that describe it — or, while
// there are too few of them, the first-scan wait. An address whose entry is already
// complete has no ARP delay to cover: the warm samples describe it, floored by the
// learned tail, and with too few of them the learned tail alone. Without this, a
// machine that scans more often than its cache expires never gathers a cold sample and
// held every address to the first-scan wait (questions, Q8). The cache state is only
// known when the sweep takes its baseline, so `make` computes both sample sets and
// `atSweepStart` records which addresses are warm.
//
// ── A known network's dead addresses (the addendum, F7) ───────────────────────────
//
// F1 left one case on the first-scan wait that shouldn't be: the cold addresses of a
// network zhen has scanned many times, but always warm. Its live hosts are cached, so it
// gathers warm samples and never cold ones. Its cold addresses are the ~240 where nothing
// lives, and every one of them waited 1.5 s on every scan (questions, Q15). The first-scan
// wait is for a network zhen doesn't know yet, and for expected addresses. A network is
// KNOWN once history holds `minimumSamples` samples of either kind. On a known network an
// unexpected cold address takes the learned tail, as an unexpected warm one already does.
// An expected cold address keeps F1's rule, because that's the sleeping phone the long
// wait exists for. `ReachSettings.unexpectedCold` keeps F1's rule as the study's other arm.
//
// ── Each expected address waits for its own device (addendum 3, F11) ──────────────
//
// One percentile over the whole network can't protect one slow device. On the testbed two
// 500 ms hosts among eleven are under a fifth of the cold samples, on a home network one
// slow phone among fifty hosts is under 3%, and P97 of the pool waits past it. So an
// expected cold address waits for the device history holds there: the percentile of THAT
// device's cold samples, or their maximum while it has fewer than
// `deviceMinimumSamples`, floored by the learned tail and capped. The network percentile
// is the fallback for a device with no cold samples of its own. This is what "a wait per
// address, learned from history" meant from the first brief; the pool was a shortcut.

/// How a sweep decides how long to wait for an address.
public enum SweepReach: Sendable, Hashable {
    /// Study 1's behaviour: one network-wide tail, learned from the replies that arrive.
    /// With `--no-neighbor-watch`, this is study 1's mechanism exactly (gate G3).
    case learned
    /// The default. Addresses history expects wait up to this percentile of the
    /// network's first-contact times — the cold ones for an address with no complete
    /// neighbour entry, the warm ones for an address with one; the rest wait the
    /// learned tail.
    case history(percentile: Double)
    /// Every address waits exactly this long, whatever history or the tail says.
    case fixed(Duration)

    /// The default policy: history, at the 97th percentile.
    public static let `default` = SweepReach.history(percentile: 0.97)

    /// The wire name: `learned`, `history`, or `fixed`.
    public var name: String {
        switch self {
        case .learned: "learned"
        case .history: "history"
        case .fixed: "fixed"
        }
    }
}

/// The constants behind `.history`, every one overridable.
///
/// The defaults are the brief's, each with where it came from. Study 2 phase 1 is what
/// will move them, by flag, without a rebuild.
public struct ReachSettings: Sendable, Hashable {
    /// How long an address with no complete neighbour entry waits on a network with too
    /// few cold samples, if it is expected or the network is unknown (F7). An address
    /// whose entry is complete never waits it.
    ///
    /// 1.5 s: the testbed's slowest host makes cold first contact in about 1.0 s
    /// (study 1, the shared budget's 987 ms stage), plus margin. A first scan pays it
    /// once; that scan is what makes the next one fast.
    public var firstScanWait: Duration
    /// The longest any expected address waits, however slow history says it is.
    ///
    /// 5 s, so one pathological sample in the history cannot hold every scan of the
    /// network open for the length of the user's patience.
    public var cap: Duration
    /// Fewer samples of a kind than this, and they decide nothing: too few cold samples
    /// and a cold address takes `firstScanWait`; too few warm ones and a warm address
    /// takes the learned tail. Also how many samples of both kinds together make a
    /// network known (F7).
    ///
    /// 20: below it the 97th percentile is the maximum of a handful, which is a guess
    /// with a unit.
    public var minimumSamples: Int
    /// Each whole step of wait beyond the first earns one more transmission.
    ///
    /// 500 ms. The first step is what the base attempts already cover — study 1's default
    /// declared absence at ~0.4 s with three — so a 1.5 s wait gets five, not six.
    public var attemptsStep: Duration
    /// The most transmissions any address gets.
    public var attemptsCap: Int
    /// Transmissions for an address with no extended wait — the sweep's own `attempts`.
    public var baseAttempts: Int
    /// How recently history must have seen a device at an address for it to be expected.
    ///
    /// 30 days, and independent of how long history is kept (the fixes brief, F3). The
    /// command line keeps history for ever, and when "expected" meant "inside retention"
    /// a phone that left the household a year ago was still waited for on every scan
    /// (questions, Q1). A month covers a holiday; it does not cover a device that left.
    public var expectedWindow: Duration
    /// What an unexpected address with no complete entry waits on a known network whose
    /// cold samples are too few: the learned tail (F7, the default), or the first-scan
    /// wait (F1).
    public var unexpectedCold: UnexpectedColdWait
    /// Fewer of a device's own cold samples than this, and an expected address waits
    /// their maximum rather than their percentile (F11).
    ///
    /// 5: below it the 97th percentile of a device's samples is their maximum anyway, and
    /// saying so keeps the rule readable. With none, the network percentile decides.
    public var deviceMinimumSamples: Int

    /// 30 days: see `expectedWindow`. History's identity rules use it too (F10).
    public static let defaultExpectedWindow: Duration = .seconds(30 * 86_400)

    /// The brief's constants.
    public init(
        firstScanWait: Duration = .milliseconds(1_500),
        cap: Duration = .seconds(5),
        minimumSamples: Int = 20,
        attemptsStep: Duration = .milliseconds(500),
        attemptsCap: Int = 8,
        baseAttempts: Int = 3,
        expectedWindow: Duration = ReachSettings.defaultExpectedWindow,
        unexpectedCold: UnexpectedColdWait = .learned,
        deviceMinimumSamples: Int = 5
    ) {
        self.firstScanWait = firstScanWait
        self.cap = cap
        self.minimumSamples = minimumSamples
        self.attemptsStep = attemptsStep
        self.attemptsCap = attemptsCap
        self.baseAttempts = baseAttempts
        self.expectedWindow = expectedWindow
        self.unexpectedCold = unexpectedCold
        self.deviceMinimumSamples = deviceMinimumSamples
    }

    /// How many transmissions a wait of this length earns.
    ///
    /// The base, plus one per whole `attemptsStep` beyond the first, capped. Never fewer
    /// than the base: a short wait is not a reason to ask fewer times than today.
    public func attempts(forWait wait: Duration) -> Int {
        guard attemptsStep > .zero else { return baseAttempts }
        let steps = Int((wait / attemptsStep).rounded(.down))
        let extra = max(0, steps - 1)
        return max(baseAttempts, min(attemptsCap, baseAttempts + extra))
    }
}

/// One first-contact time, as history keeps it.
///
/// From the first transmission to an address to the first evidence of any kind from it —
/// an echo reply or its neighbour entry resolving. `cold` when the address had no
/// complete neighbour entry at that first transmission: then the time includes ARP, and
/// it is the number the wait has to cover. A warm sample measures ICMP alone and would
/// bias a cold address's percentile low, so the two are never pooled: cold samples judge
/// addresses with no complete entry, warm samples addresses with one.
public struct FirstContactSample: Sendable, Hashable, Codable {
    /// The time, in milliseconds.
    public var millis: Double
    /// Whether the address was ARP-incomplete at its first transmission.
    public var cold: Bool
    /// When the run that measured it saw the device. Nil for a sample written before
    /// samples carried it (the fixes brief, F10), which sorts as the oldest.
    public var at: Timestamp?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(millis: Double, cold: Bool, at: Timestamp? = nil) {
        self.millis = millis
        self.cold = cold
        self.at = at
    }

    /// The most samples history keeps per device, newest last.
    public static let retained = 32

    /// The newest `retained` of these, by time, oldest first.
    ///
    /// By time, not by order of arrival (F10). Two records joined, or a samples line
    /// joined to a record, put one set of samples after the other, and keeping the last
    /// 32 of that order dropped whichever set came first, whatever its age. Samples with
    /// no time sort first and keep their order among themselves.
    public static func newest(_ samples: [FirstContactSample]) -> [FirstContactSample] {
        let ordered = samples.enumerated().sorted { lhs, rhs in
            let left = lhs.element.at?.millisecondsSinceEpoch ?? .min
            let right = rhs.element.at?.millisecondsSinceEpoch ?? .min
            return (left, lhs.offset) < (right, rhs.offset)
        }
        return Array(ordered.map(\.element).suffix(retained))
    }

    /// Wire keys, spelled out.
    public enum CodingKeys: String, CodingKey {
        case millis
        case cold
        case at = "at_millis"
    }
}

/// A wait and an attempt count for every address a sweep will probe.
public struct ReachPlan: Sendable, Hashable {
    /// The policy it was built under.
    public let policy: SweepReach
    /// The constants it was built with.
    public let settings: ReachSettings
    /// The addresses history expects: a device last seen at each inside
    /// `settings.expectedWindow`.
    public var expected: Set<IPv4Address>
    /// Whether the network has too few COLD samples, so an address with no complete
    /// neighbour entry may wait `settings.firstScanWait`. Only ever true under `.history`.
    ///
    /// A property of the cold sample set, not of the scan: whether a given address
    /// takes that wait depends on its own entry and on whether it is expected
    /// (`path(for:)`). An address whose entry is complete never does.
    public let firstScan: Bool
    /// Whether history holds `settings.minimumSamples` first-contact samples of either
    /// kind, cold and warm together, for this network (F7). On a known network an
    /// unexpected cold address doesn't take the first-scan wait, unless
    /// `settings.unexpectedCold` is `.firstScan`.
    public let knownNetwork: Bool
    /// How many cold first-contact samples the network's history holds.
    public let historySamples: Int
    /// The percentile of those samples, capped — what an expected cold address whose
    /// device has no cold samples of its own waits before the learned tail floors it.
    /// Nil when there is none: not `.history`, or too few cold samples.
    public let expectedWait: Duration?
    /// What each expected address waits for its own device, capped, before the learned
    /// tail floors it: the percentile of that device's cold samples, or their maximum
    /// with fewer than `settings.deviceMinimumSamples` (F11). Only addresses whose device
    /// has cold samples; `.history` only.
    public let deviceWaits: [IPv4Address: Duration]
    /// How many warm first-contact samples the network's history holds.
    public let warmSamples: Int
    /// The percentile of the warm samples, capped: what F1 says an expected address with
    /// a complete neighbour entry would wait. Nil when there is none: not `.history`, or
    /// too few warm samples. Reported, and waited by no address, because every address
    /// it describes is `inherited` (F2; questions, Q16).
    public let warmExpectedWait: Duration?
    /// The probed addresses whose neighbour entry was complete when the sweep took its
    /// baseline. Nil until `atSweepStart` records it; until then every address is judged
    /// cold, which is what the plan said before cache state was per address.
    public let warm: Set<IPv4Address>?
    /// How many probed addresses took each path, and how many were cold and warm, once
    /// `atSweepStart` has resolved the plan against the sweep's baseline. Nil before
    /// that, and under any policy but `.history`.
    public let paths: ReachPathCounts?

    /// Creates a plan from its parts. `make` is how a sweep gets one; this exists for a
    /// test or a caller that has already decided.
    public init(
        policy: SweepReach, settings: ReachSettings = ReachSettings(),
        expected: Set<IPv4Address> = [], firstScan: Bool = false, knownNetwork: Bool = false,
        historySamples: Int = 0, expectedWait: Duration? = nil,
        warmSamples: Int = 0, warmExpectedWait: Duration? = nil,
        warm: Set<IPv4Address>? = nil, paths: ReachPathCounts? = nil,
        deviceWaits: [IPv4Address: Duration] = [:]
    ) {
        self.policy = policy
        self.settings = settings
        self.expected = expected
        self.firstScan = firstScan
        self.knownNetwork = knownNetwork
        self.historySamples = historySamples
        self.expectedWait = expectedWait
        self.warmSamples = warmSamples
        self.warmExpectedWait = warmExpectedWait
        self.warm = warm
        self.paths = paths
        self.deviceWaits = deviceWaits
    }

    /// The plan resolved against the sweep's baseline: which of `addresses` had a
    /// complete neighbour entry when it was taken.
    ///
    /// Called by the sweep, once, with the table it read before its first transmission —
    /// the same read that decides what is inherited — so the plan and the sweep agree
    /// about which addresses are warm. Pure, so the per-address rules are tested on
    /// Linux.
    public func atSweepStart(addresses: [IPv4Address], complete: Set<IPv4Address>) -> ReachPlan {
        func resolved(paths: ReachPathCounts?) -> ReachPlan {
            ReachPlan(
                policy: policy, settings: settings, expected: expected, firstScan: firstScan,
                knownNetwork: knownNetwork, historySamples: historySamples, expectedWait: expectedWait,
                warmSamples: warmSamples, warmExpectedWait: warmExpectedWait,
                warm: complete.intersection(addresses), paths: paths, deviceWaits: deviceWaits
            )
        }
        let plan = resolved(paths: nil)
        guard case .history = policy else { return plan }
        var counts = ReachPathCounts()
        for address in Set(addresses) {
            if plan.isWarm(address) { counts.warm += 1 } else { counts.cold += 1 }
            switch plan.path(for: address) {
            case .firstScan?: counts.firstScan += 1
            case .device?: counts.device += 1
            case .coldPercentile?: counts.coldPercentile += 1
            case .inherited?: counts.inherited += 1
            case .learnedTail?, nil: counts.learnedTail += 1
            }
        }
        return resolved(paths: counts)
    }

    /// Whether the address's neighbour entry was complete at the start of the sweep.
    /// False before `atSweepStart`.
    public func isWarm(_ address: IPv4Address) -> Bool {
        warm?.contains(address) ?? false
    }

    /// Which rule of `.history` decides the address's wait. Nil under the other two.
    ///
    /// Cold — no complete entry: with too few cold samples an expected address waits the
    /// first-scan wait, and so does an unexpected one while the network is unknown. On a
    /// known network an unexpected one takes the learned tail (F7), or the first-scan
    /// wait under `unexpectedCold: .firstScan` (F1). With enough cold samples an expected
    /// address waits the cold percentile and the rest the learned tail. Warm never waits the
    /// first-scan wait: that wait covers an ARP delay a complete entry does not have. An
    /// unexpected warm address gets the learned tail, and an expected one is `inherited`
    /// (F2): the entry is evidence the report already accepts, so nothing waits for more.
    /// An expected cold address whose device has cold samples of its own waits for that
    /// device (F11), however many the network has; the rules above are for the rest.
    public func path(for address: IPv4Address) -> ReachPath? {
        guard case .history = policy else { return nil }
        if isWarm(address) {
            return expected.contains(address) ? .inherited : .learnedTail
        }
        if expected.contains(address), deviceWaits[address] != nil { return .device }
        if firstScan {
            let unexpectedOnKnown = knownNetwork && !expected.contains(address)
            return unexpectedOnKnown && settings.unexpectedCold == .learned ? .learnedTail : .firstScan
        }
        guard expected.contains(address), expectedWait != nil else { return .learnedTail }
        return .coldPercentile
    }

    /// Whether the address takes the first-scan wait. Per address: a warm one never does,
    /// and on a known network an unexpected one doesn't either (F7).
    public func isFirstScan(_ address: IPv4Address) -> Bool {
        path(for: address) == .firstScan
    }

    /// Whether the address is expected and its entry was complete at the start of the
    /// sweep, so the sweep counts it as having evidence already (F2). `.history` only.
    public func isInherited(_ address: IPv4Address) -> Bool {
        path(for: address) == .inherited
    }

    /// The plan's own wait for an address. Zero means the learned tail alone.
    public func wait(for address: IPv4Address) -> Duration {
        switch policy {
        case .learned:
            return .zero
        case .fixed(let wait):
            return wait
        case .history:
            switch path(for: address) {
            case .firstScan?: return settings.firstScanWait
            case .device?: return deviceWaits[address] ?? .zero
            case .coldPercentile?: return expectedWait ?? .zero
            case .inherited?, .learnedTail?, nil: return .zero
            }
        }
    }

    /// The wait the sweep arms for an address, once it has learned a tail.
    ///
    /// `.fixed` is exactly what it says. Otherwise the plan's wait is floored by the
    /// learned tail, so history only ever lengthens a wait.
    public func wait(for address: IPv4Address, learnedTail: Duration) -> Duration {
        if case .fixed(let wait) = policy { return wait }
        return max(wait(for: address), learnedTail)
    }

    /// How many transmissions an address gets.
    public func attempts(for address: IPv4Address) -> Int {
        switch policy {
        case .learned:
            return settings.baseAttempts
        case .fixed, .history:
            let wait = wait(for: address)
            return wait > .zero ? settings.attempts(forWait: wait) : settings.baseAttempts
        }
    }

    /// Whether any address might wait longer than the learned tail would make it.
    ///
    /// False under `.learned`, which is how the sweep knows to run study 1's schedule
    /// unchanged. Under `.history` it says what the plan can know without the address
    /// list; the sweep, which has the list, keeps the plan only if an address actually
    /// gets a wait.
    public var extendsAnyWait: Bool {
        switch policy {
        case .learned: false
        case .fixed: true
        case .history:
            firstScan || (expectedWait != nil && !expected.isEmpty)
                || (warmExpectedWait != nil && !expected.isEmpty) || !deviceWaits.isEmpty
        }
    }

    /// Builds the plan for a sweep.
    ///
    /// A pure function, so G1 runs on Linux.
    ///
    /// - Parameters:
    ///   - addresses: what the sweep will probe.
    ///   - network: the network those addresses are in. History is read for this network
    ///     only: another network's first-contact times say nothing about this one.
    ///   - devices: what history holds.
    ///   - policy: how to wait.
    ///   - settings: the constants.
    ///   - now: the instant `settings.expectedWindow` is measured back from.
    public static func make(
        addresses: [IPv4Address],
        network: IPv4Network,
        devices: [StoredDevice],
        policy: SweepReach,
        settings: ReachSettings = ReachSettings(),
        now: Timestamp
    ) -> ReachPlan {
        let probed = Set(addresses)
        // F3: the window, not the store's retention. Every sample still counts — an old
        // device's first-contact times still describe the network — but only a recent
        // sighting makes an address expected.
        let cutoff = Timestamp(
            millisecondsSinceEpoch: now.millisecondsSinceEpoch
                - Int64(settings.expectedWindow.milliseconds.rounded())
        )
        var expected: Set<IPv4Address> = []
        var cold: [Double] = []
        var warm: [Double] = []
        // F11: each expected address's own device's cold samples. Where two recent devices
        // hold one address, the one seen last is the one there.
        var ownSamples: [IPv4Address: (seen: Timestamp, millis: [Double])] = [:]
        for stored in devices {
            let here = stored.device.ipv4Addresses.filter(network.contains)
            guard !here.isEmpty else { continue }
            for sample in stored.firstContactSamples {
                if sample.cold { cold.append(sample.millis) } else { warm.append(sample.millis) }
            }
            if stored.device.lastSeen >= cutoff {
                let mine = stored.firstContactSamples.filter(\.cold).map(\.millis)
                for address in here where probed.contains(address) {
                    expected.insert(address)
                    if let held = ownSamples[address], held.seen > stored.device.lastSeen { continue }
                    ownSamples[address] = (stored.device.lastSeen, mine)
                }
            }
        }

        // F7: either kind counts. A network with twenty warm samples has been scanned
        // enough to know which addresses answer, though it has no cold sample at all.
        let known = cold.count + warm.count >= max(1, settings.minimumSamples)
        guard case .history(let percentile) = policy else {
            return ReachPlan(
                policy: policy, settings: settings, expected: expected, knownNetwork: known,
                historySamples: cold.count, warmSamples: warm.count
            )
        }
        // Each sample set decides only for the addresses it describes, so each has its
        // own minimum: a network can have plenty of warm history and no cold.
        func wait(_ samples: [Double]) -> Duration? {
            guard samples.count >= max(1, settings.minimumSamples),
                  let value = Self.percentile(percentile, of: samples) else { return nil }
            return min(.milliseconds(value), settings.cap)
        }
        let coldWait = wait(cold)
        // F11: the device's percentile, or its maximum while it has few; none, no entry.
        var deviceWaits: [IPv4Address: Duration] = [:]
        for (address, own) in ownSamples where !own.millis.isEmpty {
            let value = own.millis.count >= max(1, settings.deviceMinimumSamples)
                ? Self.percentile(percentile, of: own.millis) : own.millis.max()
            if let value { deviceWaits[address] = min(.milliseconds(value), settings.cap) }
        }
        return ReachPlan(
            policy: policy, settings: settings, expected: expected,
            firstScan: coldWait == nil, knownNetwork: known,
            historySamples: cold.count, expectedWait: coldWait,
            warmSamples: warm.count, warmExpectedWait: wait(warm),
            deviceWaits: deviceWaits
        )
    }

    /// The nearest-rank percentile: the smallest sample with at least `p` of the samples
    /// at or below it.
    ///
    /// Nearest-rank rather than interpolated, because it is always a time that was
    /// actually observed, and at 20 samples it makes P97 the maximum — the conservative
    /// reading for a wait whose job is to catch the slow host.
    public static func percentile(_ p: Double, of samples: [Double]) -> Double? {
        guard !samples.isEmpty else { return nil }
        let sorted = samples.sorted()
        let rank = Int((min(max(p, 0), 1) * Double(sorted.count)).rounded(.up))
        return sorted[min(max(rank, 1), sorted.count) - 1]
    }
}
