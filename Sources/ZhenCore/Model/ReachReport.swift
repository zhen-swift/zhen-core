// ReachReport.swift — `run.reach`: how the sweep decided how long to wait, and for whom
// it was still waiting when it stopped.
//
// Written so a person and the study can both read it. "Still listening for 2 you usually
// have" is `expected_missing` while the scan runs (the `settling` event); this is what
// it came to. `zhen scan --look-longer` reads `expected_missing` back from the latest
// run to know whom to ask again.

/// What the reach plan was, and what was still missing when the run ended.
public struct ReachReport: Sendable, Hashable, Codable {
    /// `history`, `learned`, or `fixed`.
    public var policy: String
    /// The percentile of cold first-contact times an expected address waits, under
    /// `history`. Nil under the other two.
    public var percentile: Double?
    /// The wait every address got, under `fixed`, in milliseconds.
    public var fixedWaitMillis: Double?
    /// Whether any address waited the first-scan wait: it had no complete neighbour
    /// entry, on a network with too few cold samples. Only ever true under `history`.
    /// Per address since F1 — `paths.first_scan` says how many.
    public var firstScan: Bool
    /// What an expected COLD address waited before the learned tail floored it, in
    /// milliseconds: the cold samples' percentile, capped. Nil when there was none.
    public var expectedWaitMillis: Double?
    /// What an expected WARM address — one whose neighbour entry was complete at the
    /// start — waited before the learned tail floored it, in milliseconds: the warm
    /// samples' percentile, capped. Nil when there was none.
    public var warmWaitMillis: Double?
    /// How many warm first-contact samples this network's history held.
    public var warmSamples: Int?
    /// How many probed addresses were cold and warm, and how many took each path. Nil
    /// under `learned` and `fixed`, and when the sweep never started.
    public var paths: ReachPathCounts?
    /// How recently a device had to be seen at an address for it to be expected, in ms.
    public var expectedWindowMillis: Double?
    /// Whether history held enough first-contact samples of either kind for this network
    /// to count as known (F7). Nil in an artifact written before F7.
    public var knownNetwork: Bool?
    /// What an unexpected cold address waits on a known network with too few cold
    /// samples: `learned` (the default) or `first-scan` (F1), the flag's spelling.
    public var unexpectedCold: String?
    /// How many addresses history expected.
    public var expectedCount: Int
    /// The expected addresses the run found no device at, in address order.
    public var expectedMissing: [IPv4Address]

    // ── The values actually used, flagged or defaulted (study 2's contract) ─────────
    //
    // Every constant `ReachSettings` holds, echoed whether a flag set it or not, so an
    // artifact says what produced it without the reader knowing this build's defaults.

    /// The wait every address gets on a network with too little history, in ms.
    public var firstScanWaitMillis: Double?
    /// The most any expected address waits, in ms.
    public var capMillis: Double?
    /// Fewer cold samples than this and the network is treated as never scanned.
    public var minSamples: Int?
    /// Fewer of its device's own cold samples than this, and an expected address waits
    /// their maximum rather than their percentile (F11). Nil before F11.
    public var deviceMinSamples: Int?
    /// What a device's own wait was multiplied by for headroom (F12). Nil before F12.
    public var deviceMargin: Double?
    /// What each miss in a row multiplied an expected address's wait by (F13). Nil before.
    public var missBackoff: Double?
    /// Each whole step of wait beyond the first earns one more transmission, in ms.
    public var attemptsStepMillis: Double?
    /// The most transmissions any address gets.
    public var attemptsCap: Int?
    /// Transmissions for an address with no extended wait.
    public var baseAttempts: Int?
    /// How many cold first-contact samples this network's history held.
    public var historySamples: Int?
    /// Whether history was read at all. False under `--no-history`, or with nowhere to
    /// keep it — the study's empty-history arm.
    public var historyRead: Bool?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        policy: String, percentile: Double? = nil, fixedWaitMillis: Double? = nil,
        firstScan: Bool = false, expectedWaitMillis: Double? = nil,
        expectedCount: Int = 0, expectedMissing: [IPv4Address] = [],
        firstScanWaitMillis: Double? = nil, capMillis: Double? = nil, minSamples: Int? = nil,
        attemptsStepMillis: Double? = nil, attemptsCap: Int? = nil, baseAttempts: Int? = nil,
        historySamples: Int? = nil, historyRead: Bool? = nil,
        warmWaitMillis: Double? = nil, warmSamples: Int? = nil, paths: ReachPathCounts? = nil,
        expectedWindowMillis: Double? = nil, knownNetwork: Bool? = nil, unexpectedCold: String? = nil,
        deviceMinSamples: Int? = nil, deviceMargin: Double? = nil, missBackoff: Double? = nil
    ) {
        self.policy = policy
        self.percentile = percentile
        self.fixedWaitMillis = fixedWaitMillis
        self.firstScan = firstScan
        self.expectedWaitMillis = expectedWaitMillis
        self.expectedCount = expectedCount
        self.expectedMissing = expectedMissing
        self.firstScanWaitMillis = firstScanWaitMillis
        self.capMillis = capMillis
        self.minSamples = minSamples
        self.attemptsStepMillis = attemptsStepMillis
        self.attemptsCap = attemptsCap
        self.baseAttempts = baseAttempts
        self.historySamples = historySamples
        self.historyRead = historyRead
        self.warmWaitMillis = warmWaitMillis
        self.warmSamples = warmSamples
        self.paths = paths
        self.expectedWindowMillis = expectedWindowMillis
        self.knownNetwork = knownNetwork
        self.unexpectedCold = unexpectedCold
        self.deviceMinSamples = deviceMinSamples
        self.deviceMargin = deviceMargin
        self.missBackoff = missBackoff
    }

    /// The report for a plan, given the addresses the run found a device at.
    ///
    /// Missing is judged against the run's final device list, not against the sweep
    /// alone: a host the ARP sweep or a name source found is not missing, whichever
    /// engine found it.
    public init(plan: ReachPlan, found: Set<IPv4Address>, historyRead: Bool? = nil) {
        var percentile: Double?
        var fixed: Double?
        switch plan.policy {
        case .history(let p): percentile = p
        case .fixed(let wait): fixed = wait.milliseconds
        case .learned: break
        }
        self.init(
            policy: plan.policy.name,
            percentile: percentile,
            fixedWaitMillis: fixed,
            // Resolved at the sweep's start, the per-address answer; before, the plan's.
            firstScan: plan.paths.map { $0.firstScan > 0 } ?? plan.firstScan,
            expectedWaitMillis: plan.expectedWait?.milliseconds,
            expectedCount: plan.expected.count,
            expectedMissing: plan.expected.subtracting(found).sorted(),
            firstScanWaitMillis: plan.settings.firstScanWait.milliseconds,
            capMillis: plan.settings.cap.milliseconds,
            minSamples: plan.settings.minimumSamples,
            attemptsStepMillis: plan.settings.attemptsStep.milliseconds,
            attemptsCap: plan.settings.attemptsCap,
            baseAttempts: plan.settings.baseAttempts,
            historySamples: plan.historySamples,
            historyRead: historyRead,
            warmWaitMillis: plan.warmExpectedWait?.milliseconds,
            warmSamples: plan.warmSamples,
            paths: plan.paths,
            expectedWindowMillis: plan.settings.expectedWindow.milliseconds,
            knownNetwork: plan.knownNetwork,
            unexpectedCold: plan.settings.unexpectedCold.rawValue,
            deviceMinSamples: plan.settings.deviceMinimumSamples,
            deviceMargin: plan.settings.deviceMargin,
            missBackoff: plan.settings.missBackoff
        )
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case policy
        case percentile
        case fixedWaitMillis = "fixed_wait_millis"
        case firstScan = "first_scan"
        case expectedWaitMillis = "expected_wait_millis"
        case expectedCount = "expected_count"
        case expectedMissing = "expected_missing"
        case firstScanWaitMillis = "first_scan_wait_millis"
        case capMillis = "cap_millis"
        case minSamples = "min_samples"
        case attemptsStepMillis = "attempts_step_millis"
        case attemptsCap = "attempts_cap"
        case baseAttempts = "base_attempts"
        case historySamples = "history_samples"
        case historyRead = "history_read"
        case warmWaitMillis = "warm_wait_millis"
        case warmSamples = "warm_samples"
        case paths
        case expectedWindowMillis = "expected_window_millis"
        case knownNetwork = "known_network"
        case unexpectedCold = "unexpected_cold"
        case deviceMinSamples = "device_min_samples"
        case deviceMargin = "device_margin"
        case missBackoff = "miss_backoff"
    }
}
