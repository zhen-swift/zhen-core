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
    /// Whether the network had too little history, so every address waited the
    /// first-scan wait. Only ever true under `history`.
    public var firstScan: Bool
    /// What an expected address waited before the learned tail floored it, in
    /// milliseconds: the percentile, capped. Nil when there was none.
    public var expectedWaitMillis: Double?
    /// How many addresses history expected.
    public var expectedCount: Int
    /// The expected addresses the run found no device at, in address order.
    public var expectedMissing: [IPv4Address]

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        policy: String, percentile: Double? = nil, fixedWaitMillis: Double? = nil,
        firstScan: Bool = false, expectedWaitMillis: Double? = nil,
        expectedCount: Int = 0, expectedMissing: [IPv4Address] = []
    ) {
        self.policy = policy
        self.percentile = percentile
        self.fixedWaitMillis = fixedWaitMillis
        self.firstScan = firstScan
        self.expectedWaitMillis = expectedWaitMillis
        self.expectedCount = expectedCount
        self.expectedMissing = expectedMissing
    }

    /// The report for a plan, given the addresses the run found a device at.
    ///
    /// Missing is judged against the run's final device list, not against the sweep
    /// alone: a host the ARP sweep or a name source found is not missing, whichever
    /// engine found it.
    public init(plan: ReachPlan, found: Set<IPv4Address>) {
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
            firstScan: plan.firstScan,
            expectedWaitMillis: plan.expectedWait?.milliseconds,
            expectedCount: plan.expected.count,
            expectedMissing: plan.expected.subtracting(found).sorted()
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
    }
}
