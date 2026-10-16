// ReachPathCounts.swift — `run.reach.paths`: how many addresses each rule decided.
//
// Study 2 reads these to know what a scan's wall clock was spent on. A scan that ran
// 1.5 s because two hundred dead addresses were cold on a network with no cold history
// looks, from its timing alone, exactly like one that ran 1.5 s waiting for a slow host
// it expected; these say which.

/// How many probed addresses took each `ReachPath`, and how many were cold and warm.
///
/// `cold + warm` and the four path counts each add up to the addresses probed.
public struct ReachPathCounts: Sendable, Hashable, Codable {
    /// Addresses with no complete neighbour entry when the sweep started.
    public var cold: Int
    /// Addresses whose neighbour entry was complete when the sweep started.
    public var warm: Int
    /// Addresses that waited the first-scan wait.
    public var firstScan: Int
    /// Addresses that waited the cold samples' percentile.
    public var coldPercentile: Int
    /// Addresses that waited the warm samples' percentile.
    public var warmPercentile: Int
    /// Addresses left to the learned tail.
    public var learnedTail: Int

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        cold: Int = 0, warm: Int = 0, firstScan: Int = 0, coldPercentile: Int = 0,
        warmPercentile: Int = 0, learnedTail: Int = 0
    ) {
        self.cold = cold
        self.warm = warm
        self.firstScan = firstScan
        self.coldPercentile = coldPercentile
        self.warmPercentile = warmPercentile
        self.learnedTail = learnedTail
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case cold
        case warm
        case firstScan = "first_scan"
        case coldPercentile = "cold_percentile"
        case warmPercentile = "warm_percentile"
        case learnedTail = "learned_tail"
    }
}
