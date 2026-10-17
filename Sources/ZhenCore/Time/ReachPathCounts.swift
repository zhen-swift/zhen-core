// ReachPathCounts.swift — `run.reach.paths`: how many addresses each rule decided.
//
// Study 2 reads these to know what a scan's wall clock was spent on. A scan that ran
// 1.5 s because two hundred dead addresses were cold on a network with no cold history
// looks, from its timing alone, exactly like one that ran 1.5 s waiting for a slow host
// it expected; these say which.

/// How many probed addresses took each `ReachPath`, and how many were cold and warm.
///
/// `cold + warm` and the five path counts each add up to the addresses probed.
public struct ReachPathCounts: Sendable, Hashable, Codable {
    /// Addresses with no complete neighbour entry when the sweep started.
    public var cold: Int
    /// Addresses whose neighbour entry was complete when the sweep started.
    public var warm: Int
    /// Addresses that waited the first-scan wait.
    public var firstScan: Int
    /// Expected addresses that waited for their own device's cold samples (F11).
    public var device: Int
    /// Expected addresses that waited the network's cold percentile: their device had no
    /// cold samples of its own.
    public var coldPercentile: Int
    /// Expected addresses whose entry was already complete, which the sweep asked but
    /// did not wait for.
    public var inherited: Int
    /// Addresses left to the learned tail.
    public var learnedTail: Int

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        cold: Int = 0, warm: Int = 0, firstScan: Int = 0, coldPercentile: Int = 0,
        inherited: Int = 0, learnedTail: Int = 0, device: Int = 0
    ) {
        self.cold = cold
        self.warm = warm
        self.firstScan = firstScan
        self.device = device
        self.coldPercentile = coldPercentile
        self.inherited = inherited
        self.learnedTail = learnedTail
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case cold
        case warm
        case firstScan = "first_scan"
        case device
        case coldPercentile = "cold_percentile"
        case inherited
        case learnedTail = "learned_tail"
    }

    /// Decodes an artifact written before F11, which has no `device`, as zero.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            cold: try container.decode(Int.self, forKey: .cold),
            warm: try container.decode(Int.self, forKey: .warm),
            firstScan: try container.decode(Int.self, forKey: .firstScan),
            coldPercentile: try container.decode(Int.self, forKey: .coldPercentile),
            inherited: try container.decode(Int.self, forKey: .inherited),
            learnedTail: try container.decode(Int.self, forKey: .learnedTail),
            device: try container.decodeIfPresent(Int.self, forKey: .device) ?? 0
        )
    }
}
