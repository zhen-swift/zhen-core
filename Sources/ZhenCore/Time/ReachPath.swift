// ReachPath.swift — which rule of the `.history` policy decided an address's wait.

/// Which rule of `.history` decided an address's wait.
///
/// The address's own neighbour entry at the start of the sweep picks the sample set —
/// cold without a complete entry, warm with one — and history picks the rule. See
/// `ReachPlan.path(for:)`.
public enum ReachPath: String, Sendable, Hashable, CaseIterable, Codable {
    /// No complete neighbour entry, and too few cold samples: `firstScanWait`.
    case firstScan = "first_scan"
    /// No complete neighbour entry, expected, and enough cold samples: their percentile.
    case coldPercentile = "cold_percentile"
    /// A complete neighbour entry, expected, and enough warm samples: their percentile,
    /// floored by the learned tail.
    case warmPercentile = "warm_percentile"
    /// Everything else: the wait learned from this sweep's replies.
    case learnedTail = "learned_tail"
}
