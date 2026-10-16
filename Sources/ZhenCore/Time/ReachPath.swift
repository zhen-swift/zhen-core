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
    /// A complete neighbour entry, and expected: already present by the evidence the
    /// report accepts, so the sweep does not wait for more (the fixes brief, F2). It is
    /// asked on the learned schedule, and nothing holds the sweep open for it.
    ///
    /// Where F1 alone would have given it the warm samples' percentile — and F1 gives
    /// that only to an expected address with a complete entry, which is exactly this —
    /// so the warm percentile is computed and reported but waited by no address
    /// (questions, Q16).
    case inherited = "inherited"
    /// Everything else: the wait learned from this sweep's replies.
    case learnedTail = "learned_tail"
}
