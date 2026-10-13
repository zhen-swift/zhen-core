// ProbeBudget.swift — saying how big a scan is before running it.
//
// `--ports all` across a /24 is 16.7 million probes. `PortSpec.commonServices` has said
// so in its doc comment since it was written — *"a deep scan is a deliberate act, not
// the default, and 65,535 ports across a /24 is 16 million probes for almost no
// additional information"* — and nothing enforced it. The instinct was in the codebase
// and the guard was not.
//
// ── Why a floor and not a duration ────────────────────────────────────────────
//
// The number this prints is a FLOOR, derived from concurrency and the per-host budget,
// and it is deliberately not an estimate of how long the scan will take. A real
// estimate would need the network's round trips, which is the thing the scan is going
// to measure — so it would be a guess presented beside a count that is not one. A floor
// is checkable: the scan cannot beat it, and if it does the arithmetic here is wrong.

import Foundation
import ZhenCore

/// How large a port scan is, before it runs.
nonisolated struct ProbeBudget {
    /// Hosts times ports. Every probe the scan will send, ignoring retransmits.
    var probes: Int
    /// The fastest this can finish, given how many probes can be in flight at once.
    var floor: Duration

    /// Above this, a run needs `--yes`.
    ///
    /// **Chosen rather than derived, and it has to sit in a specific gap.** Above every
    /// scan this tool is built for, and below the smallest one a person would regret:
    ///
    /// | | Probes |
    /// |---|---|
    /// | `common` across a /24 — the widest deliberate scan | 9,144 |
    /// | `all` on one host — the smallest scan worth confirming | 65,535 |
    /// | `all` across a /24 | 16,645,890 |
    ///
    /// 50,000 sits in that gap. The first version of this constant was 200,000, which
    /// is outside it — above `all` on a single host — so the doc comment describing the
    /// gap and the number underneath it disagreed, and a single-host `all` would have
    /// started 65,535 probes without a word. Measured afterwards: that run returns
    /// `PARTIAL (deadline_expired)` on the default budget, which is exactly the outcome
    /// worth warning about first.
    static let confirmationThreshold = 50_000

    init(hosts: Int, ports: Int, concurrency: Int, perHostDeadline: Duration) {
        self.probes = hosts * ports
        // Integer arithmetic on the count, then one multiplication: the floor is
        // `ceil(probes / concurrency)` rounds of at most `perHostDeadline` each.
        let rounds = concurrency > 0 ? (probes + concurrency - 1) / concurrency : probes
        self.floor = perHostDeadline * rounds
    }

    /// Whether this needs confirming.
    var needsConfirmation: Bool { probes > Self.confirmationThreshold }

    /// What the refusal says, which has to carry the number it refused.
    func refusal(hosts: Int, ports: Int) -> String {
        """
        \(formatted(probes)) probes — \(formatted(ports)) ports across \(formatted(hosts)) \
        host\(hosts == 1 ? "" : "s") — would take at least \(readable(floor)). \
        Re-run with --yes if that is what you meant.
        """
    }

    /// The announcement a confirmed large scan prints before starting, on stderr, so
    /// the artifact on stdout stays clean.
    func announcement(hosts: Int, ports: Int) -> String {
        """
        \(formatted(probes)) probes — \(formatted(ports)) ports across \(formatted(hosts)) \
        host\(hosts == 1 ? "" : "s") — at least \(readable(floor)).
        """
    }

    private func formatted(_ value: Int) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        return formatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }

    private func readable(_ duration: Duration) -> String {
        let seconds = Double(duration.components.seconds)
            + Double(duration.components.attoseconds) / 1e18
        if seconds < 90 { return String(format: "%.0f seconds", seconds.rounded(.up)) }
        if seconds < 5_400 { return String(format: "%.0f minutes", (seconds / 60).rounded(.up)) }
        if seconds < 172_800 { return String(format: "%.0f hours", (seconds / 3_600).rounded(.up)) }
        return String(format: "%.0f days", (seconds / 86_400).rounded(.up))
    }
}
