// SweepClock.swift — the two budgets, in one place, so two engines cannot disagree
// about them.
//
// The split between a tight retransmit interval and a single end-of-sweep tail is the
// claim `Study/` was collected to test, and `ICMPSweep.swift` argues it at length. This
// file is not that argument; it is the arithmetic the argument is about, lifted out of
// the ICMP sweep when a second engine — the layer-2 ARP sweep — needed the same
// schedule.
//
// It was lifted rather than copied on purpose. A second engine with its own timing
// would make the artifact's `budget_policy` field a statement about whichever engine
// happened to write it, and two sweeps of one network on two schedules are not
// comparable — which is exactly the confusion the field exists to prevent. There is one
// model and both engines hold one of these.
//
// Two estimators, doing different jobs, and keeping them apart is the whole point:
//
//   * `network` tracks the TAIL — Jacobson's smoothed RTT plus four mean deviations,
//     which is what an estimator built to avoid spurious retransmission gives you. The
//     slowest live host defines it, and missing that host is the failure the tail exists
//     to prevent. Paid once, for the whole sweep, overlapping every address.
//
//   * `quantiles` tracks the LOW END. A lost frame costs one packet to replace, so
//     being wrong about the retransmit interval is cheap and the interval should be
//     tight. It is paid once per retransmission per address — on a /24, 244 dead
//     addresses times two retransmissions, so every millisecond of it costs 488
//     milliseconds of nothing.
//
// Feeding one estimator both jobs is what the `.shared` ablation restores, and the
// reason it is an ablation rather than a bug is that it was the original design.

/// A bounded sample of observed round trips, for asking about quantiles.
///
/// A sorted array rather than a sketch: a sweep sees at most a few hundred replies, and
/// the exactness is worth more than the constant factor at that size. Bounded so a watch
/// loop cannot grow it without limit.
public struct RTTQuantiles: Sendable, Hashable {
    private var samples: [Duration] = []
    private let capacity = 512

    /// Fresh, with nothing observed.
    public init() {}

    /// Whether anything has been observed.
    public var isEmpty: Bool { samples.isEmpty }
    /// How many samples are held.
    public var count: Int { samples.count }

    /// Inserts a sample, keeping the array sorted.
    public mutating func record(_ sample: Duration) {
        guard sample >= .zero else { return }
        let index = samples.firstIndex { $0 > sample } ?? samples.count
        samples.insert(sample, at: index)
        // Drop the largest when full. The tail is what the network estimator tracks;
        // this structure exists for the low end and should not spend its capacity on
        // outliers.
        if samples.count > capacity { samples.removeLast() }
    }

    /// The value at a quantile, or nil when nothing has been observed.
    public func quantile(_ q: Double) -> Duration? {
        guard !samples.isEmpty else { return nil }
        let position = Int((Double(samples.count - 1) * min(max(q, 0), 1)).rounded())
        return samples[position]
    }
}

/// How long a sweep waits, and for which of the two questions.
///
/// Holds both estimators and answers the three timing questions every sweep asks. An
/// engine records a round trip as it observes one and reads budgets back; nothing else
/// about the engine's shape is assumed here, which is what lets an ICMP sweep and an
/// ARP sweep share it.
public struct SweepClock: Sendable {
    /// Which budgets exist, and whether the interval is measured or imposed.
    public let budgets: SweepBudgets
    /// Tracks the tail. Used for the single end-of-sweep wait, never for a probe expiry.
    public private(set) var network = RTTEstimator()
    /// Tracks the low end. Used for the retransmit interval, never for the tail.
    public private(set) var quantiles = RTTQuantiles()

    /// A clock with no observations yet.
    public init(budgets: SweepBudgets = .split) {
        self.budgets = budgets
    }

    /// How many round trips have been observed.
    ///
    /// Read by the spread, which refuses to freeze a schedule on fewer than two: a
    /// single outlier setting the spacing for a whole sweep is a measured failure, not
    /// a hypothetical one.
    public var sampleCount: Int { quantiles.count }

    /// Folds in one observed round trip.
    ///
    /// Both estimators see every sample. They differ in what they do with it, not in
    /// what they are shown.
    public mutating func record(_ sample: Duration) {
        network.record(sample)
        quantiles.record(sample)
    }

    /// How long an unanswered probe waits before being resent.
    ///
    /// The median of observed round trips, doubled. Half the responsive hosts on this
    /// network answer inside it, and the ones that do not are covered by the tail — so
    /// being wrong costs one extra packet rather than a missed host, which is what lets
    /// it be this tight.
    ///
    /// With no samples yet it is 100 ms: long enough that the first replies have a
    /// chance to arrive and inform the estimate, short enough that a sweep of an empty
    /// network is not waiting on a guess.
    ///
    /// Under ``SweepBudgets/shared`` there is no separate interval to compute: the
    /// tail's number answers both questions, which is the whole of what that ablation
    /// changes. Under ``SweepBudgets/fixedRetransmit(_:)`` the stated value is returned
    /// as given — not clamped to the 25–150 ms range the adaptive path uses, because
    /// those bounds exist to keep a *measurement* sane and there is no measurement here.
    /// Clamping an imposed value would silently produce a scan the operator did not ask
    /// for, and the artifact would report the clamped number as though it had been
    /// chosen.
    public func retransmitBudget() -> Duration {
        switch budgets {
        case .shared:
            return tailBudget()
        case .fixedRetransmit(let pinned):
            return pinned
        case .split:
            guard let median = quantiles.quantile(0.5) else { return .milliseconds(100) }
            return min(max(median * 2, .milliseconds(25)), .milliseconds(150))
        }
    }

    /// How long the sweep waits at the end before calling the silent addresses absent.
    ///
    /// The tail — srtt + 4·rttvar, which is what Jacobson's estimator is for — because
    /// the slowest live host defines it and missing that host is the failure this whole
    /// budget exists to prevent. Paid once for the entire sweep.
    public func tailBudget() -> Duration {
        min(max(network.timeout(initial: .milliseconds(400),
                                floor: .milliseconds(250),
                                ceiling: .seconds(2)), .milliseconds(250)), .seconds(2))
    }

    /// How long a reply is expected to take, on the estimator's own evidence.
    ///
    /// The same quantity ``tailBudget()`` is built from, but WITHOUT the 250 ms floor
    /// that budget puts under it. The difference between the two is the sweep's slack:
    /// on a LAN answering in a millisecond the floor is what binds, and those spare
    /// milliseconds are time the sweep spends waiting for nothing.
    public func replyAllowance() -> Duration {
        min(
            max(
                network.timeout(
                    initial: .milliseconds(50), floor: .milliseconds(5), ceiling: .seconds(2)
                ),
                .milliseconds(5)
            ),
            .seconds(2)
        )
    }
}
