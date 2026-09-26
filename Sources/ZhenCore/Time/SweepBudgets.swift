// SweepBudgets.swift — which budget answers which question, and how to make the sweep
// answer both with one number again.
//
// `ICMPSweep` splits its timing in two because there are two questions — "how long
// before I ask again?" and "how long before I say nobody is home?" — and one number
// cannot be right for both. That argument is made at length in `ICMPSweep.swift` and
// is not repeated here. This file is about being able to *disprove* it.
//
// ── Why an ablation needs a flag ──────────────────────────────────────────────────
//
// The split is a claim about the mechanism: that the win comes from the two budgets
// being separately chosen, not merely from the numbers happening to be good. A claim
// like that is only checkable against the same scanner with the split taken out. The
// alternative — comparing zhen to nmap's `-T` templates — tests zhen against
// a different program, which cannot isolate anything, because every other difference
// between the two comes along for the ride.
//
// So both ablations are here, and both are reachable from the command line rather than
// through a rebuild. A measurement that requires a private build is a measurement
// nobody else can repeat, and the artifact would not be able to say which build
// produced it.
//
// ── The two policies are independent, and that is deliberate ──────────────────────
//
// `.shared` changes which budgets exist. `SweepSpacing` changes how the transmissions
// are placed inside them. They are not coupled, and it would be a mistake to couple
// them: an ablation that changed two things at once could not attribute a difference
// to either. Under `.shared` the spread is still bought out of the same tail slack it
// always was, so the gaps are wide *and* the last one is pushed out — which is a real
// cost, honestly reported, rather than a knob quietly disabling another knob.
//
// ── Why this is in core and not beside the sweep that reads it ────────────────────
//
// It is a definition, not an implementation: three cases and a name, no behaviour and
// no platform. The sweep that honours it is Darwin-only, but the CLI has to name the
// policy to pass one in, and the CLI is the portability proving ground — a signature
// it cannot write without `#if` is a signature that pulls conditional compilation into
// command code, which is the one thing `ScannerFactory` exists to prevent.
//
// ── What `.shared` restores ───────────────────────────────────────────────────────
//
// The pre-split behaviour exactly: the network estimator's srtt + 4·rttvar, which
// tracks the maximum, applied as the expiry of every individual probe. On a network
// with one 600 ms host that pins the interval near the ceiling, and every dead address
// waits it out on every attempt — which is the cost the split was introduced to
// remove, and the number this policy exists to put back on the record.

/// How the sweep chooses its retransmit interval, and whether it has one at all.
///
/// The default is ``split``. The other two cases exist so the split can be measured
/// against its own absence rather than against a different scanner.
public enum SweepBudgets: Sendable, Hashable {
    /// Two budgets, separately chosen. The retransmit interval comes from a low
    /// quantile of observed round trips; the tail comes from the estimator's upper
    /// end and is paid once.
    case split

    /// One number for both questions — the tail's number, used as every probe's
    /// expiry. What the sweep did before the split, kept so the split is falsifiable.
    case shared

    /// The retransmit interval pinned to a stated value, with the tail unchanged.
    ///
    /// This is the ablation that isolates *adaptivity* rather than *separation*: the
    /// two budgets still exist and are still asked separately, but one of them has
    /// stopped responding to the network. A difference between this and ``split`` is
    /// attributable to the measurement feeding the interval, and to nothing else.
    case fixedRetransmit(Duration)

    /// How this policy names itself in the artifact.
    ///
    /// Reported for the same reason `spacing_policy` is: two scans of one network with
    /// different timing policies are not comparable, and a reader holding only the
    /// artifacts has no other way to find that out. The pinned value itself needs no
    /// separate field — it appears in `retransmit_budget_millis` like any other
    /// interval, and this says whether it was chosen or imposed.
    public var name: String {
        switch self {
        case .split: "split"
        case .shared: "shared"
        case .fixedRetransmit: "fixed-retransmit"
        }
    }
}
