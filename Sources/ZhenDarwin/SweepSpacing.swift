// SweepSpacing.swift — how far apart the transmissions to one address are, and why
// that is a separate question from how long to wait for a reply.
//
// ── The defect this exists to fix (Study/THEORY.md, correction C8) ────────────────
//
// The retransmit budget is driven from a LOW quantile of observed round trips, which
// is right when losses are independent: a dropped frame is recovered by asking again
// promptly, and asking again is cheap. But it also decides how far apart the three
// transmissions to an address are, and those are not the same question.
//
// Three transmissions spaced by a low-quantile interval span about two of them — on a
// fast LAN, fifty milliseconds. Wi-Fi power save is the normal state of every phone on
// a consumer network, and its outages are longer than that: a station wakes on the
// access point's DTIM beacon and sleeps between them, so it is unreachable for
// stretches of a hundred milliseconds and up. An outage longer than the span takes
// ALL THREE transmissions and the host is reported absent.
//
// Simulated at a fixed 15% marginal loss rate, varying only how that loss is
// distributed in time (Study/data, Study/analysis/spacing_report.py):
//
//     mean outage        indep    50ms   100ms   250ms   500ms      1s
//     three tight        0.998   0.948   0.910   0.884   0.870   0.859
//     spread             0.998   0.986   0.976   0.946   0.914   0.889
//
// The speed advantage is unchanged across that row, so this was never a speed/recall
// trade that was chosen — it was recall being lost for nothing.
//
// ── Why the spread is free ────────────────────────────────────────────────────────
//
// Delaying a transmission delays the instant the sweep can declare the silent
// addresses absent, and measured in the simulator that cost is exactly the delay,
// once, for the whole sweep rather than once per address. Bought unconditionally it
// is not free at all: a 400 ms spread roughly doubles a 300 ms sweep, which would be
// paying for correlated loss on every network including the ones that do not have any.
//
// But the sweep is already going to sit idle for the whole tail window, and the tail
// window is usually longer than a reply needs. `tailBudget` is the network estimator's
// srtt + 4·rttvar with a 250 ms floor under it, and on a LAN answering in a
// millisecond that floor is what binds — so of those 250 ms, perhaps 240 are slack the
// sweep spends waiting for nothing. The final transmission is scheduled INTO that
// slack: sent late enough to land on the far side of an outage, early enough that its
// reply is still expected before the instant the sweep was going to stop anyway.
//
// So the declaration instant is anchored to the last TIGHT transmission rather than to
// the last transmission of any kind, and the spread is bounded by what the tail window
// can absorb. The sweep ends when it always did. Under independent loss nothing
// changes at all: the same three transmissions go out, one of them later, and every
// reply that would have been matched is still matched because the matchability horizon
// has not moved.
//
// The cost of that choice is honest and bounded: where the tail budget is genuinely
// needed — a network with a 600 ms host on it, where the floor does not bind — the
// headroom is zero and so is the spread. C8 is not closed on such a network without
// paying for it, and `spreadCeiling` is the knob that would pay.
//
// ── Why the gaps are also scattered per host ──────────────────────────────────────
//
// A fixed interval against a periodic outage can resonate. If the gap lands near the
// power-save cycle, or near a whole fraction of it, every transmission to a host
// arrives at the same phase of that cycle — so a host asleep for the first is asleep
// for all of them however many are sent. Simulated against a periodic outage the notch
// is visible and sharp: a 600 ms gap against a 667 ms cycle recovers 0.950 where its
// neighbours recover 1.000. Scattering each host's gaps by ±25% removes the notch and
// costs nothing measurable, because hosts spread in parallel and the sweep's length is
// set by the longest, not the sum.
//
// The scatter is derived from the address rather than from a random source, so two
// scans of the same network space the same host the same way. A timing schedule that
// varies run to run is not reproducible, and this project has already been bitten once
// by a budget that depended on hash order.

#if canImport(Darwin)

import ZhenCore

/// How the transmissions to one address are spread in time.
public struct SweepSpacing: Sendable, Hashable {
    /// The most the final transmission may be delayed beyond the retransmit interval.
    ///
    /// A ceiling rather than a target: what is actually spent is whatever the tail
    /// window can absorb, and this only stops an unusually long tail from stretching
    /// the schedule further than any plausible outage would justify.
    public var spreadCeiling: Duration

    /// Per-host scatter applied to every gap, as a fraction of it.
    ///
    /// 0.25 means each host's gaps are drawn from ±25% of nominal, deterministically
    /// from its address.
    public var jitter: Double

    /// Creates a policy.
    public init(spreadCeiling: Duration, jitter: Double) {
        self.spreadCeiling = spreadCeiling
        self.jitter = max(0, min(jitter, 0.9))
    }

    /// Every gap is the retransmit interval. What the sweep did before C8.
    ///
    /// Kept so the regression tests can drive the old behaviour and show it failing on
    /// the case the new behaviour survives, rather than asserting the fix against
    /// itself.
    public static let uniform = SweepSpacing(spreadCeiling: .zero, jitter: 0)

    /// The default: spend the tail window rather than idling in it, and scatter.
    public static let spreadIntoTail = SweepSpacing(
        spreadCeiling: .milliseconds(400), jitter: 0.25
    )

    /// How this policy names itself in the artifact.
    public var name: String {
        spreadCeiling > .zero ? "spread-into-tail" : "uniform"
    }

    /// The scatter factor for one address: deterministic, in `1 ± jitter`.
    ///
    /// SplitMix64 finalisation over the address. A cheaper hash — the low bits of the
    /// address, say — would put adjacent addresses at adjacent phases, which is the
    /// opposite of what scattering is for on a network where the sleeping devices are
    /// often a contiguous DHCP range.
    func scatter(for address: IPv4Address) -> Double {
        guard jitter > 0 else { return 1 }
        var x = UInt64(address.raw) &+ 0x9E37_79B9_7F4A_7C15
        x = (x ^ (x >> 30)) &* 0xBF58_476D_1CE4_E5B9
        x = (x ^ (x >> 27)) &* 0x94D0_49BB_1331_11EB
        x ^= x >> 31
        let unit = Double(x >> 11) * (1.0 / Double(1 << 53))   // [0, 1)
        return 1.0 - jitter + 2.0 * jitter * unit
    }
}

#endif
