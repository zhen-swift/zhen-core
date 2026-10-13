// RTTEstimator.swift — the smoothed round-trip estimator the adaptive timeout is
// derived from.
//
// Jacobson (SIGCOMM '88) for the estimator, Karn & Partridge (SIGCOMM '87) for the
// rule that a retransmitted probe's sample must be thrown away. Both matter here for
// the same reason: a fixed timeout is exactly why conventional scanners are slow on
// a LAN. nmap waits a second for a host that answers in four hundred microseconds,
// and it does that once per host. Measuring the network and adapting to it is the
// whole performance argument of this project, so the estimator lives in core, is a
// value type, and is testable without a socket.

/// Jacobson's smoothed RTT and mean-deviation estimator over one host.
///
/// A value type on purpose: the per-host state is small, it is copied into and out
/// of the probe loop rather than shared, and there is nothing to lock.
public struct RTTEstimator: Sendable, Hashable {
    /// Smoothed RTT. `nil` until the first sample.
    public private(set) var smoothed: Duration?
    /// Mean deviation — Jacobson's cheap stand-in for the standard deviation.
    public private(set) var variation: Duration?
    /// The most recent accepted sample.
    public private(set) var latest: Duration?
    /// How many samples have been accepted. Retransmitted samples are not counted,
    /// because they were never accepted.
    public private(set) var acceptedSamples: Int = 0

    /// Gain applied to a new sample. Jacobson's 1/8.
    public static let alpha = 0.125
    /// Gain applied to the deviation. Jacobson's 1/4.
    public static let beta = 0.25
    /// Multiplier on the deviation in the timeout. Jacobson's 4.
    public static let k = 4.0

    /// Default floor on the adaptive timeout.
    ///
    /// Shared with `RTTSample.impliedTimeout` so the artifact reports the timeout that
    /// was actually in force rather than an unclamped number no probe ever used.
    public static let defaultFloor = Duration.milliseconds(20)
    /// Default ceiling on the adaptive timeout.
    public static let defaultCeiling = Duration.seconds(2)
    /// Default timeout before any sample has been taken.
    public static let defaultInitial = Duration.milliseconds(300)
    /// How far the retransmission backoff may double: ×64.
    public static let maximumBackoffExponent = 6

    /// How many times the timeout has been doubled by Karn's backoff.
    ///
    /// Reset to zero by the next unambiguous sample.
    public private(set) var backoffExponent: Int = 0

    /// A fresh estimator that has seen nothing.
    public init() {}

    /// Folds in one measured round trip.
    ///
    /// `wasRetransmitted` implements Karn's rule and it is not optional politeness:
    /// when a probe has been sent twice you cannot tell which transmission the reply
    /// answers, so the sample is ambiguous by construction. Accepting it biases the
    /// estimate toward whichever guess you made and the error compounds — on a lossy
    /// link the estimator converges on a number that describes nothing.
    ///
    /// **Karn's algorithm is two rules, and the discard alone is a trap.** Discarding
    /// ambiguous samples without also backing the timeout off produces a deadlock: a
    /// host that moves behind a slower link — a phone stepping from Ethernet-backed
    /// Wi-Fi onto a congested band — starts timing out, so every probe is
    /// retransmitted, so every reply is ambiguous, so every sample is discarded, so
    /// the estimate never grows, so the timeout stays pinned near the floor and the
    /// host times out forever. It never recovers, and it looks like a dead host.
    ///
    /// The second rule is the exit: each retransmission doubles the timeout, and the
    /// backoff persists until an unambiguous sample arrives — which it eventually
    /// does, once the window is wide enough for the first transmission to be answered
    /// inside it. That sample resets the backoff and the estimator adapts normally.
    ///
    /// - Parameters:
    ///   - sample: a round trip measured on the monotonic clock. Taking a `Duration`
    ///     rather than a millisecond `Double` is the point: there is no way to feed
    ///     this a difference of two wall-clock timestamps.
    ///   - wasRetransmitted: whether the probe this answers was sent more than once.
    public mutating func record(_ sample: Duration, wasRetransmitted: Bool = false) {
        if wasRetransmitted {
            // Rule two: discard the sample AND widen the window, or the discard
            // becomes a trap. See the note above.
            recordRetransmission()
            return
        }
        guard sample >= .zero else { return }
        // An unambiguous sample means the current window is working. Clear the
        // backoff so the estimator returns to tracking the measurement.
        backoffExponent = 0
        latest = sample
        acceptedSamples += 1

        guard let previous = smoothed, let deviation = variation else {
            // Jacobson's initialization: the first sample is the estimate, and the
            // deviation starts at half of it.
            smoothed = sample
            variation = sample / 2
            return
        }

        let error = sample.milliseconds - previous.milliseconds
        let newVariation = deviation.milliseconds + Self.beta * (abs(error) - deviation.milliseconds)
        let newSmoothed = previous.milliseconds + Self.alpha * error
        variation = .fromMilliseconds(max(0, newVariation))
        smoothed = .fromMilliseconds(max(0, newSmoothed))
    }

    /// Records that a probe timed out and is being retransmitted.
    ///
    /// For a caller that backs off at send time rather than when an ambiguous reply
    /// arrives. Call this or `record(_:wasRetransmitted: true)` — one per ambiguous
    /// exchange, not both, or the window doubles twice for one loss.
    public mutating func recordRetransmission() {
        backoffExponent = min(backoffExponent + 1, Self.maximumBackoffExponent)
    }

    /// The adaptive per-host timeout: `srtt + 4 * rttvar`, clamped, then doubled once
    /// per outstanding retransmission.
    ///
    /// Clamped at both ends deliberately. The floor stops a 200 µs LAN reply from
    /// producing a timeout so tight that ordinary scheduler jitter reads as loss;
    /// the ceiling stops one pathological host from spending the whole budget. With
    /// no samples yet, `initial` is returned — the estimator never invents a number
    /// it has no evidence for.
    public func timeout(
        initial: Duration = RTTEstimator.defaultInitial,
        floor: Duration = RTTEstimator.defaultFloor,
        ceiling: Duration = RTTEstimator.defaultCeiling
    ) -> Duration {
        let base: Duration
        if let smoothed, let variation {
            base = min(max(.fromMilliseconds(
                smoothed.milliseconds + Self.k * variation.milliseconds
            ), floor), ceiling)
        } else {
            base = initial
        }
        guard backoffExponent > 0 else { return base }
        // The ceiling still applies after backing off: one pathological host must not
        // be able to spend the entire stage budget however many times it has retried.
        return min(base * Double(1 << backoffExponent), ceiling)
    }

    /// A serializable snapshot for the model. `nil` when nothing has been measured —
    /// which is *not observed*, never zero.
    public var sample: RTTSample? {
        guard let latest else { return nil }
        return RTTSample(
            measured: latest,
            smoothed: smoothed,
            variation: variation,
            samples: acceptedSamples
        )
    }
}

extension RTTEstimator {
    /// Concurrency derived from measured latency rather than guessed.
    ///
    /// Little's law (1961): in-flight = arrival rate × mean time in system. To sustain
    /// `probesPerSecond` against a mean response time of `meanRTT`, that many probes
    /// must be outstanding. This is why `boundedPool`'s window is a computed number
    /// and must move as the sweep learns the network's actual latency: a window
    /// chosen for the internet is an order of magnitude too large for a LAN, and
    /// oversubscribing is precisely what produces the long timeout tail that costs
    /// more wall-clock than the queue ever saved (Grosvenor et al., NSDI '15).
    public static func inFlightForRate(probesPerSecond: Double, meanRTT: Duration) -> Int {
        guard probesPerSecond > 0, meanRTT > .zero else { return 1 }
        return max(1, Int((probesPerSecond * meanRTT.milliseconds / 1000).rounded(.up)))
    }
}
