// RTTSample.swift — a round trip, in the artifact.
//
// The only initializer that takes a measurement takes a `Duration`. There is no way
// to build one of these from a difference of two `Timestamp`s, because a `Timestamp`
// has no subtraction — which is the point. RTT is measured on the monotonic clock or
// it is not measured.
//
// Millisecond fields are `Double` and not `Int` because a LAN answers in hundreds of
// microseconds. Rounding to whole milliseconds would flatten the entire range this
// scanner is trying to compete on into 0 and 1.

/// The round-trip measurement carried per host and per port.
public struct RTTSample: Sendable, Hashable, Codable {
    /// The most recent measured round trip, in milliseconds.
    public var millis: Double
    /// Jacobson's smoothed RTT over the accepted samples. Absent until there is one.
    public var smoothedMillis: Double?
    /// Jacobson's mean deviation. With `smoothedMillis`, this is everything needed
    /// to reconstruct the adaptive timeout that was actually in force.
    public var varianceMillis: Double?
    /// How many samples the estimate rests on. One sample and a hundred are both
    /// legitimate; conflating them is not.
    public var samples: Int

    /// Builds a sample from monotonically measured durations.
    ///
    /// The `Duration`-typed parameters are the enforcement point for the whole
    /// measurement discipline: a caller holding only wall-clock stamps cannot reach
    /// this initializer.
    public init(measured: Duration, smoothed: Duration? = nil, variation: Duration? = nil, samples: Int = 1) {
        self.millis = measured.milliseconds
        self.smoothedMillis = smoothed?.milliseconds
        self.varianceMillis = variation?.milliseconds
        self.samples = samples
    }

    /// Rebuilds a sample from already-serialized millisecond values.
    ///
    /// For decoding and for a consumer reconstructing a report; not for recording a
    /// measurement. If you are timing something, use `init(measured:)`.
    public init(millis: Double, smoothedMillis: Double? = nil, varianceMillis: Double? = nil, samples: Int = 1) {
        self.millis = millis
        self.smoothedMillis = smoothedMillis
        self.varianceMillis = varianceMillis
        self.samples = samples
    }

    /// The adaptive timeout this sample implies, for a caller that has the report but
    /// not the estimator — `srtt + 4 × rttvar`, or the latest sample when there is no
    /// smoothed estimate yet, clamped exactly as the estimator clamps it.
    ///
    /// The clamps are the point. Without them this reports an unclamped number that no
    /// probe ever used: a LAN host answering in 400 microseconds has `srtt + 4·rttvar`
    /// well under a millisecond, while the timeout actually in force was the 20 ms
    /// floor. An artifact whose stated timeout differs from the one the scanner ran
    /// with is worse than one that omits it, because it will be believed.
    ///
    /// It cannot reflect a Karn backoff in force at the time — the backoff exponent is
    /// estimator state and is not serialized — so this is the timeout implied by the
    /// samples, which is what a reader reconstructing the run can check.
    public var impliedTimeout: Duration {
        let base: Duration
        if let smoothedMillis, let varianceMillis {
            base = .fromMilliseconds(smoothedMillis + RTTEstimator.k * varianceMillis)
        } else {
            base = .fromMilliseconds(millis)
        }
        return min(max(base, RTTEstimator.defaultFloor), RTTEstimator.defaultCeiling)
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case millis
        case smoothedMillis = "smoothed_millis"
        case varianceMillis = "variance_millis"
        case samples
    }
}
