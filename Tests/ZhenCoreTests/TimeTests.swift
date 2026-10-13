import Foundation
import Testing
@testable import ZhenCore

@Suite("Measurement discipline")
struct TimeTests {
    @Test("The monotonic clock is not serializable, and that is the enforcement")
    func monotonicIsNotCodable() {
        // Not an assertion that can be written as a runtime check — the point is that
        // `MonotonicInstant: Codable` does not compile, so a monotonic reading cannot
        // reach a Model/ type by accident. What can be asserted is the converse:
        // Timestamp is the only one of the two that encodes.
        // Behind a function so the check is a runtime one: written inline, the
        // compiler folds it to a constant and warns, which would hide the day
        // somebody adds the conformance.
        func isCodable(_ type: Any.Type) -> Bool { type is any Codable.Type }
        #expect(isCodable(Timestamp.self))
        #expect(!isCodable(MonotonicInstant.self))
    }

    @Test("Elapsed monotonic time is measured, not computed from wall stamps")
    func elapsedIsMonotonic() async {
        let watch = Stopwatch()
        try? await Task.sleep(for: .milliseconds(30))
        // Generous bounds: this asserts that the clock advances and is read in
        // milliseconds, not that the scheduler is precise.
        #expect(watch.elapsedMillis >= 25)
        #expect(watch.elapsedMillis < 2000)
    }

    @Test("Durations convert to milliseconds without losing microseconds")
    func subMillisecondPrecision() {
        #expect(Duration.microseconds(412).milliseconds == 0.412)
        #expect(Duration.milliseconds(1500).milliseconds == 1500)
        #expect(Duration.nanoseconds(1).milliseconds > 0)
        // Round trip through the conversion the model uses.
        #expect(Duration.fromMilliseconds(0.412).milliseconds == 0.412)
    }

    @Test("A timestamp is exact milliseconds since the epoch")
    func timestampIsExact() {
        let stamp = Timestamp(millisecondsSinceEpoch: 1_756_700_000_123)
        #expect(stamp.timeIntervalSince1970 == 1_756_700_000.123)
        #expect(Timestamp.now.millisecondsSinceEpoch > 1_700_000_000_000)
    }
}

@Suite("Adaptive timeout")
struct RTTEstimatorTests {
    @Test("An estimator with no samples invents nothing")
    func noSamplesNoEstimate() {
        let estimator = RTTEstimator()
        #expect(estimator.smoothed == nil)
        #expect(estimator.sample == nil)
        #expect(estimator.timeout(initial: .milliseconds(300)) == .milliseconds(300))
    }

    @Test("The first sample seeds the estimate")
    func firstSampleSeeds() {
        var estimator = RTTEstimator()
        estimator.record(.milliseconds(400))
        #expect(estimator.smoothed == .milliseconds(400))
        #expect(estimator.variation == .milliseconds(200))
        #expect(estimator.acceptedSamples == 1)
    }

    @Test("The estimate converges on a steady round trip")
    func converges() {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(.microseconds(400)) }
        let smoothed = try! #require(estimator.smoothed)
        #expect(abs(smoothed.milliseconds - 0.4) < 0.01)
        // And the deviation collapses, so the timeout tightens toward the real RTT
        // instead of sitting at a constant.
        let variation = try! #require(estimator.variation)
        #expect(variation.milliseconds < 0.05)
    }

    @Test("A LAN host gets a LAN timeout, floored so jitter is not read as loss")
    func lanTimeoutIsTight() {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(.microseconds(400)) }
        let timeout = estimator.timeout()
        // The whole performance argument: a host answering in 400 microseconds must
        // not be waited on for a second.
        #expect(timeout < .milliseconds(100))
        // But not so tight that ordinary scheduler jitter reads as a lost probe.
        #expect(timeout >= .milliseconds(20))
    }

    @Test("A pathological host cannot spend the whole budget")
    func ceilingHolds() {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(.seconds(30)) }
        #expect(estimator.timeout(ceiling: .seconds(2)) == .seconds(2))
    }

    @Test("Karn's rule: a retransmitted probe's sample is discarded")
    func karnsRule() {
        var estimator = RTTEstimator()
        for _ in 0..<20 { estimator.record(.milliseconds(10)) }
        let before = estimator.smoothed
        let countBefore = estimator.acceptedSamples

        // You cannot tell which transmission this answers, so it is ambiguous by
        // construction and must not move the estimate.
        estimator.record(.seconds(5), wasRetransmitted: true)

        #expect(estimator.smoothed == before)
        #expect(estimator.acceptedSamples == countBefore)
    }

    @Test("The snapshot carries the sample count, not just a number")
    func snapshotCarriesProvenance() {
        var estimator = RTTEstimator()
        estimator.record(.milliseconds(5))
        estimator.record(.milliseconds(7))
        let sample = try! #require(estimator.sample)
        #expect(sample.samples == 2)
        #expect(sample.millis == 7)
        #expect(sample.smoothedMillis != nil)
        // A report reader can reconstruct the timeout that was actually in force.
        #expect(sample.impliedTimeout > .zero)
    }

    @Test("Little's law derives the window from measured latency")
    func littlesLaw() {
        // 5,000 probes per second against a 200 ms mean RTT needs 1,000 outstanding.
        #expect(RTTEstimator.inFlightForRate(probesPerSecond: 5000, meanRTT: .milliseconds(200)) == 1000)
        // A fast LAN needs far fewer in flight for the same rate — which is exactly
        // why the number must adapt rather than be a constant tuned for the internet.
        #expect(RTTEstimator.inFlightForRate(probesPerSecond: 5000, meanRTT: .microseconds(400)) == 2)
        #expect(RTTEstimator.inFlightForRate(probesPerSecond: 0, meanRTT: .milliseconds(200)) == 1)
    }
}

@Suite("Deadlines are budgets, not errors")
struct DeadlineSemanticsTests {
    @Test("An expired deadline is a normal value a stage can be handed")
    func expiredIsConstructible() {
        #expect(Deadline.expired.isExpired)
        #expect(Deadline.expired.remaining == .zero)
    }

    @Test("A fraction of a budget cannot exceed it")
    func fractionsAreClamped() {
        let parent = Deadline(after: .seconds(10))
        #expect(parent.fraction(0.6).instant <= parent.instant)
        // 150% of the remaining time is not available, whatever the caller asks for.
        #expect(parent.fraction(1.5).instant <= parent.instant)
        #expect(parent.fraction(-1).remaining == .zero)
    }

    @Test("Deadline expiry is a success outcome, and says so")
    func expiryIsSuccess() {
        #expect(Outcome.deadlineExpired.isComplete == false)
        #expect(Outcome.complete.isComplete)
        // There is no `isError`, deliberately: none of the three outcomes is one.
        #expect(Outcome.allCases.count == 3)
    }
}
