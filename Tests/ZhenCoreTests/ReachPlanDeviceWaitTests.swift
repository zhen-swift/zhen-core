// ReachPlanDeviceWaitTests.swift — gate R12 of the fixes brief, addendum 3 (F11).
//
// Each expected address waits for its own device: the percentile of that device's cold
// samples, or their maximum while it has fewer than `deviceMinimumSamples`, floored by the
// learned tail and capped. The network's percentile is the fallback for a device with
// none. Portable, like G1: it runs on Linux.
//
// F11's rule alone: every plan here has F12's margin off, and nothing has missed (F13).
// `ReachPlanMarginTests` has both.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Reach plan, each expected address waits for its own device (R12)")
struct ReachPlanDeviceWaitTests {
    typealias G1 = ReachPlanTests
    static let addresses = G1.addresses
    static func ip(_ last: UInt8) -> IPv4Address { G1.ip(last) }

    /// `n` cold samples around `millis`, a few milliseconds apart.
    static func cold(_ n: Int, around millis: Double) -> [FirstContactSample] {
        (0..<n).map { FirstContactSample(millis: millis + Double($0 % 7), cold: true) }
    }

    static func plan(
        _ devices: [StoredDevice], policy: SweepReach = .default, settings: ReachSettings = ReachSettings(deviceMargin: 1),
        complete: Set<IPv4Address> = []
    ) -> ReachPlan {
        ReachPlan.make(
            addresses: addresses, network: G1.network, devices: devices,
            policy: policy, settings: settings, now: G1.now
        ).atSweepStart(addresses: addresses, complete: complete)
    }

    /// Fifty fast devices at `.20`–`.69`, twenty cold samples each at 5–11 ms.
    static var fifty: [StoredDevice] {
        (20...69).map { G1.stored(UInt8($0), samples: cold(20, around: 5)) }
    }

    @Test("One slow device among fifty fast ones waits for itself; the network's P97 would miss it")
    func oneSlowAmongFifty() throws {
        // A sleeping phone: twenty cold first contacts at 1,000–1,006 ms. It is 20 of the
        // network's 1,020 samples, under 2%, so P97 of the pool is a fast host's time.
        let plan = Self.plan(Self.fifty + [G1.stored(12, samples: Self.cold(20, around: 1_000))])
        #expect(plan.historySamples == 1_020)
        let pooled = try #require(plan.expectedWait)
        #expect(pooled < .milliseconds(20), "the shortcut F11 replaces: P97 of the pool is fast")

        #expect(plan.path(for: Self.ip(12)) == .device)
        #expect(plan.wait(for: Self.ip(12)) == .milliseconds(1_006))
        #expect(plan.attempts(for: Self.ip(12)) == 4)
        // The learned tail floors it and never shortens it.
        #expect(plan.wait(for: Self.ip(12), learnedTail: .milliseconds(300)) == .milliseconds(1_006))
        // A fast device's own wait is its own few milliseconds, which the tail floors.
        #expect(plan.path(for: Self.ip(20)) == .device)
        #expect(plan.wait(for: Self.ip(20)) == .milliseconds(11))
        #expect(plan.wait(for: Self.ip(20), learnedTail: .milliseconds(300)) == .milliseconds(300))
        #expect(plan.attempts(for: Self.ip(20)) == 3)
        // Nobody else waits for the slow phone: an unexpected address keeps the tail.
        #expect(plan.path(for: Self.ip(100)) == .learnedTail)
        #expect(plan.wait(for: Self.ip(100)) == .zero)
        #expect(plan.paths == ReachPathCounts(cold: 254, device: 51) .with(learnedTail: 203))
    }

    @Test("A device with three samples waits their maximum; from five, their percentile")
    func fewSamplesWaitTheMaximum() {
        // P50 makes the difference visible: at P97 a handful's percentile is its maximum.
        let median = SweepReach.history(percentile: 0.5)
        let three = Self.plan(
            Self.fifty + [G1.stored(12, samples: [400, 900, 650].map { FirstContactSample(millis: $0, cold: true) })],
            policy: median
        )
        #expect(three.path(for: Self.ip(12)) == .device)
        #expect(three.wait(for: Self.ip(12)) == .milliseconds(900))

        let five = Self.plan(
            Self.fifty + [G1.stored(12, samples: [400, 900, 650, 500, 700].map { FirstContactSample(millis: $0, cold: true) })],
            policy: median
        )
        #expect(five.wait(for: Self.ip(12)) == .milliseconds(650))

        // The threshold is a setting, and a flag (`--reach-device-min-samples`).
        let six = Self.plan(
            Self.fifty + [G1.stored(12, samples: [400, 900, 650, 500, 700].map { FirstContactSample(millis: $0, cold: true) })],
            policy: median, settings: ReachSettings(deviceMinimumSamples: 6, deviceMargin: 1)
        )
        #expect(six.wait(for: Self.ip(12)) == .milliseconds(900))
    }

    @Test("A device with no cold samples falls back to the network's value")
    func noSamplesFallsBack() {
        // `.13` is expected and has only warm samples: the network's percentile decides.
        let devices = Self.fifty + [G1.stored(13, samples: [FirstContactSample(millis: 2, cold: false)])]
        let plan = Self.plan(devices)
        #expect(plan.path(for: Self.ip(13)) == .coldPercentile)
        #expect(plan.wait(for: Self.ip(13)) == plan.expectedWait)
        #expect(plan.deviceWaits[Self.ip(13)] == nil)

        // On a network with too few cold samples, the first-scan wait, as before F11.
        let thin = Self.plan([G1.stored(13), G1.stored(20, samples: Self.cold(3, around: 5))])
        #expect(thin.firstScan)
        #expect(thin.path(for: Self.ip(13)) == .firstScan)
        #expect(thin.wait(for: Self.ip(13)) == .milliseconds(1_500))
        // While `.20`, with three of its own, waits for itself however few the network has.
        #expect(thin.path(for: Self.ip(20)) == .device)
        #expect(thin.wait(for: Self.ip(20)) == .milliseconds(7))
    }

    @Test("A device's wait is capped at 5 s")
    func capped() {
        let plan = Self.plan(Self.fifty + [G1.stored(12, samples: Self.cold(20, around: 9_000))])
        #expect(plan.wait(for: Self.ip(12)) == .seconds(5))
        #expect(plan.attempts(for: Self.ip(12)) == 8)
    }

    @Test("Only expected, cold addresses wait for their device")
    func expectedAndColdOnly() {
        let devices = Self.fifty + [
            G1.stored(12, samples: Self.cold(20, around: 1_000)),
            // Last seen 40 days ago: its samples still count, it isn't waited for.
            G1.stored(13, ageDays: 40, samples: Self.cold(20, around: 1_500)),
        ]
        let plan = Self.plan(devices, complete: [Self.ip(12)])
        // Warm: inherited, as F2 says, whatever its device's cold samples are.
        #expect(plan.path(for: Self.ip(12)) == .inherited)
        #expect(plan.wait(for: Self.ip(12)) == .zero)
        // Not expected: the learned tail.
        #expect(plan.path(for: Self.ip(13)) == .learnedTail)
        #expect(plan.historySamples == 1_040)
    }

    @Test("Two recent devices at one address: the one seen last decides")
    func latestHolderDecides() {
        var older = G1.stored(12, samples: Self.cold(20, around: 1_000))
        older.device.lastSeen = Timestamp(millisecondsSinceEpoch: G1.now.millisecondsSinceEpoch - 86_400_000)
        let newer = G1.stored(12, samples: Self.cold(20, around: 40))
        for order in [[older, newer], [newer, older]] {
            #expect(Self.plan(Self.fifty + order).wait(for: Self.ip(12)) == .milliseconds(46))
        }
    }

    @Test("Learned and fixed are untouched, and run.reach says how many waited for their device")
    func otherPoliciesAndReport() throws {
        let devices = Self.fifty + [G1.stored(12, samples: Self.cold(20, around: 1_000))]
        let learned = Self.plan(devices, policy: .learned)
        #expect(learned.deviceWaits.isEmpty)
        #expect(learned.wait(for: Self.ip(12)) == .zero)
        #expect(Self.plan(devices, policy: .fixed(.seconds(2))).wait(for: Self.ip(12)) == .seconds(2))

        let report = ReachReport(plan: Self.plan(devices), found: [])
        let object = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any]
        )
        let paths = try #require(object["paths"] as? [String: Int])
        #expect(paths["device"] == 51)
        #expect(paths["cold_percentile"] == 0)
        #expect(object["device_min_samples"] as? Int == 5)
        // An artifact written before F11 has no `device`, and reads as none.
        let older = try JSONDecoder().decode(ReachPathCounts.self, from: Data(
            #"{"cold":253,"warm":1,"first_scan":0,"cold_percentile":2,"inherited":1,"learned_tail":250}"#.utf8
        ))
        #expect(older.device == 0 && older.coldPercentile == 2)
    }
}

private extension ReachPathCounts {
    func with(learnedTail: Int) -> ReachPathCounts {
        var copy = self
        copy.learnedTail = learnedTail
        return copy
    }
}
