// ReachPlanMarginTests.swift — gate R13 of the fixes brief, addendum 4 (F12).
//
// A device's own wait gets headroom over the samples it was learned from: × 1.25, never
// less than + 50 ms, then capped and floored by the learned tail. `--reach-margin 1` is
// F11's rule exactly. Portable: it runs on Linux.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Reach plan, a margin on a device's wait (R13)")
struct ReachPlanMarginTests {
    typealias G1 = ReachPlanTests
    typealias R12 = ReachPlanDeviceWaitTests
    static func ip(_ last: UInt8) -> IPv4Address { G1.ip(last) }

    static func samples(_ millis: Double...) -> [FirstContactSample] {
        millis.map { FirstContactSample(millis: $0, cold: true) }
    }

    @Test("Samples of 500, 502 and 520 ms wait 650 ms; with the margin off, 520")
    func theBriefsCase() {
        let devices = R12.fifty + [G1.stored(12, samples: Self.samples(500, 502, 520))]
        let margined = R12.plan(devices, settings: ReachSettings())
        #expect(margined.path(for: Self.ip(12)) == .device)
        #expect(margined.wait(for: Self.ip(12)) == .milliseconds(650))
        #expect(margined.attempts(for: Self.ip(12)) == 3)
        let off = R12.plan(devices, settings: ReachSettings(deviceMargin: 1))
        #expect(off.wait(for: Self.ip(12)) == .milliseconds(520))
    }

    @Test("Never less than + 50 ms; capped at 5 s; floored by the learned tail")
    func floorAndCap() {
        let devices = R12.fifty + [
            G1.stored(12, samples: Self.samples(4_500)),
            G1.stored(13, samples: Self.samples(9_000)),
        ]
        let plan = R12.plan(devices, settings: ReachSettings())
        // A fast device's 11 ms × 1.25 is under 14 ms: the + 50 ms decides.
        #expect(plan.wait(for: Self.ip(20)) == .milliseconds(61))
        #expect(plan.wait(for: Self.ip(20), learnedTail: .milliseconds(300)) == .milliseconds(300))
        // 4,500 × 1.25 = 5,625, and 9,000: both capped.
        #expect(plan.wait(for: Self.ip(12)) == .seconds(5))
        #expect(plan.wait(for: Self.ip(13)) == .seconds(5))
        // A larger factor is a flag.
        let wider = R12.plan(devices, settings: ReachSettings(deviceMargin: 1.5))
        #expect(wider.wait(for: Self.ip(20)) == .milliseconds(61))
        #expect(R12.plan(R12.fifty + [G1.stored(12, samples: Self.samples(500, 502, 520))],
                         settings: ReachSettings(deviceMargin: 1.5)).wait(for: Self.ip(12)) == .milliseconds(780))
    }

    @Test("Only a device's own wait gets the margin: the network's fallback is unchanged")
    func fallbackUnchanged() {
        let devices = R12.fifty + [G1.stored(13)]
        let plan = R12.plan(devices, settings: ReachSettings())
        #expect(plan.path(for: Self.ip(13)) == .coldPercentile)
        #expect(plan.wait(for: Self.ip(13)) == plan.expectedWait)
        let thin = R12.plan([G1.stored(13)], settings: ReachSettings())
        #expect(thin.wait(for: Self.ip(13)) == .milliseconds(1_500))
    }

    @Test("run.reach echoes the margin and the backoff")
    func echoed() throws {
        let plan = R12.plan(R12.fifty, settings: ReachSettings())
        let object = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(ReachReport(plan: plan, found: []))) as? [String: Any]
        )
        #expect(object["device_margin"] as? Double == 1.25)
        #expect(object["miss_backoff"] as? Double == 2)
    }
}
