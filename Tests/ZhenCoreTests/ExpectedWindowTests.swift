// ExpectedWindowTests.swift — F3 of the fixes brief (questions, Q1).
//
// "Expected" means a device was seen at the address within the last 30 days, whatever
// the store's retention. Portable: the plan is pure, so this runs on Linux.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Expected means seen inside the window, not inside retention (F3)")
struct ExpectedWindowTests {
    typealias G1 = ReachPlanTests
    static let day: Int64 = 86_400_000

    /// A device at `.last`, last seen `age` milliseconds before `G1.now`, with 20 cold samples.
    static func seen(_ last: UInt8, ageMillis age: Int64) -> StoredDevice {
        let at = Timestamp(millisecondsSinceEpoch: G1.now.millisecondsSinceEpoch - age)
        var device = Device(observing: HostFacts(ip: G1.ip(last)), in: G1.network, lastSeen: at)
        device.lastSeen = at
        return StoredDevice(
            device: device, isPresent: false,
            firstContactSamples: (1...20).map { FirstContactSample(millis: Double($0) * 50, cold: true) }
        )
    }

    @Test("A phone that left a year ago is not expected; its samples still teach the wait")
    func aYearAgo() {
        let plan = ReachPlan.make(
            addresses: G1.addresses, network: G1.network,
            devices: [Self.seen(12, ageMillis: 365 * Self.day), Self.seen(13, ageMillis: 2 * Self.day)],
            policy: .default, now: G1.now
        )
        #expect(plan.expected == [G1.ip(13)])
        #expect(plan.historySamples == 40)
        #expect(plan.wait(for: G1.ip(12)) == .zero)
        // Its own device's P97, 1,000 ms (F11), with F12's margin: × 1.25.
        #expect(plan.wait(for: G1.ip(13)) == .milliseconds(1_250))
    }

    @Test("The boundary: seen exactly 30 days ago is expected, a millisecond more is not")
    func boundary() {
        let window = 30 * Self.day
        let plan = ReachPlan.make(
            addresses: G1.addresses, network: G1.network,
            devices: [Self.seen(12, ageMillis: window), Self.seen(13, ageMillis: window + 1)],
            policy: .default, now: G1.now
        )
        #expect(plan.expected == [G1.ip(12)])
    }

    @Test("The window moves by setting it, and run.reach echoes the value used")
    func movesAndEchoes() throws {
        let devices = [Self.seen(12, ageMillis: 365 * Self.day)]
        let year = ReachSettings(expectedWindow: .seconds(400 * 86_400))
        let plan = ReachPlan.make(
            addresses: G1.addresses, network: G1.network, devices: devices,
            policy: .default, settings: year, now: G1.now
        )
        #expect(plan.expected == [G1.ip(12)])
        #expect(ReachReport(plan: plan, found: []).expectedWindowMillis == 34_560_000_000)
        #expect(ReachReport(plan: ReachPlan(policy: .learned), found: []).expectedWindowMillis == 2_592_000_000)

        struct Wire: Decodable { var expected_window_millis: Double }
        let wire = try JSONDecoder().decode(
            Wire.self, from: JSONEncoder().encode(ReachReport(plan: plan, found: []))
        )
        #expect(wire.expected_window_millis == 34_560_000_000)
    }
}
