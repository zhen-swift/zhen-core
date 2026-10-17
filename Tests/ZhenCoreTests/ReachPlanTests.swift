// ReachPlanTests.swift — gate G1 of the 0.8.0 brief.
//
// Percentile, cold-only samples, the under-20 fallback, the caps, and the expected set.
// Portable on purpose: the plan is a pure function so the rules that decide how long a
// scan waits can be checked on Linux, where nothing can be measured.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Reach plan (G1)")
struct ReachPlanTests {
    static let network = IPv4Network("192.168.64.0/24")!
    static let addresses = network.hosts
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0xC0A8_4000 | UInt32(last)) }
    static let now = Timestamp(millisecondsSinceEpoch: 1_790_000_000_000)

    /// A device history holds at `.last`, last seen `ageDays` ago, with these samples.
    static func stored(
        _ last: UInt8, ageDays: Int = 0, samples: [FirstContactSample] = []
    ) -> StoredDevice {
        let seen = Timestamp(millisecondsSinceEpoch: now.millisecondsSinceEpoch - Int64(ageDays) * 86_400_000)
        var device = Device(observing: HostFacts(ip: ip(last)), in: network, lastSeen: seen)
        device.lastSeen = seen
        return StoredDevice(device: device, isPresent: true, firstContactSamples: samples)
    }

    /// A device at `.200` last seen 40 days ago, holding these samples. They still count
    /// for the network (F3), and nobody waits for it, so the devices expected beside it
    /// have no cold samples of their own and take the network's rules — the fallback F11
    /// keeps for exactly that case. `ReachPlanDeviceWaitTests` has the device's own rule.
    static func pool(_ samples: [FirstContactSample]) -> StoredDevice {
        stored(200, ageDays: 40, samples: samples)
    }

    static func cold(_ millis: Double...) -> [FirstContactSample] {
        millis.map { FirstContactSample(millis: $0, cold: true) }
    }

    static func warm(_ millis: Double...) -> [FirstContactSample] {
        millis.map { FirstContactSample(millis: $0, cold: false) }
    }

    /// `.12` and `.13` expected, and twenty cold samples, 50 ms to 1,000 ms in 50 ms
    /// steps, in the network's pool.
    static var twentyColdDevices: [StoredDevice] {
        let all = (1...20).map { FirstContactSample(millis: Double($0) * 50, cold: true) }
        return [stored(12), stored(13), pool(all)]
    }

    @Test("Nearest-rank percentile: P97 of twenty is the maximum, P50 the tenth")
    func nearestRank() {
        let samples = (1...20).map { Double($0) * 50 }
        #expect(ReachPlan.percentile(0.97, of: samples) == 1_000)
        #expect(ReachPlan.percentile(0.5, of: samples) == 500)
        #expect(ReachPlan.percentile(1.0, of: samples) == 1_000)
        #expect(ReachPlan.percentile(0.0, of: samples) == 50)
        #expect(ReachPlan.percentile(0.97, of: (1...100).map(Double.init)) == 97)
        #expect(ReachPlan.percentile(0.97, of: []) == nil)
    }

    @Test("An expected address waits P97 of the cold samples, with more attempts")
    func expectedWaitsThePercentile() {
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: Self.twentyColdDevices,
            policy: .default, now: Self.now
        )
        #expect(!plan.firstScan)
        #expect(plan.historySamples == 20)
        #expect(plan.expected == [Self.ip(12), Self.ip(13)])
        #expect(plan.expectedWait == .milliseconds(1_000))
        #expect(plan.wait(for: Self.ip(12)) == .milliseconds(1_000))
        // 1,000 ms is two steps of 500: the first is covered by the base, the second
        // earns one more.
        #expect(plan.attempts(for: Self.ip(12)) == 4)
        // Not expected: the learned tail alone, and today's three.
        #expect(plan.wait(for: Self.ip(50)) == .zero)
        #expect(plan.attempts(for: Self.ip(50)) == 3)
        #expect(plan.extendsAnyWait)
    }

    @Test("Warm samples never reach the percentile: they measure ICMP alone")
    func coldOnly() {
        // Nineteen cold samples and a hundred warm ones is still a first scan, and the
        // warm ones would have dragged P97 down to ICMP's few milliseconds.
        let devices = [
            Self.stored(12, samples: Self.cold(900, 950, 1_000, 980, 990, 970, 960, 940, 930, 920,
                                               910, 905, 915, 925, 935, 945, 955, 965, 975)),
            Self.stored(13, samples: (0..<100).map { _ in FirstContactSample(millis: 3, cold: false) }),
        ]
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: devices,
            policy: .default, now: Self.now
        )
        #expect(plan.historySamples == 19)
        #expect(plan.firstScan)

        // One more cold sample crosses the line, and the warm hundred are still ignored.
        let crossed = [
            devices[0],
            Self.stored(13, samples: Self.cold(1_000) + (0..<100).map { _ in FirstContactSample(millis: 3, cold: false) }),
        ]
        let planned = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: crossed,
            policy: .default, now: Self.now
        )
        #expect(!planned.firstScan)
        #expect(planned.expectedWait == .milliseconds(1_000))
    }

    @Test("Under twenty cold samples, every address waits 1.5 s with five attempts")
    func firstScanFallback() {
        for devices in [[], [Self.stored(12), Self.pool(Self.cold(400, 500))]] {
            let plan = ReachPlan.make(
                addresses: Self.addresses, network: Self.network, devices: devices,
                policy: .default, now: Self.now
            )
            #expect(plan.firstScan)
            #expect(plan.expectedWait == nil)
            for address in [Self.ip(1), Self.ip(12), Self.ip(254)] {
                #expect(plan.wait(for: address) == .milliseconds(1_500))
                #expect(plan.attempts(for: address) == 5)
            }
            #expect(plan.extendsAnyWait)
        }
    }

    @Test("The wait is capped at 5 s and the attempts at 8")
    func caps() {
        let slow = [Self.stored(12, samples: (0..<20).map { _ in FirstContactSample(millis: 9_000, cold: true) })]
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: slow,
            policy: .default, now: Self.now
        )
        #expect(plan.expectedWait == .seconds(5))
        #expect(plan.attempts(for: Self.ip(12)) == 8)

        let settings = ReachSettings()
        #expect(settings.attempts(forWait: .milliseconds(400)) == 3)
        #expect(settings.attempts(forWait: .milliseconds(999)) == 3)
        #expect(settings.attempts(forWait: .milliseconds(1_000)) == 4)
        #expect(settings.attempts(forWait: .milliseconds(1_500)) == 5)
        #expect(settings.attempts(forWait: .seconds(60)) == 8)
    }

    @Test("The learned tail floors an expected wait; it never shortens one")
    func learnedTailFloors() {
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: Self.twentyColdDevices,
            policy: .history(percentile: 0.5), now: Self.now
        )
        #expect(plan.expectedWait == .milliseconds(500))
        #expect(plan.wait(for: Self.ip(12), learnedTail: .milliseconds(250)) == .milliseconds(500))
        #expect(plan.wait(for: Self.ip(12), learnedTail: .milliseconds(800)) == .milliseconds(800))
        #expect(plan.wait(for: Self.ip(50), learnedTail: .milliseconds(310)) == .milliseconds(310))
    }

    @Test("The expected set: in the target, in this network, seen inside the expected window")
    func expectedSet() {
        let devices = [
            Self.stored(12),
            Self.stored(13, ageDays: 40),
            // Another network's device, and its samples, say nothing about this one.
            StoredDevice(
                device: Device(observing: HostFacts(ip: IPv4Address("10.10.20.5")!),
                               in: IPv4Network("10.10.20.0/24")!, lastSeen: Self.now),
                isPresent: true,
                firstContactSamples: (0..<30).map { _ in FirstContactSample(millis: 4_000, cold: true) }
            ),
        ]
        // The default window is 30 days: .13, last seen 40 days ago, is not expected.
        let month = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: devices,
            policy: .default, now: Self.now
        )
        #expect(month.expected == [Self.ip(12)])
        #expect(month.historySamples == 0)

        let longer = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: devices,
            policy: .default, settings: ReachSettings(expectedWindow: .seconds(60 * 86_400)),
            now: Self.now
        )
        #expect(longer.expected == [Self.ip(12), Self.ip(13)])

        // A sweep of named addresses only expects among them.
        let named = ReachPlan.make(
            addresses: [Self.ip(13)], network: Self.network, devices: devices,
            policy: .default, settings: ReachSettings(expectedWindow: .seconds(60 * 86_400)),
            now: Self.now
        )
        #expect(named.expected == [Self.ip(13)])
    }

    @Test("Learned is study 1: no address waits longer and every address gets the base attempts")
    func learnedIsUnchanged() {
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: Self.twentyColdDevices,
            policy: .learned, now: Self.now
        )
        #expect(!plan.extendsAnyWait)
        #expect(!plan.firstScan)
        #expect(plan.wait(for: Self.ip(12)) == .zero)
        #expect(plan.attempts(for: Self.ip(12)) == 3)
        // History is still read, so the report can say what it held.
        #expect(plan.expected == [Self.ip(12), Self.ip(13)])
        #expect(plan.historySamples == 20)
    }

    @Test("Fixed waits exactly what it says, tail or not")
    func fixedIsFixed() {
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: [],
            policy: .fixed(.seconds(2)), now: Self.now
        )
        #expect(plan.wait(for: Self.ip(1), learnedTail: .milliseconds(400)) == .seconds(2))
        #expect(plan.wait(for: Self.ip(1), learnedTail: .seconds(3)) == .seconds(2))
        #expect(plan.attempts(for: Self.ip(1)) == 6)
    }

    @Test("Every constant moves by setting it, which is what the study's flags do")
    func settingsOverride() {
        let settings = ReachSettings(
            firstScanWait: .seconds(1), cap: .milliseconds(700), minimumSamples: 5,
            attemptsStep: .milliseconds(250), attemptsCap: 6, baseAttempts: 3
        )
        let few = [Self.stored(12, samples: Self.cold(100, 200, 300, 400, 900))]
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: few,
            policy: .default, settings: settings, now: Self.now
        )
        #expect(!plan.firstScan)
        #expect(plan.expectedWait == .milliseconds(700))
        // 700 ms is two whole steps of 250: one extra.
        #expect(plan.attempts(for: Self.ip(12)) == 4)

        let first = ReachPlan.make(
            addresses: Self.addresses, network: Self.network, devices: [],
            policy: .default, settings: settings, now: Self.now
        )
        #expect(first.wait(for: Self.ip(1)) == .seconds(1))
        #expect(first.attempts(for: Self.ip(1)) == 6)
    }
}
