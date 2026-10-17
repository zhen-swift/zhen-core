// Apple-only, like the target it tests.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// F7 of the fixes brief's addendum, in the sweep: Q15's machine. History holds only warm
/// samples, enough to make the network known, and no cold ones. Its live hosts are
/// cached; the rest of the addresses are cold and unexpected. They take the learned
/// tail, so the sweep runs study 1's schedule and ends where it would have, not 1.5 s in.
/// `--unexpected-cold first-scan` gives them the first-scan wait back.
@Suite("A known network's dead addresses keep the learned schedule (R6, sweep)")
struct KnownNetworkSweepTests {
    typealias Sweep = ReachSweepTests
    static func ip(_ last: UInt8) -> IPv4Address { Sweep.ip(last) }
    static let addresses = Sweep.addresses
    static let network = IPv4Network("10.10.20.0/24")!
    static let now = Timestamp(millisecondsSinceEpoch: 1_790_000_000_000)
    static let mac = MACAddress(raw: 0xAA_BB_CC_DD_EE_05)

    /// History expects `.5` and `.6`, and holds 20 warm samples between them, no cold.
    static func plan(expected: [UInt8] = [5, 6], settings: ReachSettings = ReachSettings()) -> ReachPlan {
        let warm = (1...10).map { FirstContactSample(millis: Double($0) * 2, cold: false) }
        let devices = expected.map { last in
            StoredDevice(
                device: Device(observing: HostFacts(ip: ip(last)), in: network, lastSeen: now),
                isPresent: true, firstContactSamples: warm
            )
        }
        return ReachPlan.make(
            addresses: addresses, network: network, devices: devices, policy: .default,
            settings: settings, now: now
        )
    }

    /// The live hosts, cached at the start of the sweep.
    static let table = [ip(5): mac, ip(6): mac]

    private func transmissions(_ state: SweepState, from start: MonotonicInstant) async -> [IPv4Address: Int] {
        var count: [IPv4Address: Int] = [:]
        var now = start
        for _ in 0..<10_000 {
            let due = await state.dueProbes(limit: 512, now: now)
            _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, now) }))
            for probe in due { count[probe.address, default: 0] += 1 }
            if await state.isSettled { break }
            now = now.advanced(by: .milliseconds(1))
        }
        return count
    }

    @Test("Warm LAN, warm-only history: study 1's schedule, and paths say no address waited 1.5 s")
    func deadAddressesKeepTheLearnedSchedule() async throws {
        let start = MonotonicInstant.now
        let planned = SweepState(
            pending: Self.addresses, neighbors: Self.table, attempts: 3, counters: ProbeCounters(), reach: Self.plan()
        )
        let plain = SweepState(pending: Self.addresses, neighbors: Self.table, attempts: 3, counters: ProbeCounters())
        #expect(!(await planned.extendsWaits))
        let a = await transmissions(planned, from: start)
        let b = await transmissions(plain, from: start)
        #expect(a == b && Set(a.values) == [3])
        let plannedEnd = await planned.declarationInstant()
        let plainEnd = await plain.declarationInstant()
        #expect(plannedEnd == plainEnd)

        let resolved = try #require(planned.resolvedReach)
        #expect(resolved.knownNetwork && resolved.firstScan)
        #expect(resolved.paths == ReachPathCounts(cold: 18, warm: 2, inherited: 2, learnedTail: 18))
        #expect(ReachReport(plan: resolved, found: []).firstScan == false)
    }

    @Test("--unexpected-cold first-scan: the dead addresses wait 1.5 s again, as under F1")
    func flagRestoresTheFirstScanWait() async throws {
        let state = SweepState(
            pending: Self.addresses, neighbors: Self.table, attempts: 3, counters: ProbeCounters(),
            reach: Self.plan(settings: ReachSettings(unexpectedCold: .firstScan))
        )
        #expect(await state.extendsWaits)
        let sent = await transmissions(state, from: .now)
        #expect(sent[Self.ip(5)] == 3)
        #expect(sent[Self.ip(7)] == 5)
        let resolved = try #require(state.resolvedReach)
        #expect(resolved.paths == ReachPathCounts(cold: 18, warm: 2, firstScan: 18, inherited: 2))
    }

    @Test("An expected address with nothing cached still waits the first-scan wait, and only it")
    func sleepingPhoneStillWaits() async throws {
        // .7 is expected and not in the table: the phone that sleeps through the cache.
        let state = SweepState(
            pending: Self.addresses, neighbors: Self.table, attempts: 3, counters: ProbeCounters(),
            reach: Self.plan(expected: [5, 6, 7])
        )
        #expect(await state.extendsWaits)
        let sent = await transmissions(state, from: .now)
        #expect(sent[Self.ip(7)] == 5)
        #expect(sent[Self.ip(8)] == 3 && sent[Self.ip(5)] == 3)
        let resolved = try #require(state.resolvedReach)
        #expect(resolved.paths == ReachPathCounts(cold: 18, warm: 2, firstScan: 1, inherited: 2, learnedTail: 17))
        #expect(await state.expectedMissing() == [Self.ip(7)])
    }
}

#endif
