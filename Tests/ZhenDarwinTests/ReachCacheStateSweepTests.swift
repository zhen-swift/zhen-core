// Apple-only, like the target it tests.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// F1 of the fixes brief, in the sweep: the plan is resolved against the sweep's own
/// baseline — the neighbour table read before the first transmission — so an address
/// with a complete entry is judged by the warm samples and never takes the first-scan
/// wait. The resolved plan is what `run.reach` reports.
@Suite("The sweep resolves the plan against its baseline (R1, sweep)")
struct ReachCacheStateSweepTests {
    typealias Sweep = ReachSweepTests
    static func ip(_ last: UInt8) -> IPv4Address { Sweep.ip(last) }
    static let addresses = Sweep.addresses
    static let mac = MACAddress(raw: 0xAA_BB_CC_DD_EE_01)

    /// A first scan: no history at all, so every cold address waits 1.5 s.
    static let firstScan = ReachPlan.make(
        addresses: addresses, network: IPv4Network("10.10.20.0/24")!, devices: [],
        policy: .default, now: Timestamp(millisecondsSinceEpoch: 1_790_000_000_000)
    )

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

    @Test("A warm address keeps the learned schedule on a first scan; the cold ones wait 1.5 s")
    func warmAddressIsNotFirstScan() async throws {
        let warm = Self.ip(5)
        let state = SweepState(
            pending: Self.addresses, neighbors: [warm: Self.mac], attempts: 3,
            counters: ProbeCounters(), reach: Self.firstScan
        )
        #expect(await state.extendsWaits)
        let sent = await transmissions(state, from: .now)
        #expect(sent[warm] == 3)
        #expect(sent[Self.ip(6)] == 5)
        let resolved = try #require(state.resolvedReach)
        #expect(resolved.isWarm(warm) && !resolved.isFirstScan(warm))
        #expect(resolved.paths == ReachPathCounts(cold: 19, warm: 1, firstScan: 19, learnedTail: 1))
    }

    @Test("Every address warm, too little warm history: study 1's schedule, and paths say why")
    func fullyWarmIsLearned() async throws {
        let table = Dictionary(uniqueKeysWithValues: Self.addresses.map { ($0, Self.mac) })
        let start = MonotonicInstant.now
        let planned = SweepState(
            pending: Self.addresses, neighbors: table, attempts: 3,
            counters: ProbeCounters(), reach: Self.firstScan
        )
        let plain = SweepState(
            pending: Self.addresses, neighbors: table, attempts: 3, counters: ProbeCounters()
        )
        #expect(!(await planned.extendsWaits))
        let a = await transmissions(planned, from: start)
        let b = await transmissions(plain, from: start)
        #expect(a == b && Set(a.values) == [3])
        let plannedEnd = await planned.declarationInstant()
        let plainEnd = await plain.declarationInstant()
        #expect(plannedEnd == plainEnd)
        // Not extended, but still reported: the artifact says no address waited 1.5 s
        // and why.
        let resolved = try #require(planned.resolvedReach)
        #expect(resolved.paths == ReachPathCounts(warm: 20, learnedTail: 20))
        #expect(ReachReport(plan: resolved, found: []).firstScan == false)
    }

    @Test("No plan, nothing resolved")
    func noPlan() {
        let state = SweepState(pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters())
        #expect(state.resolvedReach == nil)
    }
}

#endif
