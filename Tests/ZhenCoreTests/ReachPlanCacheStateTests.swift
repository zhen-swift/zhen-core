// ReachPlanCacheStateTests.swift — gate R1 of the fixes brief (F1).
//
// The sample set is chosen per address, by its own neighbour entry at the start of the
// sweep: cold samples (or the first-scan wait) without a complete entry, warm samples
// (or the learned tail) with one. Cold-only, warm-only and mixed baselines, and the
// property the fix exists for: a warm address never waits the first-scan wait.
// Portable, like G1: it runs on Linux.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Reach plan, cold and warm per address (R1)")
struct ReachPlanCacheStateTests {
    typealias G1 = ReachPlanTests
    static let addresses = G1.addresses
    static func ip(_ last: UInt8) -> IPv4Address { G1.ip(last) }

    /// `.12` and `.13` expected, with `cold` cold samples and `warm` warm ones between
    /// them: the cold ones 50 ms apart up to 1,000 ms, the warm ones 2 ms apart from 2.
    static func history(cold: Int, warm: Int) -> [StoredDevice] {
        let coldSamples = (0..<cold).map { FirstContactSample(millis: Double($0 % 20 + 1) * 50, cold: true) }
        let warmSamples = (0..<warm).map { FirstContactSample(millis: Double($0 % 20 + 1) * 2, cold: false) }
        return [
            G1.stored(12, samples: Array(coldSamples.prefix(cold / 2)) + Array(warmSamples.prefix(warm / 2))),
            G1.stored(13, samples: Array(coldSamples.dropFirst(cold / 2)) + Array(warmSamples.dropFirst(warm / 2))),
        ]
    }

    static func plan(cold: Int, warm: Int, complete: Set<IPv4Address>) -> ReachPlan {
        ReachPlan.make(
            addresses: addresses, network: G1.network, devices: history(cold: cold, warm: warm),
            policy: .default, now: G1.now
        ).atSweepStart(addresses: addresses, complete: complete)
    }

    @Test("Cold-only baseline: today's rule, unchanged — and the counts say so")
    func coldOnly() throws {
        // Enough cold history: expected addresses wait the cold P97, the rest the tail.
        let primed = Self.plan(cold: 20, warm: 0, complete: [])
        #expect(primed.path(for: Self.ip(12)) == .coldPercentile)
        #expect(primed.wait(for: Self.ip(12)) == .milliseconds(1_000))
        #expect(primed.path(for: Self.ip(50)) == .learnedTail)
        #expect(primed.wait(for: Self.ip(50)) == .zero)
        let counts = try #require(primed.paths)
        #expect(counts == ReachPathCounts(cold: 254, warm: 0, coldPercentile: 2, learnedTail: 252))

        // Too little: every cold address waits the first-scan wait, as before F1.
        let first = Self.plan(cold: 19, warm: 0, complete: [])
        for address in [Self.ip(1), Self.ip(12), Self.ip(254)] {
            #expect(first.isFirstScan(address))
            #expect(first.wait(for: address) == .milliseconds(1_500))
            #expect(first.attempts(for: address) == 5)
        }
        #expect(first.paths == ReachPathCounts(cold: 254, firstScan: 254))
    }

    @Test("Warm-only baseline: no first-scan wait anywhere, with no cold history at all")
    func warmOnly() throws {
        let everything = Set(Self.addresses)
        // Q8's machine: it has only ever scanned warm. Too few warm samples: the
        // learned tail alone, everywhere — no address waits 1.5 s.
        let fresh = Self.plan(cold: 0, warm: 4, complete: everything)
        #expect(fresh.firstScan, "the cold sample set is still empty")
        for address in [Self.ip(1), Self.ip(12), Self.ip(254)] {
            #expect(!fresh.isFirstScan(address))
            #expect(fresh.path(for: address) == .learnedTail)
            #expect(fresh.wait(for: address) == .zero)
            #expect(fresh.attempts(for: address) == 3)
        }
        #expect(fresh.paths == ReachPathCounts(warm: 254, learnedTail: 254))

        // Enough warm samples: expected addresses wait their percentile, floored by the
        // learned tail, so in practice the tail.
        let primed = Self.plan(cold: 0, warm: 20, complete: everything)
        #expect(primed.warmSamples == 20)
        #expect(primed.warmExpectedWait == .milliseconds(40))
        #expect(primed.path(for: Self.ip(12)) == .warmPercentile)
        #expect(primed.wait(for: Self.ip(12)) == .milliseconds(40))
        #expect(primed.wait(for: Self.ip(12), learnedTail: .milliseconds(250)) == .milliseconds(250))
        #expect(primed.attempts(for: Self.ip(12)) == 3)
        #expect(primed.path(for: Self.ip(50)) == .learnedTail)
        #expect(primed.paths == ReachPathCounts(warm: 254, warmPercentile: 2, learnedTail: 252))
    }

    @Test("Mixed baseline: each address judged by its own entry")
    func mixed() throws {
        // .12 warm, .13 cold, everything else cold; cold history too thin, warm enough.
        let thinCold = Self.plan(cold: 10, warm: 20, complete: [Self.ip(12), Self.ip(1)])
        #expect(thinCold.path(for: Self.ip(12)) == .warmPercentile)
        #expect(thinCold.path(for: Self.ip(1)) == .learnedTail)
        #expect(thinCold.path(for: Self.ip(13)) == .firstScan)
        #expect(thinCold.path(for: Self.ip(200)) == .firstScan)
        #expect(thinCold.paths == ReachPathCounts(
            cold: 252, warm: 2, firstScan: 252, warmPercentile: 1, learnedTail: 1
        ))

        // Cold history enough, warm too thin: the warm expected address falls back to
        // the learned tail, never to the first-scan wait; the cold one waits the cold P97.
        let thinWarm = Self.plan(cold: 20, warm: 3, complete: [Self.ip(12)])
        #expect(thinWarm.path(for: Self.ip(12)) == .learnedTail)
        #expect(thinWarm.path(for: Self.ip(13)) == .coldPercentile)
        #expect(thinWarm.wait(for: Self.ip(13)) == .milliseconds(1_000))
        #expect(thinWarm.attempts(for: Self.ip(13)) == 4)
        #expect(thinWarm.paths == ReachPathCounts(
            cold: 253, warm: 1, coldPercentile: 1, learnedTail: 253
        ))
    }

    @Test("A warm address never gets the first-scan wait, whatever history holds")
    func warmNeverFirstScan() {
        for cold in [0, 5, 19, 20, 40] {
            for warm in [0, 5, 19, 20, 40] {
                let plan = Self.plan(cold: cold, warm: warm, complete: [Self.ip(12), Self.ip(77)])
                for address in [Self.ip(12), Self.ip(77)] {
                    #expect(!plan.isFirstScan(address))
                    #expect(plan.wait(for: address) != plan.settings.firstScanWait)
                    #expect(plan.wait(for: address, learnedTail: .milliseconds(250)) < .milliseconds(1_500))
                }
            }
        }
    }

    @Test("Unresolved, every address is cold: the plan G1 tested")
    func unresolvedIsCold() {
        let plan = ReachPlan.make(
            addresses: Self.addresses, network: G1.network, devices: Self.history(cold: 0, warm: 40),
            policy: .default, now: G1.now
        )
        #expect(plan.warm == nil && plan.paths == nil)
        #expect(!plan.isWarm(Self.ip(12)))
        #expect(plan.isFirstScan(Self.ip(12)))
        #expect(plan.wait(for: Self.ip(12)) == .milliseconds(1_500))
    }

    @Test("Resolving keeps only probed addresses, and learned and fixed count no paths")
    func resolutionScope() {
        let outside = IPv4Address("10.10.20.5")!
        let plan = Self.plan(cold: 20, warm: 20, complete: [Self.ip(12), outside])
        #expect(plan.warm == [Self.ip(12)])
        for policy: SweepReach in [.learned, .fixed(.seconds(2))] {
            let other = ReachPlan.make(
                addresses: Self.addresses, network: G1.network, devices: Self.history(cold: 20, warm: 20),
                policy: policy, now: G1.now
            ).atSweepStart(addresses: Self.addresses, complete: [Self.ip(12)])
            #expect(other.paths == nil)
            #expect(other.path(for: Self.ip(12)) == nil)
            #expect(other.isWarm(Self.ip(12)))
        }
    }

    @Test("run.reach reports both percentiles, both counts and the paths")
    func reported() throws {
        let plan = Self.plan(cold: 20, warm: 20, complete: [Self.ip(12)])
        let report = ReachReport(plan: plan, found: [Self.ip(12)])
        #expect(report.expectedWaitMillis == 1_000)
        #expect(report.historySamples == 20)
        #expect(report.warmWaitMillis == 40)
        #expect(report.warmSamples == 20)
        #expect(report.paths == plan.paths)
        #expect(report.firstScan == false)

        // The keys the analysis reads, decoded independently of `ReachReport`.
        struct Wire: Decodable {
            var paths: [String: Int]
            var warm_wait_millis: Double
            var warm_samples: Int
        }
        let wire = try JSONDecoder().decode(Wire.self, from: JSONEncoder().encode(report))
        #expect(wire.paths == [
            "cold": 253, "warm": 1, "first_scan": 0, "cold_percentile": 1,
            "warm_percentile": 1, "learned_tail": 252,
        ])
        #expect(wire.warm_wait_millis == 40)
        #expect(wire.warm_samples == 20)
        #expect(try JSONDecoder().decode(ReachReport.self, from: JSONEncoder().encode(report)) == report)

        // first_scan is per address: a thin cold history with every address warm says
        // false, because nobody waited it.
        let warmOnly = Self.plan(cold: 0, warm: 0, complete: Set(Self.addresses))
        #expect(warmOnly.firstScan)
        #expect(ReachReport(plan: warmOnly, found: []).firstScan == false)
        #expect(ReachReport(plan: Self.plan(cold: 0, warm: 0, complete: []), found: []).firstScan)
    }
}
