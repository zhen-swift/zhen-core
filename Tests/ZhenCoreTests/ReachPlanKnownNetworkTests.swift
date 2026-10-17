// ReachPlanKnownNetworkTests.swift — gate R6 of the fixes brief's addendum (F7).
//
// The first-scan wait is for a network zhen doesn't know yet, and for expected addresses.
// On a known network, one whose history holds `minimumSamples` samples of either kind, an
// unexpected address with no neighbour entry takes the learned tail. That's Q15's machine:
// it scans often, its live hosts stay cached, it never gathers a cold sample, and its ~240
// dead addresses held every scan to 1.5 s. `--unexpected-cold first-scan` must give F1's
// rule back exactly, so the study can measure the alternative from the frozen binary.
// Portable, like G1 and R1: it runs on Linux.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Reach plan, a known network's unexpected cold addresses (R6)")
struct ReachPlanKnownNetworkTests {
    typealias G1 = ReachPlanTests
    typealias R1 = ReachPlanCacheStateTests
    static let addresses = G1.addresses
    static func ip(_ last: UInt8) -> IPv4Address { G1.ip(last) }
    static let f7 = ReachSettings()
    static let f1 = ReachSettings(unexpectedCold: .firstScan)

    /// `.12` and `.13` expected, with R1's samples between them.
    static func plan(
        cold: Int, warm: Int, complete: Set<IPv4Address>, settings: ReachSettings = f7
    ) -> ReachPlan {
        R1.plan(cold: cold, warm: warm, complete: complete, settings: settings)
    }

    /// F1's rule as it stood before F7, with F2 on top: the code `path(for:)` had at
    /// `eaae1d7`, kept here as the reference the flag must reproduce.
    static func f1Path(_ plan: ReachPlan, _ address: IPv4Address) -> ReachPath {
        if plan.isWarm(address) {
            return plan.expected.contains(address) ? .inherited : .learnedTail
        }
        if plan.firstScan { return .firstScan }
        guard plan.expected.contains(address), plan.expectedWait != nil else { return .learnedTail }
        return .coldPercentile
    }

    @Test("A known network with only warm samples: unexpected cold takes the tail, expected cold the first-scan wait")
    func knownWarmOnly() throws {
        // .12 is the sleeping phone: expected, nothing cached. .13 is expected and cached,
        // .1 cached and unexpected. Everything else is cold and unexpected: the dead addresses.
        let plan = Self.plan(cold: 0, warm: 20, complete: [Self.ip(13), Self.ip(1)])
        #expect(plan.knownNetwork)
        #expect(plan.firstScan, "the cold sample set is still empty")

        #expect(plan.path(for: Self.ip(12)) == .firstScan)
        #expect(plan.wait(for: Self.ip(12)) == .milliseconds(1_500))
        #expect(plan.attempts(for: Self.ip(12)) == 5)

        for dead in [Self.ip(2), Self.ip(200), Self.ip(254)] {
            #expect(plan.path(for: dead) == .learnedTail)
            #expect(!plan.isFirstScan(dead))
            #expect(plan.wait(for: dead) == .zero)
            #expect(plan.wait(for: dead, learnedTail: .milliseconds(250)) == .milliseconds(250))
            #expect(plan.attempts(for: dead) == 3)
        }
        #expect(plan.path(for: Self.ip(13)) == .inherited)
        #expect(plan.path(for: Self.ip(1)) == .learnedTail)
        #expect(plan.paths == ReachPathCounts(cold: 252, warm: 2, firstScan: 1, inherited: 1, learnedTail: 252))

        // Q15 itself: every live host cached and expected, so nothing waits 1.5 s at all.
        let warmLAN = Self.plan(cold: 0, warm: 20, complete: [Self.ip(12), Self.ip(13)])
        #expect(warmLAN.paths == ReachPathCounts(cold: 252, warm: 2, inherited: 2, learnedTail: 252))
        #expect(ReachReport(plan: warmLAN, found: []).firstScan == false)
    }

    @Test("An unknown network is unchanged: every cold address takes the first-scan wait, under either value")
    func unknownUnchanged() throws {
        for (cold, warm) in [(0, 0), (0, 19), (10, 9), (19, 0)] {
            for complete: Set<IPv4Address> in [[], [Self.ip(13)], [Self.ip(12), Self.ip(13), Self.ip(1)]] {
                let f7 = Self.plan(cold: cold, warm: warm, complete: complete)
                let f1 = Self.plan(cold: cold, warm: warm, complete: complete, settings: Self.f1)
                #expect(!f7.knownNetwork)
                for address in Self.addresses where !complete.contains(address) {
                    #expect(f7.path(for: address) == .firstScan, "\(cold) cold, \(warm) warm, \(address)")
                }
                for address in Self.addresses {
                    #expect(f7.path(for: address) == f1.path(for: address))
                    #expect(f7.wait(for: address) == f1.wait(for: address))
                    #expect(f7.attempts(for: address) == f1.attempts(for: address))
                }
                #expect(f7.paths == f1.paths)
            }
        }
    }

    @Test("Known means minimumSamples samples, cold and warm together")
    func knownBoundary() {
        for (cold, warm, known) in [(10, 10, true), (10, 9, false), (0, 20, true), (20, 0, true), (0, 19, false)] {
            #expect(Self.plan(cold: cold, warm: warm, complete: []).knownNetwork == known, "\(cold) cold, \(warm) warm")
        }
        // The same flag moves both: --reach-min-samples 5.
        var five = ReachSettings()
        five.minimumSamples = 5
        #expect(Self.plan(cold: 0, warm: 5, complete: [], settings: five).knownNetwork)
        #expect(!Self.plan(cold: 0, warm: 4, complete: [], settings: five).knownNetwork)
        // Reported under every policy: it's a fact about history, not about the wait.
        let learned = ReachPlan.make(
            addresses: Self.addresses, network: G1.network, devices: R1.history(cold: 0, warm: 20),
            policy: .learned, now: G1.now
        )
        #expect(learned.knownNetwork)
        #expect(learned.path(for: Self.ip(200)) == nil)
    }

    @Test("With enough cold samples F7 changes nothing")
    func enoughColdUnchanged() {
        for warm in [0, 20, 40] {
            let f7 = Self.plan(cold: 20, warm: warm, complete: [Self.ip(13)])
            let f1 = Self.plan(cold: 20, warm: warm, complete: [Self.ip(13)], settings: Self.f1)
            #expect(!f7.firstScan)
            for address in Self.addresses {
                #expect(f7.path(for: address) == f1.path(for: address))
            }
            #expect(f7.paths == f1.paths)
        }
    }

    @Test("--unexpected-cold first-scan reproduces F1 exactly; learned differs only on a known network's unexpected cold addresses")
    func flagReproducesF1() {
        let shapes = [0, 4, 10, 19, 20, 40]
        let completes: [Set<IPv4Address>] = [[], [Self.ip(12)], [Self.ip(13), Self.ip(1), Self.ip(77)], Set(Self.addresses)]
        var compared = 0
        var moved = 0
        for cold in shapes {
            for warm in shapes {
                for complete in completes {
                    let f1 = Self.plan(cold: cold, warm: warm, complete: complete, settings: Self.f1)
                    let f7 = Self.plan(cold: cold, warm: warm, complete: complete)
                    for address in Self.addresses {
                        let reference = Self.f1Path(f1, address)
                        #expect(f1.path(for: address) == reference)
                        let referenceWait: Duration = switch reference {
                        case .firstScan: .milliseconds(1_500)
                        case .coldPercentile: f1.expectedWait ?? .zero
                        case .inherited, .learnedTail: .zero
                        }
                        #expect(f1.wait(for: address) == referenceWait)

                        let shouldMove = f7.knownNetwork && reference == .firstScan && !f7.expected.contains(address)
                        #expect(f7.path(for: address) == (shouldMove ? .learnedTail : reference))
                        compared += 1
                        if shouldMove { moved += 1 }
                    }
                }
            }
        }
        #expect(compared == 6 * 6 * 4 * 254)
        #expect(moved > 0, "the grid must include the case F7 changes")
    }

    @Test("run.reach reports known_network and unexpected_cold, and an older artifact has neither")
    func reported() throws {
        let plan = Self.plan(cold: 0, warm: 20, complete: [Self.ip(12), Self.ip(13)])
        let object = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(ReachReport(plan: plan, found: []))) as? [String: Any]
        )
        #expect(object["known_network"] as? Bool == true)
        #expect(object["unexpected_cold"] as? String == "learned")

        let f1 = Self.plan(cold: 0, warm: 20, complete: [Self.ip(12), Self.ip(13)], settings: Self.f1)
        let report = ReachReport(plan: f1, found: [])
        #expect(report.unexpectedCold == "first-scan")
        #expect(report.firstScan)
        #expect(try JSONDecoder().decode(ReachReport.self, from: JSONEncoder().encode(report)) == report)

        let old = #"{"policy":"history","first_scan":true,"expected_count":0,"expected_missing":[]}"#
        let decoded = try JSONDecoder().decode(ReachReport.self, from: Data(old.utf8))
        #expect(decoded.knownNetwork == nil && decoded.unexpectedCold == nil)
    }
}
