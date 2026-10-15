// ReachReportTests.swift — change 6 of 0.8.0: settling on the wire, and `run.reach`.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Settling and run.reach on the wire")
struct ReachReportTests {
    static let twelve = IPv4Address("10.10.20.12")!
    static let thirteen = IPv4Address("10.10.20.13")!

    @Test("settling is a tagged event with expected_missing")
    func settlingWire() throws {
        let event = ProbeEvent.settling(expectedMissing: [Self.twelve, Self.thirteen])
        let data = try JSONEncoder().encode(event)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["event"] as? String == "settling")
        #expect(object["expected_missing"] as? [String] == ["10.10.20.12", "10.10.20.13"])
        #expect(try JSONDecoder().decode(ProbeEvent.self, from: data) == event)
    }

    @Test("run.reach says the policy, the plan, and who was missing at the end")
    func reachFromPlan() throws {
        let plan = ReachPlan(
            policy: .default, expected: [Self.twelve, Self.thirteen, IPv4Address("10.10.20.1")!],
            historySamples: 24, expectedWait: .milliseconds(1_034)
        )
        let report = ReachReport(plan: plan, found: [IPv4Address("10.10.20.1")!, Self.thirteen])
        #expect(report.policy == "history")
        #expect(report.percentile == 0.97)
        #expect(report.firstScan == false)
        #expect(report.expectedCount == 3)
        #expect(report.expectedMissing == [Self.twelve])
        #expect(report.expectedWaitMillis == 1_034)

        let run = ScanRun(
            id: UUID(), startedAt: Timestamp(millisecondsSinceEpoch: 0), target: IPv4Network("10.10.20.0/24")!,
            interface: "en0", engine: EngineDescriptor(name: "t", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing(), reach: report
        )
        let text = String(decoding: try ScanReport(run: run, devices: []).encoded(), as: UTF8.self)
        for key in [#""policy":"history""#, #""percentile":0.97"#, #""first_scan":false"#,
                    #""expected_count":3"#, #""expected_missing":["10.10.20.12"]"#] {
            #expect(text.contains(key), "missing \(key)")
        }
        #expect(try ScanReport.decoded(from: Data(text.utf8)).run.reach == report)
    }

    @Test("learned and fixed say so, without a percentile")
    func otherPolicies() {
        let learned = ReachReport(plan: ReachPlan(policy: .learned), found: [])
        #expect(learned.policy == "learned" && learned.percentile == nil && learned.fixedWaitMillis == nil)
        let fixed = ReachReport(plan: ReachPlan(policy: .fixed(.seconds(10))), found: [])
        #expect(fixed.policy == "fixed" && fixed.fixedWaitMillis == 10_000)
    }

    @Test("A run written before 0.8.0 has no reach, and decodes")
    func absentReach() throws {
        let run = ScanRun(
            id: UUID(), startedAt: Timestamp(millisecondsSinceEpoch: 0), target: IPv4Network("10.10.20.0/24")!,
            interface: "en0", engine: EngineDescriptor(name: "t", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing()
        )
        let text = String(decoding: try ScanReport(run: run, devices: []).encoded(), as: UTF8.self)
        #expect(!text.contains(#""reach""#))
        #expect(try ScanReport.decoded(from: Data(text.utf8)).run.reach == nil)
    }
}
