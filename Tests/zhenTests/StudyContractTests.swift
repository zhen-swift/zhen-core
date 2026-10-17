// StudyContractTests.swift — change 9 of 0.8.0: every knob a flag, every number the
// study's analysis needs in the artifact. The fixture half of gate G9; the live half runs
// the real binary, once per row, and is in the ledger.

import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

@Suite("The study contract (G9, fixture)")
struct StudyContractTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static func ip(_ last: Int) -> IPv4Address { IPv4Address("10.10.20.\(last)")! }

    // ── Row 1: every constant overridable, and echoed whether flagged or not ─────

    @Test("Each constant has a flag, and the defaults are the brief's")
    func everyConstantIsAFlag() throws {
        let defaults = try Scan.parse([]).reachOptions.settings()
        #expect(defaults == ReachSettings())
        let flagged = try Scan.parse([
            "--first-scan-wait", "2s", "--reach-cap", "3500ms", "--reach-min-samples", "12",
            "--expected-attempts-step", "1s", "--expected-attempts-cap", "6",
            "--expected-window", "7d", "--unexpected-cold", "first-scan",
            "--reach-device-min-samples", "3",
        ]).reachOptions.settings()
        #expect(flagged.firstScanWait == .seconds(2))
        #expect(flagged.cap == .milliseconds(3_500))
        #expect(flagged.minimumSamples == 12)
        #expect(flagged.attemptsStep == .seconds(1))
        #expect(flagged.attemptsCap == 6)
        #expect(flagged.baseAttempts == 3)
        #expect(flagged.expectedWindow == .seconds(7 * 86_400))
        #expect(defaults.expectedWindow == .seconds(30 * 86_400))
        // F7's row: the default is the learned tail; the flag gives F1's rule back.
        #expect(flagged.unexpectedCold == .firstScan)
        #expect(defaults.unexpectedCold == .learned)
        #expect(try Scan.parse(["--unexpected-cold", "Learned"]).reachOptions.settings().unexpectedCold == .learned)
        // F11's row: a device's own samples before its percentile replaces its maximum.
        #expect(flagged.deviceMinimumSamples == 3)
        #expect(defaults.deviceMinimumSamples == 5)
    }

    @Test("A value that cannot be a setting is refused")
    func badSettings() {
        for arguments in [
            ["--first-scan-wait", "soon"], ["--first-scan-wait", "0ms"], ["--reach-cap", "-1s"],
            ["--reach-min-samples", "0"], ["--expected-attempts-step", "0s"],
            ["--expected-attempts-cap", "2"], ["--expected-window", "0d"],
            ["--expected-window", "a month"], ["--unexpected-cold", "sometimes"],
            ["--unexpected-cold", "first_scan"], ["--reach-device-min-samples", "0"],
        ] {
            var refused = false
            do { _ = try Scan.parse(arguments).reachOptions.settings() } catch { refused = true }
            #expect(refused, "accepted \(arguments)")
        }
    }

    @Test("run.reach echoes every value used, under the keys the analysis reads")
    func echo() throws {
        var settings = ReachSettings()
        settings.firstScanWait = .seconds(2)
        settings.minimumSamples = 12
        let plan = ReachPlan(policy: .history(percentile: 0.95), settings: settings, firstScan: true, historySamples: 7)
        let report = ReachReport(plan: plan, found: [], historyRead: true)
        let data = try JSONEncoder().encode(report)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["policy"] as? String == "history")
        #expect(object["percentile"] as? Double == 0.95)
        #expect(object["first_scan_wait_millis"] as? Double == 2_000)
        #expect(object["cap_millis"] as? Double == 5_000)
        #expect(object["min_samples"] as? Int == 12)
        #expect(object["attempts_step_millis"] as? Double == 500)
        #expect(object["attempts_cap"] as? Int == 8)
        #expect(object["base_attempts"] as? Int == 3)
        #expect(object["first_scan"] as? Bool == true)
        #expect(object["history_samples"] as? Int == 7)
        #expect(object["history_read"] as? Bool == true)
        // F3: the expected window, a row of its own in G9.
        #expect(object["expected_window_millis"] as? Double == 2_592_000_000)
        // F7: the rule for a known network's unexpected cold addresses, and whether it was known.
        #expect(object["unexpected_cold"] as? String == "learned")
        #expect(object["known_network"] as? Bool == false)
        // F11: the device rule's constant.
        #expect(object["device_min_samples"] as? Int == 5)
    }

    // ── Rows 3–6, through the pipeline ──────────────────────────────────────────

    private func scanner(_ discovery: any HostDiscovery) -> PlatformScanner {
        PlatformScanner(
            interfaces: FakeInterfaces(), discovery: discovery, ports: FakePorts(), udpPorts: FakePorts(),
            ipv6Neighbors: NoIPv6Neighbors(), naming: FakeNaming(),
            descriptorLimit: 92_160, concurrency: 512, notices: []
        )
    }

    @Test("--no-history: nothing read, nothing written, and the artifact says so")
    func noHistory() async throws {
        #expect(try Scan.parse(["--no-history"]).reachOptions.noHistory)
        var refused = false
        do { try Scan.parse(["--look-longer", "--no-history"]).checkLookLonger(policy: .default, network: nil) }
        catch { refused = true }
        #expect(refused, "--look-longer has nothing to extend without history")

        var target = ScanTarget(network: Self.network, interface: FakeInterfaces.en0)
        target.reach = ReachPlan.make(
            addresses: target.resolvedAddresses, network: Self.network, devices: [],
            policy: .default, now: .now
        )
        let completed = await ScanPipeline(
            scanner: scanner(TargetRecordingDiscovery(hosts: [HostFacts(ip: Self.ip(1))])),
            renderer: RecordingRenderer(), discoveryOnly: true, deep: false,
            ports: .commonServices, history: nil
        ).run(target: target, budget: .seconds(5))
        let reach = try #require(completed.report.run.reach)
        #expect(reach.historyRead == false)
        #expect(reach.firstScan == true)
        #expect(reach.historySamples == 0)
    }

    @Test("found_after_millis is per host, from the scan's start, and fuses to the earliest")
    func foundAfter() async throws {
        let start = MonotonicInstant.now
        let facts = HostFacts(ip: Self.ip(12), foundAt: start.advanced(by: .milliseconds(987)))
        let device = Device(observing: facts, in: Self.network, scanStart: start)
        #expect(device.foundAfterMillis == 987)
        #expect(Device(observing: facts, in: Self.network).foundAfterMillis == nil, "no start, no claim")
        let text = String(decoding: try JSONEncoder().encode(device), as: UTF8.self)
        #expect(text.contains(#""found_after_millis":987"#))
        // Two engines found it; the composite keeps the first.
        let other = HostFacts(ip: Self.ip(12), foundAt: start.advanced(by: .milliseconds(40)))
        #expect(facts.merged(with: other).foundAt == other.foundAt)

        // Through the pipeline: a host the engine timed carries it, measured from a start
        // the pipeline takes before discovery — so never negative, and never later than
        // the wall clock the run took.
        let completed = await ScanPipeline(
            scanner: scanner(TargetRecordingDiscovery(hosts: [HostFacts(ip: Self.ip(1), foundAt: .now)])),
            renderer: RecordingRenderer(), discoveryOnly: true, deep: false, ports: .commonServices
        ).run(target: ScanTarget(network: Self.network, interface: FakeInterfaces.en0), budget: .seconds(5))
        let found = try #require(completed.report.devices.first?.foundAfterMillis)
        #expect(found >= 0 && found < 5_000)
    }

    @Test("timing.stages carries attempts and concurrency")
    func attemptsAndConcurrency() throws {
        let stage = StageTiming(stage: .discovery, elapsedMillis: 367, attempts: 3, concurrency: 512)
        let text = String(decoding: try JSONEncoder().encode(stage), as: UTF8.self)
        #expect(text.contains(#""attempts":3"#) && text.contains(#""concurrency":512"#))
        #expect(try JSONDecoder().decode(StageTiming.self, from: Data(text.utf8)) == stage)
        // F9: what the sweep couldn't attribute, and what it attributed late, absent
        // where no echo was sent.
        #expect(!text.contains("stray_replies") && !text.contains("late_replies"))
        let swept = StageTiming(stage: .discovery, elapsedMillis: 505, strayReplies: 2, lateReplies: 1)
        let sweptText = String(decoding: try JSONEncoder().encode(swept), as: UTF8.self)
        #expect(sweptText.contains(#""stray_replies":2"#) && sweptText.contains(#""late_replies":1"#))
        #expect(try JSONDecoder().decode(StageTiming.self, from: Data(sweptText.utf8)) == swept)
    }

    // ── Row 8: the build ─────────────────────────────────────────────────────────

    @Test("run.tool names the build, and --version prints the commit")
    func tool() async throws {
        let completed = await ScanPipeline(
            scanner: scanner(TargetRecordingDiscovery(hosts: [])), renderer: RecordingRenderer(),
            discoveryOnly: true, deep: false, ports: .commonServices
        ).run(target: ScanTarget(network: Self.network, interface: FakeInterfaces.en0), budget: .seconds(5))
        let tool = try #require(completed.report.run.tool)
        #expect(tool.name == "zhen" && tool.version == ZhenVersion.current)
        #expect(tool.commit == Version.commit)
        // Built from this repository's checkout, the stamp is a real 40-hex commit.
        let commit = try #require(Version.commit, "the StampCommit plugin did not stamp this build")
        let hash = commit.hasSuffix("-dirty") ? String(commit.dropLast(6)) : commit
        #expect(hash.count == 40 && hash.allSatisfy(\.isHexDigit))
        #expect(Version.display == "\(ZhenVersion.current) (\(commit))")
        let text = String(decoding: try completed.report.encoded(), as: UTF8.self)
        #expect(text.contains(#""tool":{"commit":""#))
    }
}
