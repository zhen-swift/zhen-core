// ReachCLITests.swift — change 7 of 0.8.0: the reach flags, the plan reaching the sweep,
// and `zhen scan --look-longer` (the pipeline half of G7's fixture).

import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

/// A discovery engine that remembers the target it was handed.
nonisolated final class TargetRecordingDiscovery: HostDiscovery, @unchecked Sendable {
    let descriptor = EngineDescriptor(name: "fake", kind: .unprivileged, capabilities: [.icmpSweep])
    private let lock = NSLock()
    private var targets: [ScanTarget] = []
    let hosts: [HostFacts]

    init(hosts: [HostFacts]) { self.hosts = hosts }

    var seen: [ScanTarget] { lock.withLock { targets } }

    func discover(_ target: ScanTarget, deadline: Deadline, progress: ProgressSink) async -> DiscoveryResult {
        lock.withLock { targets.append(target) }
        return DiscoveryResult(
            hosts: hosts, usedCapabilities: [.icmpSweep],
            timing: Timing(stages: [StageTiming(stage: .discovery, elapsedMillis: 9)])
        )
    }

    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent> {
        AsyncStream { $0.finish() }
    }
}

@Suite("Reach on the command line")
struct ReachCLITests {
    static let network = IPv4Network("10.10.20.0/24")!
    static func ip(_ last: Int) -> IPv4Address { IPv4Address("10.10.20.\(last)")! }

    // ── The flags ────────────────────────────────────────────────────────────────

    @Test("No flag is history at P97; learned, a duration, and a percentile parse")
    func policies() throws {
        #expect(try Scan.parse([]).reachOptions.policy() == .history(percentile: 0.97))
        #expect(try Scan.parse(["--reach", "history"]).reachOptions.policy() == .history(percentile: 0.97))
        #expect(try Scan.parse(["--reach", "learned"]).reachOptions.policy() == .learned)
        #expect(try Scan.parse(["--reach", "3s"]).reachOptions.policy() == .fixed(.seconds(3)))
        #expect(try Scan.parse(["--reach-percentile", "0.9"]).reachOptions.policy() == .history(percentile: 0.9))
        #expect(try Scan.parse([]).reachOptions.noNeighborWatch == false)
        #expect(try Scan.parse(["--no-neighbor-watch"]).reachOptions.noNeighborWatch)
    }

    @Test("A percentile with anything but history, out of range, or a reach that is not one, is refused")
    func refusals() throws {
        for arguments in [
            ["--reach", "learned", "--reach-percentile", "0.9"],
            ["--reach", "2s", "--reach-percentile", "0.9"],
            ["--reach-percentile", "0"],
            ["--reach-percentile", "1.5"],
            ["--reach", "soon"],
            ["--reach", "0s"],
        ] {
            var refused = false
            do { _ = try Scan.parse(arguments).reachOptions.policy() } catch { refused = true }
            #expect(refused, "accepted \(arguments)")
        }
    }

    @Test("--look-longer takes a duration or nothing, and no --deep or --cidr")
    func lookLongerFlags() throws {
        try Scan.parse(["--look-longer"]).checkLookLonger(policy: .default, network: nil)
        try Scan.parse(["--look-longer", "--reach", "20s"]).checkLookLonger(policy: .fixed(.seconds(20)), network: nil)
        for (arguments, policy, network) in [
            (["--look-longer", "--deep"], SweepReach.default, IPv4Network?.none),
            (["--look-longer", "--reach", "learned"], .learned, nil),
            (["--look-longer", "--reach-percentile", "0.5"], .history(percentile: 0.5), nil),
            (["--look-longer"], .default, Self.network),
        ] {
            var refused = false
            do { try Scan.parse(arguments).checkLookLonger(policy: policy, network: network) } catch { refused = true }
            #expect(refused, "accepted \(arguments)")
        }
        #expect(Scan.lookLongerWait == .seconds(10))
    }

    // ── The plan reaches the sweep, and the report ──────────────────────────────

    private func scanner(_ discovery: any HostDiscovery) -> PlatformScanner {
        PlatformScanner(
            interfaces: FakeInterfaces(), discovery: discovery, ports: FakePorts(), udpPorts: FakePorts(),
            ipv6Neighbors: NoIPv6Neighbors(), naming: FakeNaming(),
            descriptorLimit: 92_160, concurrency: 512, notices: []
        )
    }

    @Test("The plan on the target is the plan the sweep gets, and run.reach reports it")
    func planReachesTheReport() async throws {
        let discovery = TargetRecordingDiscovery(hosts: [HostFacts(ip: Self.ip(1)), HostFacts(ip: Self.ip(12))])
        let renderer = RecordingRenderer()
        let plan = ReachPlan(
            policy: .default, expected: [Self.ip(1), Self.ip(12), Self.ip(13)],
            historySamples: 24, expectedWait: .milliseconds(1_034)
        )
        var target = ScanTarget(network: Self.network, interface: FakeInterfaces.en0)
        target.reach = plan
        let completed = await ScanPipeline(
            scanner: scanner(discovery), renderer: renderer, discoveryOnly: true, deep: false,
            ports: .commonServices
        ).run(target: target, budget: .seconds(5))
        #expect(discovery.seen.first?.reach == plan)
        let reach = try #require(completed.report.run.reach)
        #expect(reach.policy == "history" && reach.expectedCount == 3)
        #expect(reach.expectedMissing == [Self.ip(13)])
        #expect(completed.report.run.extendsRun == nil)
    }

    // ── --look-longer, through the pipeline (G7, fixture) ───────────────────────

    @Test("Look longer asks only the missing, extends the latest run, and marks nobody absent")
    func lookLongerExtends() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-look-longer-cli-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = LogHistoryStore(url: directory.appending(path: "history.ndjson"))

        // Two scans through the pipeline: the phone (.42) answers the first and not the
        // second, which therefore reports it in expected_missing.
        func host(_ last: Int) -> HostFacts {
            HostFacts(ip: Self.ip(last), mac: MACAddress(raw: 0x2000_0000_0000 | UInt64(last)), discoveredVia: [.probeReply])
        }
        for hosts in [[host(1), host(10), host(42)], [host(1), host(10)]] {
            var target = ScanTarget(network: Self.network, interface: FakeInterfaces.en0)
            target.reach = ReachPlan.make(
                addresses: target.resolvedAddresses, network: Self.network,
                devices: await store.devices(), policy: .default, now: .now
            )
            _ = await ScanPipeline(
                scanner: scanner(TargetRecordingDiscovery(hosts: hosts)), renderer: RecordingRenderer(),
                discoveryOnly: true, deep: false, ports: .commonServices, history: store
            ).run(target: target, budget: .seconds(5))
        }
        let latest = try #require(await store.latestRun())
        #expect(latest.reach?.expectedMissing == [Self.ip(42)])

        // The phone is back. The fake also reports .1 from the table, as the real sweep
        // reports table-only hosts anywhere in the network; it was not asked about.
        let discovery = TargetRecordingDiscovery(hosts: [host(42), host(1)])
        let renderer = RecordingRenderer()
        let completed = await ScanPipeline(
            scanner: scanner(discovery), renderer: renderer, discoveryOnly: true, deep: false,
            ports: .commonServices, history: store
        ).lookLonger(
            extending: latest, interface: FakeInterfaces.en0, wait: .seconds(10),
            settings: ReachSettings(), budget: .seconds(12)
        )

        let asked = try #require(discovery.seen.first)
        #expect(asked.addresses == [Self.ip(42)])
        #expect(asked.reach?.policy == .fixed(.seconds(10)))
        let report = completed.report
        #expect(report.devices.map(\.primaryAddress) == [.v4(Self.ip(42))])
        #expect(report.run.extendsRun == latest.id)
        #expect(report.run.id != latest.id)
        #expect(report.run.reach?.policy == "fixed" && report.run.reach?.expectedMissing == [])

        // History: the latest run is unchanged, the phone is present in it, nobody left.
        #expect(await store.latestRun()?.id == latest.id)
        let present = Set(await store.devices().filter(\.isPresent).map(\.device.primaryAddress))
        #expect(present == [.v4(Self.ip(1)), .v4(Self.ip(10)), .v4(Self.ip(42))])
        let kinds = await store.events().map(\.kind)
        #expect(kinds.filter { $0 == .appeared }.count == 1)
        #expect(kinds.filter { $0 == .disappeared }.count == 1, "only the second scan's, for the phone")
    }
}
