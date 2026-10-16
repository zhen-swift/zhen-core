import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// The B1 gate: decomposing `ScanPipeline.run` must not change a single byte of what it
// produces.
//
// A live scan cannot be used for this. Its RTT column differs between runs, so a diff
// of two live runs measures the network rather than the refactor — which is the shape of
// mistake this project has made four times. The fakes below produce a fixed report from
// a fixed input, and the only field that is wall-clock by construction is normalised,
// named, and justified where it happens.

/// The hosts the fixture finds.
///
/// **Not empty, and the first version of this gate was.** An empty `FakeDiscovery`
/// produced `"devices":[]`, which made `--deep` skip the port stage by its own
/// `!facts.isEmpty` guard — so shallow and deep encoded identically and the gate would
/// have compared two empty reports before and after the refactor and passed. That is
/// the dead-baseline failure this project has made before, caught here by the
/// discriminator rather than by luck.
private func fixtureHosts() -> [HostFacts] {
    [
        HostFacts(
            ip: IPv4Address("10.10.20.1")!, mac: MACAddress("78:20:51:5E:07:28"),
            ttl: 64, rtt: RTTSample(measured: .microseconds(412)),
            discoveredVia: [.probeReply]),
        HostFacts(
            ip: IPv4Address("10.10.20.103")!, mac: MACAddress("C8:69:CD:5E:01:E1"),
            ttl: 64, rtt: RTTSample(measured: .microseconds(51_680)),
            discoveredVia: [.probeReply, .arpReply]),
        // A host the neighbour table knows and that answered nothing, so the artifact
        // carries both shapes.
        HostFacts(ip: IPv4Address("10.10.20.8")!, discoveredVia: [.neighborTable]),
    ]
}

/// Ports the fake scanner reports, so `--deep` has something to put in the artifact.
private func fixturePorts() -> [IPAddress: [PortObservation]] {
    [
        .v4(IPv4Address("10.10.20.1")!): [
            PortObservation(port: 22, proto: .tcp, state: .filtered),
            PortObservation(port: 80, proto: .tcp, state: .open,
                            service: ServiceIdentity(name: "http", product: "nginx",
                                                     version: "1.24", evidence: .banner),
                            rtt: RTTSample(measured: .microseconds(4_210))),
            PortObservation(port: 443, proto: .tcp, state: .closed),
        ],
        .v4(IPv4Address("10.10.20.103")!): [
            PortObservation(port: 22, proto: .tcp, state: .closed),
            PortObservation(port: 80, proto: .tcp, state: .filtered),
            PortObservation(port: 443, proto: .tcp, state: .filtered),
        ],
    ]
}

/// A deterministic run, encoded canonically.
@MainActor
func canonicalArtifact(deep: Bool, discoveryOnly: Bool = false) async -> String {
    var discovery = FakeDiscovery()
    discovery.hosts = fixtureHosts()
    var naming = FakeNaming()
    naming.names = [
        IPv4Address("10.10.20.103")!: [
            NameCandidate(value: "Sala de estar principal", source: .mdns),
        ],
    ]
    var ports = FakePorts()
    ports.result = PortScanResult(
        ports: fixturePorts(), fingerprints: [:], degradations: [],
        usedCapabilities: [.connectScan], outcome: .complete,
        timing: Timing(
            stages: [StageTiming(stage: .deepScan, elapsedMillis: 33,
                                 probesSent: 9, repliesSeen: 4)],
            counters: ProbeCounterSnapshot(probesSent: 9, repliesSeen: 4,
                                           peakConcurrency: 8, inFlight: 0)))

    let pipeline = ScanPipeline(
        scanner: PlatformScanner(
            interfaces: FakeInterfaces(), discovery: discovery, ports: ports, udpPorts: ports, ipv6Neighbors: NoIPv6Neighbors(),
            naming: naming,
            descriptorLimit: 92_160, concurrency: 512, notices: []),
        renderer: SilentGateRenderer(),
        discoveryOnly: discoveryOnly, deep: deep,
        ports: PortSpec([22, 80, 443]),
        history: nil,
        // Pinned: the real stamp changes with every commit. 0.8.0 added `run.tool`, and
        // with it these two bytes-for-bytes baselines (change 9, a deliberate change).
        tool: RunTool(name: "zhen", version: "0.0.0-gate", commit: "0000000000000000000000000000000000000000"))

    let completed = await pipeline.run(
        target: ScanTarget(
            network: IPv4Network("10.10.20.0/24")!,
            interface: NetworkInterface(
                name: "en0", address: IPv4Address("10.10.20.124")!,
                network: IPv4Network("10.10.20.0/24")!,
                hardwareAddress: MACAddress("D6:0A:97:5E:06:9C"))),
        budget: .seconds(20),
        startedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_000),
        runID: UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!)

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(completed.report)) ?? Data()
    var text = String(data: data, encoding: .utf8) ?? ""

    // ── The wall-clock fields, blanked by name ───────────────────────────────────
    //
    // Three fields cannot be pinned from outside `run`: `finished_at` is
    // `Timestamp.now`, and `last_seen` and `first_seen` derive from it for a host with
    // no history. Everything else — the run id, the start time, every stage timing,
    // every host, every port — comes from the fakes or from the arguments and is
    // compared byte for byte.
    //
    // **Blanked by name, never by pattern.** A regex over "any long number" would also
    // flatten `started_at`, the RTT samples and the probe counts, and a gate that
    // blanks the fields it is meant to be watching passes on anything. These three are
    // listed because each one was shown to vary between two immediately consecutive
    // runs of the same fixture; `theFixtureIsStable` is what would fail if a fourth
    // appeared.
    for field in ["finished_at", "last_seen", "first_seen"] {
        text = text.replacingOccurrences(
            of: "\"\(field)\":[0-9]+", with: "\"\(field)\":0",
            options: .regularExpression)
    }
    // And the rate, which is probes over that elapsed time.
    text = text.replacingOccurrences(
        of: "\"effective_probes_per_second\":[0-9.e+-]+",
        with: "\"effective_probes_per_second\":0", options: .regularExpression)
    return text
}

nonisolated final class SilentGateRenderer: Renderer {
    func handle(_ event: ProbeEvent) {}
    func finish(_ report: ScanReport) {}
}

@Suite("Decomposing the pipeline changes no byte of the artifact")
@MainActor
struct PipelineArtifactGateTests {
    @Test("capture", .enabled(if: ProcessInfo.processInfo.environment["ZHEN_CAPTURE_BASELINE"] != nil))
    func captureBaselines() async {
        print("SHALLOW>>>" + (await canonicalArtifact(deep: false)) + "<<<")
        print("DEEP>>>" + (await canonicalArtifact(deep: true)) + "<<<")
    }

    @Test("The fixture is deterministic, or this gate measures nothing")
    func theFixtureIsStable() async {
        // Run first, before trusting any comparison against it. A fixture that varies
        // makes the gate fail for reasons that have nothing to do with the refactor —
        // and a fixture that is CONSTANT for the wrong reason, like an empty report,
        // makes it pass for nothing.
        let first = await canonicalArtifact(deep: false)
        let second = await canonicalArtifact(deep: false)
        #expect(first == second, "two identical runs produced different artifacts")
        #expect(first.contains("10.10.20.103"), "the fixture found no hosts")
        #expect(first.count > 1_000,
                Comment(rawValue: "the artifact is \(first.count) bytes, too small to be "
                        + "a real report — the gate would pass on nothing"))
    }

    @Test("A deep run differs from a shallow one, so the flag reaches the artifact")
    func deepIsDifferent() async {
        let shallow = await canonicalArtifact(deep: false)
        let deep = await canonicalArtifact(deep: true)
        #expect(shallow != deep,
                "--deep produced an identical artifact, so this gate cannot see the port stage")
    }

    /// **The gate itself.** Captured from `ScanPipeline.run` as it stood before B1
    /// decomposed it. The decomposition must not change a byte.
    ///
    /// Committed rather than regenerated: a baseline the refactor can rewrite is not a
    /// baseline. If these ever need updating, the change was a behaviour change and
    /// belongs in a commit that says so.
    @Test("A shallow run encodes exactly as it did before the decomposition")
    func shallowIsUnchanged() async {
        let produced = await canonicalArtifact(deep: false)
        #expect(produced == Self.shallowBaseline,
                Comment(rawValue: "the shallow artifact moved.\nproduced: \(produced)"))
    }

    @Test("A deep run encodes exactly as it did before the decomposition")
    func deepIsUnchanged() async {
        let produced = await canonicalArtifact(deep: true)
        #expect(produced == Self.deepBaseline,
                Comment(rawValue: "the deep artifact moved.\nproduced: \(produced)"))
    }

    @Test("The deep baseline actually contains the port stage")
    func theDeepBaselineIsNotHollow() {
        // The first version of this gate compared two EMPTY reports and passed. This is
        // what says the deep baseline has something in it that a broken port stage
        // would remove.
        #expect(Self.deepBaseline.contains("\"stage\":\"deep_scan\""),
                "the deep baseline has no port stage in it")
        #expect(Self.deepBaseline.contains("\"state\":\"open\""),
                "the deep baseline has no open port in it")
        #expect(Self.deepBaseline.contains("nginx"),
                "the deep baseline carries no service identity")
        #expect(Self.shallowBaseline != Self.deepBaseline)
    }

    static let shallowBaseline = #"{"degradations":[],"devices":[{"address_sources":[{"address":"10.10.20.1","discovered_via":["probe_reply"]}],"addresses":["10.10.20.1"],"discovered_via":["probe_reply"],"first_seen":0,"identification":"partial","identification_evidence":{"has_distinct_name":false,"has_model":false,"has_os_hint":true,"has_vendor":false,"independent_sources":0,"name_source_is_self_sufficient":false},"identity_stability":"strong","last_seen":0,"mac":"78:20:51:5E:07:28","names":[],"ports":[],"rtt":{"millis":0.412,"samples":1},"ttl":64},{"address_sources":[{"address":"10.10.20.8","discovered_via":["neighbor_table"]}],"addresses":["10.10.20.8"],"discovered_via":["neighbor_table"],"first_seen":0,"identification":"minimal","identification_evidence":{"has_distinct_name":false,"has_model":false,"has_os_hint":false,"has_vendor":false,"independent_sources":0,"name_source_is_self_sufficient":false},"identity_stability":"ephemeral","last_seen":0,"names":[],"ports":[]},{"address_sources":[{"address":"10.10.20.103","discovered_via":["probe_reply","arp_reply"]}],"addresses":["10.10.20.103"],"discovered_via":["probe_reply","arp_reply"],"first_seen":0,"identification":"identified","identification_evidence":{"has_distinct_name":true,"has_model":false,"has_os_hint":true,"has_vendor":false,"independent_sources":1,"name_source_is_self_sufficient":true},"identity_stability":"strong","last_seen":0,"mac":"C8:69:CD:5E:01:E1","names":[{"rank":0,"source":"mdns","value":"Sala de estar principal"}],"ports":[],"rtt":{"millis":51.68,"samples":1},"ttl":64}],"run":{"engine":{"capabilities":["arp_sweep","icmp_sweep"],"kind":"unprivileged","name":"fake"},"finished_at":0,"id":"3F2504E0-4F89-11D3-9A0C-0305E82C3301","interface":"en0","mode":"full","outcome":"complete","started_at":1756700000000,"target":"10.10.20.0\/24","timing":{"effective_probes_per_second":0,"peak_concurrency":64,"probes_sent":256,"replies_seen":4,"stages":[{"elapsed_millis":12,"probes_sent":254,"replies_seen":3,"stage":"discovery"},{"elapsed_millis":7,"hosts_found":1,"probes_sent":2,"replies_seen":1,"stage":"naming"}]},"tool":{"commit":"0000000000000000000000000000000000000000","name":"zhen","version":"0.0.0-gate"}},"schema":4}"#
    static let deepBaseline = #"{"degradations":[],"devices":[{"address_sources":[{"address":"10.10.20.1","discovered_via":["probe_reply"]}],"addresses":["10.10.20.1"],"discovered_via":["probe_reply"],"first_seen":0,"identification":"partial","identification_evidence":{"has_distinct_name":false,"has_model":false,"has_os_hint":true,"has_vendor":false,"independent_sources":0,"name_source_is_self_sufficient":false},"identity_stability":"strong","last_seen":0,"mac":"78:20:51:5E:07:28","names":[],"ports":[{"address":"10.10.20.1","port":22,"proto":"tcp","state":"filtered"},{"address":"10.10.20.1","port":80,"proto":"tcp","rtt":{"millis":4.21,"samples":1},"service":{"evidence":"banner","name":"http","product":"nginx","version":"1.24"},"state":"open"},{"address":"10.10.20.1","port":443,"proto":"tcp","state":"closed"}],"rtt":{"millis":0.412,"samples":1},"ttl":64},{"address_sources":[{"address":"10.10.20.8","discovered_via":["neighbor_table"]}],"addresses":["10.10.20.8"],"discovered_via":["neighbor_table"],"first_seen":0,"identification":"minimal","identification_evidence":{"has_distinct_name":false,"has_model":false,"has_os_hint":false,"has_vendor":false,"independent_sources":0,"name_source_is_self_sufficient":false},"identity_stability":"ephemeral","last_seen":0,"names":[],"ports":[]},{"address_sources":[{"address":"10.10.20.103","discovered_via":["probe_reply","arp_reply"]}],"addresses":["10.10.20.103"],"discovered_via":["probe_reply","arp_reply"],"first_seen":0,"identification":"identified","identification_evidence":{"has_distinct_name":true,"has_model":false,"has_os_hint":true,"has_vendor":false,"independent_sources":1,"name_source_is_self_sufficient":true},"identity_stability":"strong","last_seen":0,"mac":"C8:69:CD:5E:01:E1","names":[{"rank":0,"source":"mdns","value":"Sala de estar principal"}],"ports":[{"address":"10.10.20.103","port":22,"proto":"tcp","state":"closed"},{"address":"10.10.20.103","port":80,"proto":"tcp","state":"filtered"},{"address":"10.10.20.103","port":443,"proto":"tcp","state":"filtered"}],"rtt":{"millis":51.68,"samples":1},"ttl":64}],"run":{"engine":{"capabilities":["arp_sweep","icmp_sweep","connect_scan"],"kind":"unprivileged","name":"fake"},"finished_at":0,"id":"3F2504E0-4F89-11D3-9A0C-0305E82C3301","interface":"en0","mode":"full","outcome":"complete","started_at":1756700000000,"target":"10.10.20.0\/24","timing":{"effective_probes_per_second":0,"peak_concurrency":64,"probes_sent":265,"replies_seen":8,"stages":[{"elapsed_millis":12,"probes_sent":254,"replies_seen":3,"stage":"discovery"},{"elapsed_millis":7,"hosts_found":1,"probes_sent":2,"replies_seen":1,"stage":"naming"},{"elapsed_millis":33,"probes_sent":9,"replies_seen":4,"stage":"deep_scan"}]},"tool":{"commit":"0000000000000000000000000000000000000000","name":"zhen","version":"0.0.0-gate"}},"schema":4}"#
}
