import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// Fake engines, so the paths that need a hostile network can be tested without one.
// A denied Local Network permission cannot be arranged on demand, and a scan with a
// deliberately slow consumer cannot be arranged reliably against a real /24.

/// A discovery engine whose behaviour is dictated rather than measured.
nonisolated struct FakeDiscovery: HostDiscovery {
    var descriptor = EngineDescriptor(
        name: "fake", kind: .unprivileged, capabilities: [.icmpSweep, .arpSweep]
    )
    var hosts: [HostFacts] = []
    var degradations: [Degradation] = []
    var used: EngineCapabilities = [.icmpSweep, .arpSweep]
    var outcome: Outcome = .complete
    /// Events to emit through the progress sink. Deliberately allowed to differ from
    /// `hosts` — that difference is what the lossy-channel test turns on.
    var events: [ProbeEvent] = []

    func discover(
        _ target: ScanTarget, deadline: Deadline, progress: ProgressSink
    ) async -> DiscoveryResult {
        for event in events { progress(event) }
        return DiscoveryResult(
            hosts: hosts, degradations: degradations, usedCapabilities: used,
            outcome: outcome,
            timing: Timing(
                stages: [StageTiming(stage: .discovery, elapsedMillis: 12,
                                     probesSent: 254, repliesSeen: hosts.count)],
                counters: ProbeCounterSnapshot(probesSent: 254, repliesSeen: hosts.count,
                                               peakConcurrency: 64, inFlight: 0))
        )
    }

    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent> {
        AsyncStream { continuation in
            for event in events { continuation.yield(event) }
            continuation.finish()
        }
    }
}

nonisolated struct FakePorts: PortScanning {
    var descriptor = EngineDescriptor(name: "fake-ports", kind: .unprivileged, capabilities: [.connectScan])
    /// What the fake reports. Empty by default, as it always was; the artifact gate
    /// dictates one so `--deep` has something to put in the report.
    var result = PortScanResult()
    func scan(_ targets: [IPv4Address], ports: PortSpec, perHostDeadline: Duration,
              deadline: Deadline, progress: ProgressSink) async -> PortScanResult {
        result
    }
    func stream(_ targets: [IPv4Address], ports: PortSpec, perHostDeadline: Duration,
                deadline: Deadline) -> AsyncStream<ProbeEvent> {
        AsyncStream { $0.finish() }
    }
}

/// A naming stage whose answers are dictated. Naming against a real network is a
/// property of the room the machine is in, which is not a thing a test can assert on.
nonisolated struct FakeNaming: NameResolving {
    var descriptor = EngineDescriptor(name: "fake-naming", kind: .unprivileged, capabilities: [])
    var names: [IPv4Address: [NameCandidate]] = [:]
    var hardware: [IPv4Address: MACAddress] = [:]
    var degradations: [Degradation] = []
    var outcome: Outcome = .complete

    func resolveNames(
        for addresses: [IPv4Address], on target: ScanTarget,
        deadline: Deadline, progress: ProgressSink
    ) async -> NameResolution {
        NameResolution(
            names: names, hardware: hardware, degradations: degradations, outcome: outcome,
            timing: StageTiming(stage: .naming, elapsedMillis: 7,
                                probesSent: 2, repliesSeen: names.count,
                                hostsFound: names.count)
        )
    }
}

nonisolated struct FakeInterfaces: InterfaceProvider {
    func interfaces() throws(PlatformError) -> [NetworkInterface] { [Self.en0] }
    func primaryInterface() throws(PlatformError) -> NetworkInterface { Self.en0 }
    static let en0 = NetworkInterface(
        name: "en0", address: IPv4Address("10.10.20.8")!,
        network: IPv4Network("10.10.20.0/24")!,
        hardwareAddress: MACAddress("52:A1:8A:E0:7A:8A")
    )
}

/// A renderer that records what it was handed and drops progress events on the floor,
/// standing in for a consumer too slow to keep up.
nonisolated final class RecordingRenderer: Renderer, @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [ProbeEvent] = []
    private var finished: ScanReport?
    var events: [ProbeEvent] { lock.withLock { seen } }
    var report: ScanReport? { lock.withLock { finished } }
    func handle(_ event: ProbeEvent) { lock.withLock { seen.append(event) } }
    func finish(_ report: ScanReport) { lock.withLock { finished = report } }
}

private func pipeline(
    _ discovery: FakeDiscovery,
    renderer: any Renderer,
    naming: FakeNaming = FakeNaming(),
    discoveryOnly: Bool = false
) -> ScanPipeline {
    ScanPipeline(
        scanner: PlatformScanner(
            interfaces: FakeInterfaces(), discovery: discovery, ports: FakePorts(), udpPorts: FakePorts(), ipv6Neighbors: NoIPv6Neighbors(),
            naming: naming,
            descriptorLimit: 92_160, concurrency: 512, notices: []
        ),
        renderer: renderer, discoveryOnly: discoveryOnly, deep: false,
        ports: .commonServices
    )
}

/// A naming stage that records whether it was ever asked anything.
///
/// The point of `--discovery-only` is not that the naming stage returns nothing, it is
/// that it never runs. A fake returning an empty resolution would pass a test that only
/// looked at the artifact while the three protocols were still on the wire.
nonisolated final class ObservingNaming: NameResolving, @unchecked Sendable {
    let descriptor = EngineDescriptor(name: "observing-naming", kind: .unprivileged,
                                      capabilities: [])
    private let lock = NSLock()
    private var calls = 0
    var callCount: Int { lock.withLock { calls } }

    func resolveNames(
        for addresses: [IPv4Address], on target: ScanTarget,
        deadline: Deadline, progress: ProgressSink
    ) async -> NameResolution {
        lock.withLock { calls += 1 }
        return NameResolution(
            names: [:], hardware: [:], degradations: [], outcome: .complete,
            timing: StageTiming(stage: .naming, elapsedMillis: 7)
        )
    }
}

private func pipeline(
    _ discovery: FakeDiscovery,
    renderer: any Renderer,
    observing: ObservingNaming,
    discoveryOnly: Bool
) -> ScanPipeline {
    ScanPipeline(
        scanner: PlatformScanner(
            interfaces: FakeInterfaces(), discovery: discovery, ports: FakePorts(), udpPorts: FakePorts(), ipv6Neighbors: NoIPv6Neighbors(),
            naming: observing,
            descriptorLimit: 92_160, concurrency: 512, notices: []
        ),
        renderer: renderer, discoveryOnly: discoveryOnly, deep: false,
        ports: .commonServices
    )
}

private let target = ScanTarget(scanning: FakeInterfaces.en0)

@Suite("The artifact never comes from the lossy channel")
struct ArtifactSourceTests {
    @Test("Devices missing from the progress stream are still in the report")
    func droppedEventsDoNotLoseDevices() async throws {
        // The exact failure this restructure exists to prevent. The engine finds three
        // hosts and reports ONE through the progress sink — which is what a
        // `.bufferingNewest` channel does to a consumer that fell behind. A report
        // assembled from the events the display saw would list one device and still say
        // `outcome: complete`.
        let hosts = ["10.10.20.1", "10.10.20.2", "10.10.20.3"].map {
            HostFacts(ip: IPv4Address($0)!)
        }
        let engine = FakeDiscovery(hosts: hosts, events: [.hostFound(hosts[0])])
        let renderer = RecordingRenderer()
        let completed = await pipeline(engine, renderer: renderer).run(
            target: target, budget: .seconds(5)
        )
        #expect(renderer.events.filter { if case .hostFound = $0 { true } else { false } }.count == 1)
        #expect(completed.report.devices.count == 3)
        #expect(completed.report.run.outcome == .complete)
    }

    @Test("Degradations reach the report even when the display never saw them")
    func droppedEventsDoNotLoseDegradations() async {
        let degradation = Degradation(stage: .discovery, reason: "ARP unreadable.", recoverable: true)
        // Returned in the envelope, emitted through the sink not at all.
        let engine = FakeDiscovery(degradations: [degradation], events: [])
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.report.degradations == [degradation])
    }

    @Test("Stage timings come from the envelope, not from events")
    func timingComesFromTheEnvelope() async {
        let engine = FakeDiscovery(hosts: [HostFacts(ip: IPv4Address("10.10.20.1")!)], events: [])
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        // Per stage, because a named host means the naming stage ran and contributed
        // its own row and its own counts. The claim under test is that the DISCOVERY
        // numbers came from the returned envelope rather than from the events the
        // display happened to see, and that survives another stage joining the report.
        let discovery = completed.report.run.timing.stages.first { $0.stage == .discovery }
        #expect(discovery?.probesSent == 254)
        #expect(completed.report.run.timing.stages.map(\.stage) == [.discovery, .naming])
        // Measured, not restated from the configured window.
        #expect(completed.report.run.timing.peakConcurrency == 64)
    }
}

@Suite("Exit status is derived from degradations too")
struct DenialExitTests {
    @Test("A denied Local Network permission exits 69, not 0")
    func denialIsUnavailable() async {
        // The whole point of exit 69, and it was unreachable at runtime: the engine
        // detected the denial, the CLI wrote it into the report, and then chose the
        // exit code from the termination reason alone — so a denied permission was
        // indistinguishable from an empty network to any script.
        let denial = LocalNetworkDenialHeuristic.evaluate(
            repliesSeen: 0, probesSent: 254, neighborEntries: 6, advice: .appleLocalNetwork
        )
        let engine = FakeDiscovery(
            // The ARP cache still yields hosts, so the device list is NOT empty —
            // which is exactly why "zero devices" cannot be the signal.
            hosts: [HostFacts(ip: IPv4Address("10.10.20.1")!, mac: MACAddress("78:20:51:74:CB:28"))],
            degradations: [denial!],
            used: [.arpSweep],
            outcome: .complete
        )
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.status == .unavailable)
        #expect(completed.status.rawValue == 69)
        #expect(!completed.report.devices.isEmpty)
    }

    @Test("A capability the engine did not exercise is reported as not exercised")
    func usedCapabilitiesAreHonest() async {
        let engine = FakeDiscovery(used: [.arpSweep])
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.report.run.engine.capabilities == [.arpSweep])
        #expect(!completed.report.run.engine.capabilities.contains(.icmpSweep))
    }

    @Test("A recoverable degradation does not change the exit status")
    func recoverableDegradationsAreNotFailures() async {
        let engine = FakeDiscovery(
            degradations: [Degradation(stage: .naming, reason: "mDNS is phase three.", recoverable: true)]
        )
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.status == .ok)
    }

    @Test("An expired deadline still exits zero, degradation or not")
    func partialStillExitsZero() async {
        let engine = FakeDiscovery(outcome: .deadlineExpired)
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.report.run.outcome == .deadlineExpired)
        #expect(completed.status == .ok)
    }
}


@Suite("Naming joins onto the device list")
struct NamingStageTests {
    /// The reference network's Apple TV: one device, two service types, two spellings.
    private static let clean = NameCandidate(
        value: "Sala de entretenimiento", source: .mdns, rank: 1, model: "AppleTV5,3"
    )
    private static let prefixed = NameCandidate(
        value: "70-35-60-63.1 Sala de entretenimiento", source: .mdns, rank: 16
    )

    @Test("The winner is shown and every loser is kept")
    func losersSurvive() async throws {
        let ip = IPv4Address("10.10.20.2")!
        let engine = FakeDiscovery(hosts: [HostFacts(ip: ip)])
        let naming = FakeNaming(names: [ip: [Self.prefixed, Self.clean]])
        let completed = await pipeline(engine, renderer: RecordingRenderer(), naming: naming).run(
            target: target, budget: .seconds(5)
        )
        let device = try #require(completed.report.devices.first)
        #expect(device.displayName == "Sala de entretenimiento")
        // The whole "Known by" panel is built from the losers. A pipeline that kept only
        // the winner would pass every test of the winning name and destroy the feature.
        #expect(device.names.count == 2)
        #expect(device.names.contains(Self.prefixed))
    }

    @Test("A host only a name source saw is added rather than dropped")
    func nameSourceCanFindAHost() async {
        // The sweep hears nothing from .12; Bonjour resolves an address record for it.
        // That is positive evidence of a device, and discarding it for the sake of tidy
        // stage boundaries would report the network as emptier than it is.
        let silent = IPv4Address("10.10.20.12")!
        let engine = FakeDiscovery(hosts: [HostFacts(ip: IPv4Address("10.10.20.2")!)])
        let naming = FakeNaming(names: [silent: [NameCandidate(value: "Hue Bridge", source: .mdns, rank: 9)]])
        let completed = await pipeline(engine, renderer: RecordingRenderer(), naming: naming).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.report.devices.count == 2)
        #expect(completed.report.devices.first { $0.primaryAddress == .v4(silent) }?.displayName == "Hue Bridge")
    }

    @Test("A name for an address outside the target is not smuggled into the report")
    func offNetworkNamesAreIgnored() async {
        let engine = FakeDiscovery(hosts: [HostFacts(ip: IPv4Address("10.10.20.2")!)])
        // A VPN-side or loopback sighting that survived the remap has no row to join and
        // must not create one: the report is about one network.
        let naming = FakeNaming(names: [
            IPv4Address("192.168.4.9")!: [NameCandidate(value: "Somewhere else", source: .ssdp)],
        ])
        let completed = await pipeline(engine, renderer: RecordingRenderer(), naming: naming).run(
            target: target, budget: .seconds(5)
        )
        #expect(completed.report.devices.count == 1)
    }

    @Test("A naming degradation reaches the artifact and sets the exit status")
    func namingDegradationSurfaces() async {
        let denial = Degradation(
            stage: .naming,
            reason: "No device answered Bonjour, UPnP or NetBIOS, so no names could be read this scan.",
            recoverable: false
        )
        let engine = FakeDiscovery(hosts: [HostFacts(ip: IPv4Address("10.10.20.2")!)])
        let completed = await pipeline(
            engine, renderer: RecordingRenderer(), naming: FakeNaming(degradations: [denial])
        ).run(target: target, budget: .seconds(5))
        #expect(completed.report.degradations.contains(denial))
        #expect(completed.status == .unavailable)
    }

    @Test("The naming stage's timing is in the artifact, under its own wire keys")
    func namingTimingIsReported() async throws {
        let engine = FakeDiscovery(hosts: [HostFacts(ip: IPv4Address("10.10.20.2")!)])
        let completed = await pipeline(engine, renderer: RecordingRenderer()).run(
            target: target, budget: .seconds(5)
        )
        let naming = try #require(completed.report.run.timing.stages.first { $0.stage == .naming })
        // The naming budgets must NOT arrive under the sweep's retransmit and tail keys.
        // One wire key with two meanings would make a consumer decode a number correctly
        // and read it wrongly, which is worse than not carrying it at all.
        #expect(naming.retransmitBudgetMillis == nil)
        #expect(naming.tailBudgetMillis == nil)
        let encoded = try JSONEncoder().encode(naming)
        let json = try #require(
            try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        #expect(json["retransmit_budget_millis"] == nil)
    }
}


/// `Study/PHASE0.md` 0.2. Without a discovery-only mode every timing comparison in the
/// study measures zhen running four protocols against `nmap -sn` running one, so
/// the flag is a prerequisite of the measurement rather than a finding of it.
@Suite("Discovery-only mode")
struct DiscoveryOnlyTests {
    private static let hosts = [
        HostFacts(ip: IPv4Address("10.10.20.4")!),
        HostFacts(ip: IPv4Address("10.10.20.5")!),
    ]

    private func run(discoveryOnly: Bool) async -> (ScanReport, Int) {
        let naming = ObservingNaming()
        let scan = pipeline(FakeDiscovery(hosts: Self.hosts),
                            renderer: RecordingRenderer(),
                            observing: naming, discoveryOnly: discoveryOnly)
        let done = await scan.run(target: target, budget: .seconds(5))
        return (done.report, naming.callCount)
    }

    @Test("The naming stage is absent from the artifact, not present and empty")
    func namingStageIsAbsent() async {
        let (report, _) = await run(discoveryOnly: true)
        #expect(!report.run.timing.stages.contains { $0.stage == .naming },
                "a stage that never ran must not appear at all")
        #expect(report.run.timing.stages.contains { $0.stage == .discovery })
        #expect(report.devices.count == 2, "discovery still reports what it found")
    }

    @Test("The naming protocols are never started")
    func namingIsNotRun() async {
        // The artifact could look right while mDNS, SSDP and NetBIOS were still on the
        // wire, which would leave the timing comparison exactly as broken as before.
        let (_, calls) = await run(discoveryOnly: true)
        #expect(calls == 0)
    }

    @Test("The default is unchanged: naming runs and its stage is present")
    func defaultBehaviourIsUnchanged() async {
        let (report, calls) = await run(discoveryOnly: false)
        #expect(calls == 1)
        #expect(report.run.timing.stages.contains { $0.stage == .naming })
        #expect(report.run.mode == .full)
    }

    @Test("The run metadata names the mode, so one artifact is self-describing")
    func modeIsRecordedInRunMetadata() async {
        let (only, _) = await run(discoveryOnly: true)
        let (full, _) = await run(discoveryOnly: false)
        #expect(only.run.mode == .discoveryOnly)
        #expect(full.run.mode == .full)
    }

    @Test("Both modes round-trip through the decoder unchanged")
    func bothModesRoundTrip() async throws {
        for discoveryOnly in [true, false] {
            let (report, _) = await run(discoveryOnly: discoveryOnly)
            let encoded = try report.encoded()
            let decoded = try ScanReport.makeDecoder().decode(ScanReport.self, from: encoded)
            try decoded.validateSchema()
            #expect(decoded == report)
            #expect(decoded.run.mode == report.run.mode)
            let decodedStages: [Stage] = decoded.run.timing.stages.map { $0.stage }
            let originalStages: [Stage] = report.run.timing.stages.map { $0.stage }
            #expect(decodedStages == originalStages)
        }
    }

    @Test("The mode reaches the wire under a key of its own")
    func modeIsOnTheWire() async throws {
        let (report, _) = await run(discoveryOnly: true)
        let json = try JSONSerialization.jsonObject(
            with: try report.encoded()) as? [String: Any]
        let run = json?["run"] as? [String: Any]
        #expect(run?["mode"] as? String == "discovery_only")
        let stages = (run?["timing"] as? [String: Any])?["stages"] as? [[String: Any]]
        #expect(stages?.contains { $0["stage"] as? String == "naming" } == false)
    }

    @Test("A document written before the mode existed still decodes, as full")
    func documentsWithoutTheModeKeyDecodeAsFull() async throws {
        // The field is additive, and this is the test that makes that claim true rather
        // than asserted. A synthesized decoder would have refused these documents and
        // turned an additive change into a breaking one — see the reasoning at
        // `ScanReport.schemaVersion`.
        let (report, _) = await run(discoveryOnly: false)
        var json = try JSONSerialization.jsonObject(
            with: try report.encoded()) as! [String: Any]
        var run = json["run"] as! [String: Any]
        run.removeValue(forKey: "mode")
        json["run"] = run
        let stripped = try JSONSerialization.data(withJSONObject: json)
        let decoded = try ScanReport.makeDecoder().decode(ScanReport.self, from: stripped)
        try decoded.validateSchema()
        #expect(decoded.run.mode == .full)
        #expect(decoded.schema == ScanReport.schemaVersion)
    }

    @Test("Exit status is unaffected by the mode")
    func exitStatusIsUnaffected() async {
        let naming = ObservingNaming()
        for discoveryOnly in [true, false] {
            let scan = pipeline(FakeDiscovery(hosts: Self.hosts),
                                renderer: RecordingRenderer(),
                                observing: naming, discoveryOnly: discoveryOnly)
            let done = await scan.run(target: target, budget: .seconds(5))
            #expect(done.status == .ok)
        }
        // And a failure is still a failure in both modes.
        let denial = Degradation(
            stage: .discovery,
            reason: "The system denied access to the local network.",
            recoverable: false
        )
        for discoveryOnly in [true, false] {
            let scan = pipeline(
                FakeDiscovery(hosts: [], degradations: [denial], used: []),
                renderer: RecordingRenderer(),
                observing: ObservingNaming(), discoveryOnly: discoveryOnly)
            let done = await scan.run(target: target, budget: .seconds(5))
            #expect(done.status != .ok, "a fatal degradation must still fail")
        }
    }
}

@Suite("A stage that was asked for and did not run says so")
struct SkippedDeepScanTests {
    /// Raised at stage 2 and closed now.
    ///
    /// `ScanPipeline` guards the deep stage with `outcome == .complete`, so a partial
    /// discovery skipped port scanning entirely — no degradation, no stage entry, and
    /// nothing in the artifact saying the stage had been asked for and declined. Stage
    /// 2's port matrix made the silence visible for the first time: every cell became a
    /// dash with nothing explaining why.
    ///
    /// An empty `ports` array on every host is indistinguishable from a stage that ran
    /// and found nothing, which is the collapse `Ports.swift` spends its file header
    /// arguing against.
    @Test("A deep scan skipped by a partial discovery is reported, not silent")
    func skippedDeepScanIsReported() async {
        let pipeline = ScanPipeline(
            scanner: try! await PlatformScanner.make(concurrencyOverride: 1),
            renderer: SilentRenderer(),
            deep: true,
            ports: PortSpec([80]),
            history: nil)
        // A budget of nothing: discovery cannot finish, so the deep stage is skipped by
        // the guard rather than by choice.
        let completed = await pipeline.run(
            target: ScanTarget(network: IPv4Network("10.10.20.0/30")!,
                               interface: NetworkInterface(
                                   name: "lo0", address: IPv4Address("127.0.0.1")!,
                                   network: IPv4Network("127.0.0.0/8")!,
                                   hardwareAddress: nil)),
            budget: .milliseconds(1))

        let skipped = completed.report.degradations.first { $0.stage == .deepScan }
        #expect(skipped != nil,
                Comment(rawValue: "the deep stage was skipped in silence. Degradations: "
                        + "\(completed.report.degradations.map(\.reason))"))
        #expect(skipped?.reason.contains("not scanned") == true,
                Comment(rawValue: "the reason does not say ports were not scanned: "
                        + "\(skipped?.reason ?? "")"))
        // It has to say WHY, because "not attempted" and "nothing answered" are
        // different facts and the artifact has to keep them apart.
        #expect(skipped?.reason.contains("not because nothing answered") == true,
                Comment(rawValue: "the reason does not distinguish absence from silence: "
                        + "\(skipped?.reason ?? "")"))
    }

    @Test("A run that never asked for ports is not told they are missing")
    func withoutDeepThereIsNoComplaint() async {
        let pipeline = ScanPipeline(
            scanner: try! await PlatformScanner.make(concurrencyOverride: 1),
            renderer: SilentRenderer(),
            deep: false,
            ports: PortSpec([80]),
            history: nil)
        let completed = await pipeline.run(
            target: ScanTarget(network: IPv4Network("10.10.20.0/30")!,
                               interface: NetworkInterface(
                                   name: "lo0", address: IPv4Address("127.0.0.1")!,
                                   network: IPv4Network("127.0.0.0/8")!,
                                   hardwareAddress: nil)),
            budget: .milliseconds(1))
        #expect(!completed.report.degradations.contains { $0.stage == .deepScan },
                "a scan that did not ask for ports was told they were not scanned")
    }
}

/// Swallows everything. The pipeline needs a renderer and these tests are about the
/// artifact.
private struct SilentRenderer: Renderer {
    func handle(_ event: ProbeEvent) {}
    func finish(_ report: ScanReport) {}
}

/// An IPv6 neighbour cache with nothing in it — every pipeline test that predates D3.
struct NoIPv6Neighbors: IPv6NeighborCache {
    func ipv6Entries() async throws(PlatformError) -> [IPv6NeighborEntry] { [] }
}

/// A fixed IPv6 neighbour cache.
struct FixedIPv6Neighbors: IPv6NeighborCache {
    var entries: [IPv6NeighborEntry]
    func ipv6Entries() async throws(PlatformError) -> [IPv6NeighborEntry] { entries }
}

@Suite("D3: the IPv6 neighbour cache is a discovery source, and says so")
struct IPv6NeighborStageTests {
    private func entry(_ address: String, _ mac: String, permanent: Bool = false) -> IPv6NeighborEntry {
        IPv6NeighborEntry(address: IPv6Address(address)!, mac: MACAddress(mac)!, isPermanent: permanent)
    }

    private func scan(_ cache: FixedIPv6Neighbors) async -> ScanReport? {
        var discovery = FakeDiscovery()
        // One v4 host that answered. Nothing else answered anything.
        discovery.hosts = [HostFacts(ip: IPv4Address("10.10.20.1")!, mac: MACAddress("78:20:51:74:CB:28"),
                                     discoveredVia: [.probeReply])]
        let renderer = RecordingRenderer()
        let scan = ScanPipeline(
            scanner: PlatformScanner(
                interfaces: FakeInterfaces(), discovery: discovery, ports: FakePorts(),
                udpPorts: FakePorts(), ipv6Neighbors: cache, naming: FakeNaming(),
                descriptorLimit: 92_160, concurrency: 512, notices: []),
            renderer: renderer, discoveryOnly: true, deep: false, ports: .commonServices)
        let done = await scan.run(target: ScanTarget(scanning: FakeInterfaces.en0), budget: .seconds(5))
        return done.report
    }

    @Test("A host only the cache knows is reported, with the cache as its only source")
    func cacheOnlyHostIsReported() async throws {
        let report = try #require(await scan(FixedIPv6Neighbors(entries: [
            entry("fe80::4d0:baf6:1770:5849%en0", "9E:BA:51:6A:82:9B"),
        ])))
        let silent = try #require(report.devices.first { $0.mac == MACAddress("9E:BA:51:6A:82:9B") })
        #expect(silent.addresses == [IPAddress("fe80::4d0:baf6:1770:5849%en0")!])
        #expect(silent.discoveredVia == [.neighborTable])
        #expect(silent.identification == .minimal)
        #expect(report.devices.count == 2)
    }

    @Test("A cache entry sharing a MAC with a v4 host becomes that host's second address")
    func sameMACFuses() async throws {
        let report = try #require(await scan(FixedIPv6Neighbors(entries: [
            entry("fe80::7a20:51ff:fe74:cb28%en0", "78:20:51:74:CB:28"),
        ])))
        #expect(report.devices.count == 1)
        let gateway = try #require(report.devices.first)
        #expect(gateway.addresses == [IPAddress("10.10.20.1")!, IPAddress("fe80::7a20:51ff:fe74:cb28%en0")!])
        #expect(gateway.discoveredVia == [.probeReply, .neighborTable])
    }

    @Test("This machine's own addresses and other interfaces' neighbours are not reported")
    func ownAndForeignAreExcluded() async throws {
        let report = try #require(await scan(FixedIPv6Neighbors(entries: [
            entry("fe80::10fe:8abd:76f3:5a11%en0", "D6:0A:97:FE:72:9C", permanent: true),
            entry("fe80::8c97:23ff:fe36:6cec%awdl0", "8E:97:23:36:6C:EC"),
        ])))
        #expect(report.devices.count == 1, "only the v4 host")
    }
}
