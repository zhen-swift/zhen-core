import Foundation
import Testing
@testable import ZhenCore

// One suite per defect from the review. Each test names the failure it prevents
// rather than the code it touches, so a future change that reintroduces the bug fails
// with an explanation instead of a diff.

@Suite("A device can reproduce its own identity keys")
struct DeviceIdentityReproducibilityTests {
    static let network = IPv4Network("10.10.20.0/24")!

    @Test("A Device yields the same candidate keys as the HostFacts it came from")
    func deviceMatchesFacts() throws {
        let facts = HostFacts(
            ip: try #require(IPv4Address("10.10.20.4")),
            mac: try MACAddress.required("F2:3A:91:5E:0A:44"),
            allNames: [NameCandidate(value: "Mac Studio de Luis", source: .mdns, rank: 1)],
            reverseDNS: "mac-studio.lan",
            dhcpHostname: "mac-studio"
        )
        let device = Device(observing: facts, in: Self.network)

        let fromFacts = HostIdentifier.candidates(for: facts, in: Self.network)
        let fromDevice = HostIdentifier.candidates(for: device, in: Self.network)
        #expect(fromDevice == fromFacts)
        // Specifically: the weight-40 key the Device overload used to omit.
        #expect(fromDevice.contains { $0.kind == .dhcpHostname })
    }

    @Test("The key set survives a round trip through JSON")
    func keysSurviveEncoding() throws {
        let facts = HostFacts(
            ip: try #require(IPv4Address("10.10.20.4")),
            mac: try MACAddress.required("F2:3A:91:5E:0A:44"),
            allNames: [NameCandidate(value: "Mac Studio de Luis", source: .mdns, rank: 1)],
            reverseDNS: "mac-studio.lan",
            dhcpHostname: "mac-studio"
        )
        let device = Device(observing: facts, in: Self.network)
        let decoded = try ScanReport.makeDecoder().decode(
            Device.self, from: try ScanReport.makeEncoder().encode(device)
        )
        // The point of the whole fix: identityStability in a report has to be
        // recomputable from that report, or it is a number nobody downstream can check.
        #expect(HostIdentifier.candidates(for: decoded, in: Self.network)
                == HostIdentifier.candidates(for: facts, in: Self.network))
        #expect(Stability(strongestOf: HostIdentifier.candidates(for: decoded, in: Self.network))
                == decoded.identityStability)
    }

    @Test("A lease-named device survives MAC rotation instead of vanishing and returning")
    func leaseNameSurvivesRotation() throws {
        // The exact failure the identity model exists to prevent. No mDNS name, a
        // randomized MAC that rotates between runs, and a DHCP hostname that does not.
        func device(mac: MACAddress) -> Device {
            Device(observing: HostFacts(
                ip: IPv4Address("10.10.20.33")!,
                mac: mac,
                dhcpHostname: "kitchen-display"
            ), in: Self.network, lastSeen: Timestamp(millisecondsSinceEpoch: 0))
        }
        let events = deriveEvents(
            previous: [device(mac: try MACAddress.required("DA:5C:22:5E:08:0A"))],
            current: [device(mac: try MACAddress.required("6E:F0:9D:5E:0B:52"))],
            at: Timestamp(millisecondsSinceEpoch: 0), run: UUID(), network: Self.network
        )
        #expect(!events.contains { $0.kind == .hostAppeared })
        #expect(!events.contains { $0.kind == .hostDisappeared })
        #expect(events.isEmpty)
    }
}

@Suite("Stability bands agree with their own prose")
struct StabilityBandTests {
    static let network = IPv4Network("10.10.20.0/24")!

    @Test("Every key kind lands in the band its documentation names")
    func bandTable() {
        // .moderate documents "a Bonjour instance, or a DHCP lease hostname"; .weak
        // documents "a rotating MAC and nothing better". Weight 40 used to fall in
        // .weak, so a host with no MAC at all was described as having a rotating one.
        let expected: [(HostIdentifierKind, Stability)] = [
            (.universalMAC, .strong),
            (.mdnsInstance, .moderate),
            (.dhcpHostname, .moderate),
            (.randomizedMAC, .weak),
            (.ipLease, .ephemeral),
        ]
        for (kind, band) in expected {
            #expect(Stability(strongestWeight: kind.weight) == band, "\(kind)")
        }
    }

    @Test("A host known only by its lease hostname is moderate, not weak")
    func hostnameOnly() {
        // No MAC at all, so nothing rotating to describe.
        let keys: [HostIdentifier] = [
            .dhcpHostname("kitchen-display"),
            .ipLease(IPv4Address("10.10.20.33")!, in: Self.network),
        ]
        #expect(Stability(strongestOf: keys) == .moderate)
    }

    @Test("A device with no MAC and only a lease name reports moderate end to end")
    func hostnameOnlyDevice() throws {
        let device = Device(
            observing: HostFacts(ip: try #require(IPv4Address("10.10.20.33")),
                                 dhcpHostname: "kitchen-display"),
            in: Self.network
        )
        #expect(device.mac == nil)
        #expect(device.identityStability == .moderate)
    }

    @Test("No threshold sits on a defined weight, so a new kind cannot land on a boundary")
    func thresholdsSitBetweenWeights() {
        let weights = Set(HostIdentifierKind.allCases.map(\.weight))
        for threshold in [80, 35, 20] {
            #expect(!weights.contains(threshold), "threshold \(threshold) collides with a key weight")
        }
    }
}

@Suite("Bounded runs report why they stopped")
struct PoolTerminationTests {
    @Test("Exhausted work reports exhausted, and maps to a complete outcome")
    func exhausted() async {
        let run = await boundedPool(
            over: Array(1...50), concurrency: 8, deadline: Deadline(after: .seconds(10))
        ) { .observed($0) }
        #expect(run.termination == .exhausted)
        #expect(run.termination.outcome == .complete)
        #expect(run.completed == 50)
        #expect(run.abandoned == 0)
    }

    @Test("A mostly-silent sweep still reports exhausted, because a short result is not a signal")
    func silenceIsNotIncompleteness() async {
        // The reason termination cannot be inferred from `results.count`: dropping
        // silent probes is the normal shape of a successful scan over an empty network.
        let run = await boundedPool(
            over: Array(1...100), concurrency: 8, deadline: Deadline(after: .seconds(10))
        ) { $0 == 1 ? .observed($0) : .silent }
        #expect(run.results.count == 1)
        #expect(run.completed == 100)
        #expect(run.termination == .exhausted)
    }

    @Test("An expired budget reports deadlineExpired, which is a success outcome")
    func deadlineExpired() async {
        let run = await boundedPool(
            over: Array(1...5000), concurrency: 4, deadline: Deadline(after: .milliseconds(120))
        ) { item in
            try? await Task.sleep(for: .milliseconds(10))
            return .observed(item)
        }
        #expect(run.termination == .deadlineExpired)
        #expect(run.termination.outcome == .deadlineExpired)
        #expect(run.completed < run.total)
        #expect(run.abandoned > 0)
    }

    @Test("Ctrl-C mid-sweep reports cancelled, not a deadline hit")
    func cancelledMidSweep() async {
        let started = ProbeCounters()
        let task = Task {
            await boundedPool(
                over: Array(1...5000), concurrency: 4, deadline: Deadline(after: .seconds(30))
            ) { item -> ProbeOutcome<Int> in
                started.probeSent()
                try? await Task.sleep(for: .milliseconds(5))
                return .observed(item)
            }
        }
        // Let the sweep get going, then interrupt it the way a signal handler would.
        while started.snapshot().probesSent < 8 { await Task.yield() }
        task.cancel()
        let run = await task.value

        // The distinction that matters: an external cancellation makes the timer's
        // sleep throw immediately, so a naive reading would call this a deadline hit
        // and every Ctrl-C would be reported with the wrong outcome.
        #expect(run.termination == .cancelled)
        #expect(run.termination.outcome == .cancelled)
        #expect(run.completed < run.total)
    }

    @Test("An empty item list is exhausted, not a failure")
    func emptyIsExhausted() async {
        let run = await boundedPool(
            over: [Int](), concurrency: 8, deadline: Deadline(after: .seconds(1))
        ) { ProbeOutcome.observed($0) }
        #expect(run.termination == .exhausted)
        #expect(run.total == 0)
    }
}

@Suite("A network too wide to sweep refuses rather than reporting empty")
struct WideNetworkTests {
    @Test("A /8 refuses, and says how many addresses and what to do instead")
    func slashEightRefuses() throws {
        let target = ScanTarget(
            network: try #require(IPv4Network("10.0.0.0/8")),
            interface: NetworkInterface(name: "en0",
                                        address: try #require(IPv4Address("10.10.20.5")),
                                        network: try #require(IPv4Network("10.0.0.0/8")))
        )
        let refusal = try #require(target.resolution.refusal)
        // Never .complete with an empty device list: a user with sixteen million
        // addressable hosts must not be told their network is empty.
        #expect(refusal.stage == .setup)
        #expect(refusal.reason.contains("16777214"))
        #expect(target.resolution.addresses == nil)
    }

    @Test("A /16 is still scanned")
    func slashSixteenResolves() throws {
        let network = try #require(IPv4Network("10.10.0.0/16"))
        let target = ScanTarget(network: network,
                                interface: NetworkInterface(name: "en0",
                                                            address: try #require(IPv4Address("10.10.20.5")),
                                                            network: network))
        #expect(target.network.isEnumerable)
        #expect(target.resolution.addresses?.count == 65534)
    }

    @Test("Chunking is the deliberate way to scan something wider")
    func chunking() throws {
        let wide = try #require(IPv4Network("10.0.0.0/8"))
        let chunks = wide.chunked()
        #expect(chunks.count == 256)
        #expect(chunks.first?.description == "10.0.0.0/16")
        #expect(chunks.last?.description == "10.255.0.0/16")
        #expect(chunks.allSatisfy { $0.isEnumerable })
        // Every address in the original is covered by exactly one chunk.
        #expect(chunks.reduce(0) { $0 + $1.hostCount } == 256 * 65534)
    }

    @Test("An already-narrow network chunks to itself")
    func narrowChunksToItself() throws {
        let network = try #require(IPv4Network("10.10.20.0/24"))
        #expect(network.chunked() == [network])
    }

    @Test("An explicit address list is honoured however wide the network")
    func explicitAddressesWin() throws {
        let wide = try #require(IPv4Network("10.0.0.0/8"))
        let target = ScanTarget(
            network: wide,
            interface: NetworkInterface(name: "en0",
                                        address: try #require(IPv4Address("10.10.20.5")),
                                        network: wide),
            addresses: [try #require(IPv4Address("10.10.20.1"))]
        )
        #expect(target.resolution.addresses?.count == 1)
    }

    @Test("An empty explicit list refuses too, rather than silently scanning nothing")
    func emptyExplicitListRefuses() throws {
        let network = try #require(IPv4Network("10.10.20.0/24"))
        let target = ScanTarget(network: network,
                                interface: NetworkInterface(name: "en0",
                                                            address: try #require(IPv4Address("10.10.20.5")),
                                                            network: network),
                                addresses: [])
        #expect(target.resolution.refusal != nil)
    }
}

@Suite("Wire format is pinned and canonical")
struct WireStabilityTests {
    static let network = IPv4Network("10.10.20.0/24")!

    @Test("Every Codable enum case has an explicit snake_case raw value")
    func rawValuesArePinnedAndConsistent() {
        // Renaming a Swift case must be a refactor, not a wire-format change. And the
        // casing has to match the field keys, which are snake_case throughout.
        func check(_ values: [String], _ label: String) {
            for value in values {
                #expect(value == value.lowercased(), "\(label): '\(value)' is not lowercase")
                #expect(!value.contains(" "), "\(label): '\(value)' contains a space")
            }
        }
        check(NameSource.allCases.map(\.rawValue), "NameSource")
        check(Stage.allCases.map(\.rawValue), "Stage")
        check(PortState.allCases.map(\.rawValue), "PortState")
        check(TransportProtocol.allCases.map(\.rawValue), "TransportProtocol")
        check(ServiceEvidence.allCases.map(\.rawValue), "ServiceEvidence")
        check(HostIdentifierKind.allCases.map(\.rawValue), "HostIdentifierKind")
        check(Stability.allCases.map(\.rawValue), "Stability")
        check(Identification.allCases.map(\.rawValue), "Identification")
        check(OSHint.allCases.map(\.rawValue), "OSHint")
        check(Outcome.allCases.map(\.rawValue), "Outcome")
        check(EngineKind.allCases.map(\.rawValue), "EngineKind")
        check(ScanEventKind.allCases.map(\.rawValue), "ScanEventKind")
        check(EventSeverity.allCases.map(\.rawValue), "EventSeverity")

        // Spot-check the multi-word ones, which are where camelCase used to leak out.
        #expect(Stage.deepScan.rawValue == "deep_scan")
        #expect(Outcome.deadlineExpired.rawValue == "deadline_expired")
        #expect(HostIdentifierKind.universalMAC.rawValue == "universal_mac")
        #expect(ServiceEvidence.tlsCertificate.rawValue == "tls_certificate")
        #expect(ScanEventKind.hostAppeared.rawValue == "host_appeared")
        #expect(OSHint.networkDevice.rawValue == "network_device")
        #expect(EngineKind.privilegedBPF.rawValue == "privileged_bpf")
    }

    @Test("Two scans that found the same network encode to identical bytes")
    func encodingIsCanonical() throws {
        func report(_ order: [Int]) throws -> ScanReport {
            let devices = try order.map { last in
                Device(observing: HostFacts(
                    ip: try #require(IPv4Address("10.10.20.\(last)")),
                    ports: [PortObservation(port: 443, state: .open),
                            PortObservation(port: 22, state: .open),
                            PortObservation(port: 80, state: .open)].shuffled()
                ), in: Self.network, lastSeen: Timestamp(millisecondsSinceEpoch: 0))
            }
            return ScanReport(
                run: ScanRun(id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                             startedAt: Timestamp(millisecondsSinceEpoch: 0),
                             target: Self.network, interface: "en0",
                             engine: EngineDescriptor(name: "t", kind: .unprivileged, capabilities: []),
                             outcome: .complete, timing: Timing()),
                devices: devices
            )
        }
        // Same hosts, discovered in a different order — which is what actually happens,
        // since devices arrive in whatever order they answer.
        let a = try report([1, 2, 3, 8]).encoded()
        let b = try report([8, 3, 1, 2]).encoded()
        #expect(a == b)
    }

    @Test("Ports are canonical inside a device, on both construction paths")
    func portsAreSorted() throws {
        let device = Device(observing: HostFacts(
            ip: try #require(IPv4Address("10.10.20.6")),
            ports: [PortObservation(port: 9100, state: .open),
                    PortObservation(port: 22, state: .closed),
                    PortObservation(port: 443, state: .open)]
        ), in: Self.network)
        #expect(device.ports.map(\.port) == [22, 443, 9100])

        // Decoding must establish the same invariant, or a hand-edited document
        // reintroduces the instability the sort exists to remove.
        let json = #"""
        {"ip":"10.10.20.6","names":[],"identification":"minimal",
         "identification_evidence":{"has_distinct_name":false,"name_source_is_self_sufficient":false,
          "has_model":false,"has_vendor":false,"has_os_hint":false,"independent_sources":0},
         "identity_stability":"ephemeral","first_seen":0,"last_seen":0,
         "ports":[{"port":9100,"proto":"tcp","state":"open"},{"port":22,"proto":"tcp","state":"closed"}]}
        """#
        let decoded = try ScanReport.makeDecoder().decode(Device.self, from: Data(json.utf8))
        #expect(decoded.ports.map(\.port) == [22, 9100])
    }
}

@Suite("Name ordering is total")
struct NameOrderingTests {
    @Test("Equal source and rank tie on value, so the winner is not arrival order")
    func tiesAreBrokenByValue() {
        let a = NameCandidate(value: "Apple TV", source: .mdns, rank: 3)
        let b = NameCandidate(value: "Zebra Printer", source: .mdns, rank: 3)
        // Whichever order they arrive in, the same one wins.
        #expect([a, b].best == [b, a].best)
        #expect([a, b].best?.value == "Apple TV")
    }

    @Test("displayName does not flip with mDNS arrival order")
    func displayNameIsStable() throws {
        // The failure this prevents: an unstable winner emits a nameChanged event at
        // .warning severity — the severity reserved for "the identity join may be
        // wrong" — for a device that has not changed at all.
        let candidates = [
            NameCandidate(value: "living-room", source: .mdns, rank: 2),
            NameCandidate(value: "Living Room", source: .mdns, rank: 2),
            NameCandidate(value: "LivingRoom", source: .mdns, rank: 2),
        ]
        let names = Set(candidates.permutations().map { permutation in
            Device(observing: HostFacts(ip: IPv4Address("10.10.20.9")!, allNames: permutation),
                   in: IPv4Network("10.10.20.0/24")!).displayName
        })
        #expect(names.count == 1)
    }

    @Test("Sorting is a total order: no two distinct candidates compare as equal")
    func orderingIsTotal() {
        let candidates = [
            NameCandidate(value: "a", source: .mdns, rank: 1),
            NameCandidate(value: "b", source: .mdns, rank: 1),
            NameCandidate(value: "a", source: .ssdp, rank: 1),
            NameCandidate(value: "a", source: .mdns, rank: 2),
        ]
        for x in candidates {
            for y in candidates where x != y {
                #expect(x < y || y < x, "\(x.value)/\(x.source) and \(y.value)/\(y.source) are unordered")
            }
        }
    }
}

private extension Array {
    /// Every ordering of the receiver. Small inputs only; this is a test helper.
    func permutations() -> [[Element]] {
        guard count > 1 else { return [self] }
        return indices.flatMap { index -> [[Element]] in
            var rest = self
            let element = rest.remove(at: index)
            return rest.permutations().map { [element] + $0 }
        }
    }
}

@Suite("A dual-homed device stays in the diff")
struct DualHomedTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static let mac = "30:DE:4B:5E:03:10"

    private func device(_ ip: String, name: String? = nil, openPorts: [UInt16] = []) -> Device {
        Device(observing: HostFacts(
            ip: IPv4Address(ip)!,
            mac: MACAddress(Self.mac),
            allNames: name.map { [NameCandidate(value: $0, source: .mdns)] } ?? [],
            ports: openPorts.map { PortObservation(port: $0, state: .open) }
        ), in: Self.network, lastSeen: Timestamp(millisecondsSinceEpoch: 0))
    }

    private func derive(_ previous: [Device], _ current: [Device]) -> [ScanEvent] {
        deriveEvents(previous: previous, current: current,
                     at: Timestamp(millisecondsSinceEpoch: 0), run: UUID(), network: Self.network)
    }

    @Test("Two interfaces on one MAC, both unchanged, produce no events")
    func stableDualHomedIsQuiet() {
        // Last-write-wins used to drop one of the two, and which one survived depended
        // on array order — so an unchanged host could diff as having moved.
        let before = [device("10.10.20.10", name: "NAS"), device("10.10.20.11", name: "NAS")]
        #expect(derive(before, before).isEmpty)
        #expect(derive(before, before.reversed()).isEmpty)
    }

    @Test("One interface moving does not drag the other into the diff")
    func oneInterfaceMoves() {
        let events = derive(
            [device("10.10.20.10", name: "NAS"), device("10.10.20.11", name: "NAS")],
            [device("10.10.20.10", name: "NAS"), device("10.10.20.12", name: "NAS")]
        )
        #expect(events.map(\.kind) == [.ipMoved])
        #expect(events[0].details["from"] == "10.10.20.11")
        #expect(events[0].details["to"] == "10.10.20.12")
    }

    @Test("Losing one interface is a disappearance, not a move")
    func losingAnInterface() {
        let events = derive(
            [device("10.10.20.10", name: "NAS"), device("10.10.20.11", name: "NAS")],
            [device("10.10.20.10", name: "NAS")]
        )
        #expect(events.map(\.kind) == [.hostDisappeared])
        #expect(events[0].ip.description == "10.10.20.11")
    }

    @Test("Gaining one is an appearance")
    func gainingAnInterface() {
        let events = derive(
            [device("10.10.20.10", name: "NAS")],
            [device("10.10.20.10", name: "NAS"), device("10.10.20.11", name: "NAS")]
        )
        #expect(events.map(\.kind) == [.hostAppeared])
    }

    @Test("Field changes on the interface that stayed put are still reported")
    func fieldsOnMatchedInterface() {
        let events = derive(
            [device("10.10.20.10", name: "NAS"), device("10.10.20.11", name: "NAS")],
            [device("10.10.20.10", name: "NAS", openPorts: [445]), device("10.10.20.11", name: "NAS")]
        )
        #expect(events.map(\.kind) == [.portOpened])
        #expect(events[0].ip.description == "10.10.20.10")
    }
}

@Suite("Karn's rule is both halves")
struct KarnBackoffTests {
    private func settled(at rtt: Duration) -> RTTEstimator {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(rtt) }
        return estimator
    }

    @Test("A retransmission widens the window, so the discard is not a trap")
    func backoffWidensTheWindow() {
        var estimator = settled(at: .microseconds(400))
        let tight = estimator.timeout()
        #expect(tight == RTTEstimator.defaultFloor)

        estimator.record(.milliseconds(500), wasRetransmitted: true)
        #expect(estimator.backoffExponent == 1)
        #expect(estimator.timeout() == tight * 2)

        estimator.record(.milliseconds(500), wasRetransmitted: true)
        #expect(estimator.timeout() == tight * 4)
    }

    @Test("A host moving behind a slower link recovers instead of timing out forever")
    func recoversAfterMovingToASlowerLink() {
        // Without the backoff: every probe times out, so every reply is ambiguous, so
        // every sample is discarded, so the estimate never grows, so the timeout stays
        // pinned at the floor. The host is alive and looks dead, permanently.
        var estimator = settled(at: .microseconds(400))
        let newRTT = Duration.milliseconds(180)

        var retransmissions = 0
        while estimator.timeout() < newRTT {
            estimator.record(newRTT, wasRetransmitted: true)
            retransmissions += 1
            #expect(retransmissions < 20, "backoff never reached the new RTT")
        }
        // The window is now wide enough that the first transmission gets answered, so
        // the next sample is unambiguous.
        estimator.record(newRTT)
        #expect(estimator.backoffExponent == 0)
        #expect(estimator.acceptedSamples == 51)

        for _ in 0..<20 { estimator.record(newRTT) }
        let smoothed = try! #require(estimator.smoothed)
        #expect(abs(smoothed.milliseconds - 180) < 20)
    }

    @Test("An unambiguous sample clears the backoff")
    func successResetsBackoff() {
        var estimator = settled(at: .milliseconds(50))
        estimator.record(.milliseconds(50), wasRetransmitted: true)
        estimator.record(.milliseconds(50), wasRetransmitted: true)
        #expect(estimator.backoffExponent == 2)
        estimator.record(.milliseconds(50))
        #expect(estimator.backoffExponent == 0)
    }

    @Test("An ambiguous sample still never moves the estimate")
    func discardStillHolds() {
        var estimator = settled(at: .milliseconds(10))
        let before = estimator.smoothed
        let count = estimator.acceptedSamples
        estimator.record(.seconds(5), wasRetransmitted: true)
        #expect(estimator.smoothed == before)
        #expect(estimator.acceptedSamples == count)
    }

    @Test("Backoff is capped, and the ceiling still holds")
    func backoffIsCapped() {
        var estimator = settled(at: .milliseconds(500))
        for _ in 0..<50 { estimator.record(.seconds(1), wasRetransmitted: true) }
        #expect(estimator.backoffExponent == RTTEstimator.maximumBackoffExponent)
        #expect(estimator.timeout() <= RTTEstimator.defaultCeiling)
    }
}

@Suite("The artifact reports the timeout that was used")
struct ImpliedTimeoutTests {
    @Test("A LAN sample implies the floor, not an unclamped sub-millisecond number")
    func floorIsApplied() {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(.microseconds(400)) }
        let sample = try! #require(estimator.sample)
        // srtt + 4·rttvar here is well under a millisecond, but no probe ever waited
        // that long — the floor was in force. An artifact that says otherwise is worse
        // than one that says nothing, because it will be believed.
        #expect(sample.impliedTimeout == RTTEstimator.defaultFloor)
        #expect(sample.impliedTimeout == estimator.timeout())
    }

    @Test("A pathological sample implies the ceiling")
    func ceilingIsApplied() {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(.seconds(30)) }
        let sample = try! #require(estimator.sample)
        #expect(sample.impliedTimeout == RTTEstimator.defaultCeiling)
        #expect(sample.impliedTimeout == estimator.timeout())
    }

    @Test("A sample in the middle passes through, and matches the estimator")
    func midRangeMatches() {
        var estimator = RTTEstimator()
        for _ in 0..<50 { estimator.record(.milliseconds(120)) }
        let sample = try! #require(estimator.sample)
        #expect(sample.impliedTimeout == estimator.timeout())
        #expect(sample.impliedTimeout > RTTEstimator.defaultFloor)
        #expect(sample.impliedTimeout < RTTEstimator.defaultCeiling)
    }

    @Test("A single sample with no smoothed estimate is clamped too")
    func singleSampleIsClamped() {
        #expect(RTTSample(measured: .microseconds(50)).impliedTimeout == RTTEstimator.defaultFloor)
        #expect(RTTSample(measured: .seconds(60)).impliedTimeout == RTTEstimator.defaultCeiling)
    }
}

@Suite("Remediation text is not macOS-only")
struct PermissionAdviceTests {
    private func degradation(_ advice: ProbePermissionAdvice) -> Degradation {
        try! #require(LocalNetworkDenialHeuristic.evaluate(
            repliesSeen: 0, probesSent: 254, neighborEntries: 6, advice: advice
        ))
    }

    @Test("By default core names the observation and prescribes nothing")
    func defaultIsPlatformNeutral() {
        let reason = degradation(.unspecified).reason
        // A package that must run on Linux cannot tell every user to open a macOS
        // settings pane, and a wrong instruction is worse than none.
        #expect(!reason.contains("macOS"))
        #expect(!reason.contains("Privacy & Security"))
        #expect(reason.contains("6 devices"))
        #expect(reason.contains("likely cause"))
    }

    @Test("The Apple platform target opts into the Local Network wording")
    func appleAdvice() {
        let reason = degradation(.appleLocalNetwork).reason
        #expect(reason.contains("Privacy & Security"))
        #expect(reason.contains("likely cause"))
    }

    @Test("An app gets the same grant, without the sentence about command-line builds")
    func appAdvice() {
        let cli = degradation(.appleLocalNetwork).reason
        let app = degradation(.appleLocalNetworkInApp).reason
        #expect(app.contains("Privacy & Security › Local Network"))
        #expect(app.contains("likely cause"))
        // The sentence the app used to cut out of the text at runtime.
        #expect(!app.contains("command-line"), "an app was told it has no bundle")
        #expect(!app.contains("terminal"))
        #expect(cli.contains("A command-line build has no bundle of its own"),
                "the command line lost the sentence it needs")
    }

    @Test("Linux gets the sysctl that actually governs unprivileged ICMP there")
    func linuxAdvice() {
        let reason = degradation(.linuxPingGroupRange).reason
        #expect(reason.contains("ping_group_range"))
        #expect(!reason.contains("Privacy & Security"))
    }

    @Test("The heuristic still refuses to fire when there is nothing to explain")
    func guardsStillHold() {
        for advice in ProbePermissionAdvice.allCases {
            #expect(LocalNetworkDenialHeuristic.evaluate(
                repliesSeen: 0, probesSent: 254, neighborEntries: 0, advice: advice) == nil)
            #expect(LocalNetworkDenialHeuristic.evaluate(
                repliesSeen: 3, probesSent: 254, neighborEntries: 6, advice: advice) == nil)
            #expect(LocalNetworkDenialHeuristic.evaluate(
                repliesSeen: 0, probesSent: 0, neighborEntries: 6, advice: advice) == nil)
        }
    }
}
