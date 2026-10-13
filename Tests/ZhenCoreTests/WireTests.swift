import Foundation
import Testing
@testable import ZhenCore

@Suite("Internet checksum")
struct ChecksumTests {
    @Test("Known vectors, and a correct packet sums to zero")
    func knownVectorsAndSelfVerification() {
        // A real ICMP echo header: type 8, code 0, checksum 0, id 0x1234, seq 1.
        // 0x0800 + 0x0000 + 0x1234 + 0x0001 = 0x1A35; ~0x1A35 = 0xE5CA.
        var packet: [UInt8] = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]
        #expect(InternetChecksum.compute(packet) == 0xE5CA)

        // The receive-side property: summing a correct packet including its checksum
        // field yields zero. This is the check the ICMP reader will do.
        let checksum = InternetChecksum.compute(packet)
        packet[2] = UInt8(checksum >> 8)
        packet[3] = UInt8(checksum & 0xFF)
        #expect(InternetChecksum.compute(packet) == 0)
        #expect(packet.withSpan { InternetChecksum.verifies($0) })

        // And it holds for an odd-length payload, which is where the tail handling
        // below actually bites.
        var longer: [UInt8] = [0x08, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x2A]
        longer.append(contentsOf: (0..<57).map { UInt8($0) })
        let longerChecksum = InternetChecksum.compute(longer)
        longer[2] = UInt8(longerChecksum >> 8)
        longer[3] = UInt8(longerChecksum & 0xFF)
        #expect(InternetChecksum.compute(longer) == 0)
    }

    @Test("Odd tails, carries and the empty buffer")
    func edgeCases() {
        // An odd trailing byte pads on the RIGHT. Getting this backwards produces a
        // checksum that is correct for every even-length packet and wrong for every
        // odd-length one — a bug that survives a suite built only from 8-byte headers.
        #expect(InternetChecksum.compute([0x01]) == UInt16(bitPattern: ~0x0100))
        #expect(InternetChecksum.compute([0x01, 0x02, 0x03]) == UInt16(bitPattern: ~0x0402))

        // Carries fold back in: 0xFFFF + 0xFFFF = 0x1FFFE, folds to 0xFFFF, complements
        // to zero.
        #expect(InternetChecksum.compute([0xFF, 0xFF, 0xFF, 0xFF]) == 0)

        #expect(InternetChecksum.compute([UInt8]()) == 0xFFFF)
    }
}

extension Array where Element == UInt8 {
    /// Borrows a span over this array, so a test can exercise the Span-taking entry
    /// point directly rather than only the array convenience.
    func withSpan<T>(_ body: (Span<UInt8>) -> T) -> T { body(span) }
}

@Suite("Port state is three-valued")
struct PortStateTests {
    @Test("A refusal proves a host is there; silence proves nothing")
    func closedProvesAlive() {
        // The distinction that separates a live host behind a firewall from a dead
        // address. Collapsing these two into "not open" makes that unanswerable.
        #expect(PortState.open.provesHostAlive)
        #expect(PortState.closed.provesHostAlive)
        #expect(!PortState.filtered.provesHostAlive)
    }

    @Test("A host whose ports are all closed is up; all filtered is unknown")
    func hostLivenessFromPorts() throws {
        let network = IPv4Network("10.10.20.0/24")!
        let firewalled = Device(
            observing: HostFacts(
                ip: try #require(IPv4Address("10.10.20.50")),
                ports: [PortObservation(port: 22, state: .closed),
                        PortObservation(port: 80, state: .closed)]
            ),
            in: network
        )
        #expect(firewalled.portScanProvesAlive)
        #expect(firewalled.openPorts.isEmpty)

        let silent = Device(
            observing: HostFacts(
                ip: try #require(IPv4Address("10.10.20.51")),
                ports: [PortObservation(port: 22, state: .filtered)]
            ),
            in: network
        )
        #expect(!silent.portScanProvesAlive)
    }

    @Test("A service can only be claimed from evidence, never from a port number")
    func servicesNeedEvidence() {
        // There is no `.portNumber` case to construct. 8080 is a proxy, or a dev
        // server, or a printer, or a Plex box, and the type refuses to let us guess.
        #expect(ServiceEvidence.allCases.count == 3)
        #expect(!ServiceEvidence.allCases.map(\.rawValue).contains("portNumber"))

        let identified = ServiceIdentity(
            name: "ssh", product: "OpenSSH", version: "9.6",
            banner: "SSH-2.0-OpenSSH_9.6", evidence: .banner
        )
        #expect(identified.evidence == .banner)
        // The evidence is kept, so a user who disagrees with our parse can see it.
        #expect(identified.banner != nil)
    }
}

@Suite("Degradations")
struct DegradationTests {
    @Test("A silent sweep over a populated ARP cache raises the permission heuristic")
    func denialHeuristicFires() {
        let degradation = LocalNetworkDenialHeuristic.evaluate(
            repliesSeen: 0, probesSent: 254, neighborEntries: 6
        )
        let raised = try! #require(degradation)
        #expect(raised.stage == .discovery)
        #expect(!raised.recoverable)
        // The permission cannot be queried, only inferred, and the string must say so
        // rather than claim a certainty we do not have.
        #expect(raised.reason.contains("likely cause"))
        #expect(raised.reason.contains("6 devices"))
    }

    @Test("A genuinely empty network raises nothing")
    func noNeighboursNoClaim() {
        // Nothing in the ARP cache means there is nothing to explain — the network
        // really may be empty, and that is a distinction the user can make and we
        // cannot.
        #expect(LocalNetworkDenialHeuristic.evaluate(repliesSeen: 0, probesSent: 254, neighborEntries: 0) == nil)
    }

    @Test("A sweep that found something raises nothing")
    func repliesMeanNoDenial() {
        #expect(LocalNetworkDenialHeuristic.evaluate(repliesSeen: 3, probesSent: 254, neighborEntries: 6) == nil)
    }

    @Test("A stage that never ran is a different problem")
    func noProbesNoClaim() {
        #expect(LocalNetworkDenialHeuristic.evaluate(repliesSeen: 0, probesSent: 0, neighborEntries: 6) == nil)
    }

    @Test("Degradations round-trip, because they reach the UI and the artifact alike")
    func degradationsRoundTrip() throws {
        let degradation = Degradation(stage: .deepScan, reason: "BPF nodes are all busy.", recoverable: true)
        let data = try ScanReport.makeEncoder().encode(degradation)
        #expect(try ScanReport.makeDecoder().decode(Degradation.self, from: data) == degradation)
    }
}
