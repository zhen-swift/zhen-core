import Foundation
import Testing
@testable import ZhenCore

/// A deterministic generator, so a failure is reproducible from the seed printed in
/// the assertion rather than from luck.
private struct Rng: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { self.state = seed &* 6364136223846793005 &+ 1442695040888963407 }
    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
}

@Suite("Round trip holds for arbitrary devices")
struct PropertyRoundTripTests {
    static let network = IPv4Network("10.10.20.0/24")!

    /// Builds a device from a random observation, with random first/last seen stamps.
    private static func randomDevice(_ rng: inout Rng) -> Device {
        let firstSeen = Timestamp(millisecondsSinceEpoch: Int64(rng.next() % 1_800_000_000_000))
        let lastSeen = Timestamp(millisecondsSinceEpoch: Int64(rng.next() % 1_800_000_000_000))
        return Device(observing: randomFacts(&rng), in: Self.network,
                      firstSeen: firstSeen, lastSeen: lastSeen)
    }

    /// Builds an observation whose every optional field is independently present or
    /// absent. The point is coverage of the *combinations*: a hand-written fixture
    /// tends to be either fully populated or fully empty, and the encoding bugs live
    /// in between — a device with a model but no name, a port with an RTT but no
    /// service, a host with a lease name and no MAC.
    private static func randomFacts(_ rng: inout Rng) -> HostFacts {
        func maybe(_ probability: Double = 0.5) -> Bool {
            Double(rng.next() % 1000) / 1000 < probability
        }

        let ip = IPv4Address(raw: 0x0A0A_1400 | UInt32(rng.next() % 254 + 1))
        let mac: MACAddress? = maybe() ? MACAddress(raw: rng.next()) : nil

        var names: [NameCandidate] = []
        for source in NameSource.allCases where maybe(0.4) {
            names.append(NameCandidate(
                value: maybe(0.1) ? "" : "device-\(rng.next() % 1000)",
                source: source,
                rank: Int(rng.next() % 20),
                model: maybe() ? "Model\(rng.next() % 99)" : nil
            ))
        }

        var ports: [PortObservation] = []
        for _ in 0..<(rng.next() % 4) {
            let states: [PortState] = [.open, .closed, .filtered]
            ports.append(PortObservation(
                port: UInt16(rng.next() % 65535),
                proto: maybe() ? .tcp : .udp,
                state: states[Int(rng.next() % 3)],
                service: maybe() ? ServiceIdentity(
                    name: "svc\(rng.next() % 20)",
                    product: maybe() ? "Product" : nil,
                    version: maybe() ? "1.2.3" : nil,
                    banner: maybe() ? "banner text" : nil,
                    tlsSubject: maybe() ? "CN=example.lan" : nil,
                    evidence: [.banner, .tlsCertificate, .protocolHandshake][Int(rng.next() % 3)]
                ) : nil,
                rtt: maybe() ? RTTSample(measured: .microseconds(Int(rng.next() % 5000))) : nil
            ))
        }

        return HostFacts(
            ip: ip,
            mac: mac,
            allNames: names,
            vendor: maybe() ? "Vendor \(rng.next() % 50)" : nil,
            reverseDNS: maybe() ? "host.lan" : nil,
            dhcpHostname: maybe() ? "dhcp-name" : nil,
            ttl: maybe() ? UInt8(rng.next() % 256) : nil,
            rtt: maybe() ? RTTSample(
                measured: .microseconds(Int(rng.next() % 20000)),
                smoothed: maybe() ? .microseconds(Int(rng.next() % 20000)) : nil,
                variation: maybe() ? .microseconds(Int(rng.next() % 5000)) : nil,
                samples: Int(rng.next() % 100)
            ) : nil,
            ports: ports
        )
    }

    @Test("Two thousand arbitrary devices survive encode and decode unchanged")
    func devicesRoundTrip() throws {
        let encoder = ScanReport.makeEncoder()
        let decoder = ScanReport.makeDecoder()
        for seed in UInt64(1)...2000 {
            var rng = Rng(seed: seed)
            let device = Self.randomDevice(&rng)
            let decoded = try decoder.decode(Device.self, from: try encoder.encode(device))
            #expect(decoded == device, "seed \(seed)")
        }
    }

    @Test("Encoding is deterministic, so two identical scans diff to nothing")
    func encodingIsStable() throws {
        let encoder = ScanReport.makeEncoder()
        for seed in UInt64(1)...200 {
            var first = Rng(seed: seed)
            var second = Rng(seed: seed)
            let a = try encoder.encode(Self.randomDevice(&first))
            let b = try encoder.encode(Self.randomDevice(&second))
            #expect(a == b, "seed \(seed)")
        }
    }

    @Test("Every arbitrary device reproduces the key set of the facts it came from")
    func candidateKeysAgreeAcrossTheCorpus() throws {
        // The property behind the first review defect, checked over the whole random
        // corpus rather than one fixture: a Device and the HostFacts it was built from
        // must be indistinguishable to the identity resolver, before and after
        // encoding. Without it, identityStability in a report is unverifiable.
        let encoder = ScanReport.makeEncoder()
        let decoder = ScanReport.makeDecoder()
        for seed in UInt64(1)...500 {
            var rng = Rng(seed: seed)
            let facts = Self.randomFacts(&rng)
            let device = Device(observing: facts, in: Self.network)
            let expected = HostIdentifier.candidates(for: facts, in: Self.network)
            #expect(HostIdentifier.candidates(for: device, in: Self.network) == expected, "seed \(seed)")

            let decoded = try decoder.decode(Device.self, from: try encoder.encode(device))
            #expect(HostIdentifier.candidates(for: decoded, in: Self.network) == expected, "seed \(seed)")
            #expect(decoded.identityStability == Stability(strongestOf: expected), "seed \(seed)")
        }
    }

    @Test("Arbitrary host facts round-trip too, since they are the NDJSON payload")
    func factsRoundTrip() throws {
        let encoder = ScanReport.makeEncoder()
        let decoder = ScanReport.makeDecoder()
        for seed in UInt64(1)...500 {
            var rng = Rng(seed: seed)
            let facts = Self.randomFacts(&rng)
            #expect(try decoder.decode(HostFacts.self, from: try encoder.encode(facts)) == facts,
                    "seed \(seed)")
        }
    }

    @Test("A report of arbitrary devices round-trips as a whole")
    func reportsRoundTrip() throws {
        var rng = Rng(seed: 99)
        let devices = (0..<40).map { _ in Self.randomDevice(&rng) }
        let report = ScanReport(
            run: ScanRun(
                id: UUID(uuidString: "00000000-0000-0000-0000-0000000000FF")!,
                startedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_000),
                finishedAt: nil,
                target: Self.network,
                interface: "en0",
                engine: EngineDescriptor(name: "unprivileged-icmp", kind: .composite,
                                         capabilities: [.icmpSweep, .arpSweep, .connectScan]),
                outcome: .cancelled,
                timing: Timing(stages: [], counters: ProbeCounterSnapshot(
                    probesSent: 0, repliesSeen: 0, peakConcurrency: 0, inFlight: 0))
            ),
            devices: devices,
            degradations: []
        )
        let data = try report.encoded()
        #expect(try ScanReport.decoded(from: data) == report)
        // A run still in progress has no finishedAt, and that absence must survive.
        #expect(try ScanReport.decoded(from: data).run.finishedAt == nil)
    }
}
