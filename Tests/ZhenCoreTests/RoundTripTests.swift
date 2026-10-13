import Foundation
import Testing
@testable import ZhenCore

/// Encoding a value and decoding it must produce something equal to what went in.
/// Not "similar": `==`. Every field, including every absent one.
private func roundTrip<T: Codable & Equatable>(_ value: T) throws -> T {
    let data = try ScanReport.makeEncoder().encode(value)
    return try ScanReport.makeDecoder().decode(T.self, from: data)
}

/// Canonical encoding, as every consumer is meant to produce it.
private func encodedText(_ value: some Encodable) throws -> String {
    String(decoding: try ScanReport.makeEncoder().encode(value), as: UTF8.self)
}

@Suite("Wire round trip")
struct RoundTripTests {
    // The network this tool was built against, as recorded in the specification.
    // Real values rather than invented ones, because the awkward cases here — a
    // device with nothing but an address, a name with a typographic apostrophe — are
    // the ones that actually occur.
    static let network = IPv4Network("10.10.20.0/24")!

    @Test("An address round-trips as readable text, not as a packed integer")
    func addressesEncodeAsText() throws {
        let mac = try MACAddress.required("30:DE:4B:5E:03:10")
        #expect(try encodedText(mac) == "\"30:DE:4B:5E:03:10\"")
        #expect(try roundTrip(mac) == mac)

        let ip = try #require(IPv4Address("10.10.20.112"))
        #expect(try encodedText(ip) == "\"10.10.20.112\"")
        #expect(try roundTrip(ip) == ip)

        // The canonical encoder sets .withoutEscapingSlashes; Foundation's default
        // would render this "10.10.20.0\\/24", which is valid JSON and horrible.
        #expect(try encodedText(Self.network) == "\"10.10.20.0/24\"")
        #expect(try roundTrip(Self.network) == Self.network)
    }

    @Test("An unpadded MAC decodes to the same value a scan would have produced")
    func unpaddedMACDecodes() throws {
        let decoded = try JSONDecoder().decode(MACAddress.self, from: Data(#""0:92:35:30:a:1""#.utf8))
        #expect(decoded == MACAddress("00:92:35:30:0A:01"))
    }

    @Test("Malformed address text fails to decode rather than becoming a zero address")
    func malformedAddressesThrow() {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(IPv4Address.self, from: Data(#""10.10.20.999""#.utf8))
        }
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(MACAddress.self, from: Data(#""not-a-mac""#.utf8))
        }
    }

    @Test("The unidentified device — every field nil — survives the round trip intact")
    func allNilDeviceRoundTrips() throws {
        // 10.10.20.8 on the real network: randomized MAC, no name, no vendor, no
        // model, no TTL, no RTT, no ports. This is the acceptance case for the whole
        // product, not an error, and it must not decode into something subtly
        // different from what was encoded.
        let facts = HostFacts(ip: try #require(IPv4Address("10.10.20.8")))
        let device = Device(observing: facts, in: Self.network, lastSeen: Timestamp(millisecondsSinceEpoch: 1_756_700_000_000))

        #expect(device.mac == nil)
        #expect(device.names.isEmpty)
        #expect(device.vendor == nil)
        #expect(device.ttl == nil)
        #expect(device.rtt == nil)
        #expect(device.ports.isEmpty)
        #expect(device.identification == .minimal)

        let decoded = try roundTrip(device)
        #expect(decoded == device)
        // Absent must stay absent: a nil that decodes as a zero would put a host with
        // a 0 ms round trip in the report, which reads as the fastest device on the
        // network.
        #expect(decoded.rtt == nil)
        #expect(decoded.ttl == nil)
    }

    @Test("Absent optionals are omitted from the JSON, not written as null")
    func absentFieldsAreOmitted() throws {
        let device = Device(
            observing: HostFacts(ip: try #require(IPv4Address("10.10.20.8"))),
            in: Self.network
        )
        let json = try encodedText(device)
        #expect(!json.contains("null"))
        #expect(!json.contains("\"rtt\""))
    }

    @Test("A fully populated device round-trips, apostrophe and all")
    func populatedDeviceRoundTrips() throws {
        // The non-ASCII apostrophe in "Alex's MacBook Pro" is a real value from the
        // real network and it must not be escaped or mangled on the way out.
        let facts = HostFacts(
            ip: try #require(IPv4Address("10.10.20.2")),
            mac: try MACAddress.required("A8:51:AB:5E:09:6C"),
            allNames: [
                NameCandidate(value: "Sala de estar principal", source: .mdns, rank: 1, model: "AppleTV5,3"),
                NameCandidate(value: "70-35-60-63.1 Sala de estar principal", source: .mdns, rank: 9),
                NameCandidate(value: "Alex's MacBook Pro", source: .administrative),
            ],
            vendor: "Apple, Inc.",
            reverseDNS: "appletv.lan",
            dhcpHostname: "appletv",
            ttl: 64,
            rtt: RTTSample(measured: .microseconds(412), smoothed: .microseconds(430), variation: .microseconds(90), samples: 7),
            ports: [
                PortObservation(port: 7000, state: .open,
                                service: ServiceIdentity(name: "airplay", evidence: .banner),
                                rtt: RTTSample(measured: .milliseconds(2))),
                PortObservation(port: 22, state: .closed),
                PortObservation(port: 445, state: .filtered),
            ]
        )
        let device = Device(observing: facts, in: Self.network)
        #expect(try roundTrip(device) == device)
        #expect(try roundTrip(facts) == facts)

        let json = try encodedText(device)
        #expect(json.contains("Alex's MacBook Pro"))
        #expect(!json.contains("\\u"))
    }

    @Test("Sub-millisecond RTT survives serialization")
    func subMillisecondRTTSurvives() throws {
        // A LAN answers in hundreds of microseconds. If this rounds to whole
        // milliseconds the entire range this scanner competes on collapses to 0.
        let sample = RTTSample(measured: .microseconds(412))
        #expect(sample.millis > 0.41 && sample.millis < 0.42)
        let decoded = try roundTrip(sample)
        #expect(decoded.millis == sample.millis)
    }

    @Test("The whole report round-trips")
    func reportRoundTrips() throws {
        let report = ScanReport(
            run: ScanRun(
                id: UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!,
                startedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_000),
                finishedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_001_240),
                target: Self.network,
                interface: "en0",
                engine: EngineDescriptor(
                    name: "unprivileged-icmp",
                    kind: .unprivileged,
                    capabilities: [.icmpSweep, .connectScan, .bannerProbe]
                ),
                outcome: .deadlineExpired,
                timing: Timing(
                    stages: [
                        StageTiming(stage: .discovery, elapsedMillis: 840.5, probesSent: 254, repliesSeen: 6),
                        StageTiming(stage: .naming, elapsedMillis: 399.5, probesSent: 17, repliesSeen: 4),
                    ],
                    counters: ProbeCounterSnapshot(probesSent: 271, repliesSeen: 10, peakConcurrency: 64, inFlight: 0)
                )
            ),
            devices: [
                Device(observing: HostFacts(ip: try #require(IPv4Address("10.10.20.1")), vendor: "Example Networks"), in: Self.network),
                Device(observing: HostFacts(ip: try #require(IPv4Address("10.10.20.8"))), in: Self.network),
            ],
            degradations: [
                Degradation(stage: .naming, reason: "Bonjour browsing returned nothing.", recoverable: true)
            ]
        )
        #expect(try roundTrip(report) == report)
    }

    @Test("Capabilities encode as names, so an archived report stays readable")
    func capabilitiesEncodeAsNames() throws {
        let capabilities: EngineCapabilities = [.icmpSweep, .arpSweep]
        let json = try encodedText(capabilities)
        #expect(json.contains("icmp_sweep"))
        #expect(json.contains("arp_sweep"))
        #expect(try roundTrip(capabilities) == capabilities)
    }

    @Test("An unknown capability from a newer build is ignored, not fatal")
    func unknownCapabilityIsIgnored() throws {
        let decoded = try JSONDecoder().decode(
            EngineCapabilities.self,
            from: Data(#"["icmp_sweep","time_travel"]"#.utf8)
        )
        #expect(decoded == .icmpSweep)
    }

    @Test("Every probe event round-trips, so --ndjson carries the same schema")
    func probeEventsRoundTrip() throws {
        let events: [ProbeEvent] = [
            .stageStarted(.discovery),
            .stageProgress(.discovery, completed: 40, total: 254),
            .stageFinished(StageTiming(stage: .discovery, elapsedMillis: 12.5, probesSent: 254, repliesSeen: 6)),
            .hostFound(HostFacts(ip: try #require(IPv4Address("10.10.20.3")))),
            .hostUpdated(HostFacts(ip: try #require(IPv4Address("10.10.20.3")),
                                   allNames: [NameCandidate(value: "Alex's MacBook Pro", source: .mdns)])),
            .degraded(Degradation(stage: .naming, reason: "no mDNS responder", recoverable: true)),
        ]
        for event in events {
            #expect(try roundTrip(event) == event)
        }
    }

    @Test("Probe events carry a discriminator a non-Swift consumer can switch on")
    func probeEventsAreTagged() throws {
        let json = try encodedText(ProbeEvent.stageStarted(.deepScan))
        #expect(json.contains("\"event\":\"stage_started\""))
        // snake_case throughout, matching the field keys.
        #expect(json.contains("\"stage\":\"deep_scan\""))
    }

    @Test("A report from an unknown schema is refused before it is trusted")
    func schemaIsChecked() throws {
        var report = ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: .now, target: Self.network, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            )
        )
        #expect(throws: Never.self) { try report.validateSchema() }

        // An OLDER document still validates. Schema 2 only added an enum case, so
        // every artifact this tool has previously written is still readable — including
        // everything the study's 1,580 schema-1 runs refer to.
        report.schema = 1
        #expect(throws: Never.self) { try report.validateSchema() }

        report.schema = 99
        // The constant, not a literal. This read `supported: 1` and had to be edited
        // when `open_filtered` bumped the schema to 2 — an edit that says nothing and
        // has to be made again every bump. What the test is for is that an unknown
        // version is REFUSED, and that survives the number changing.
        #expect(throws: SchemaError.unsupportedSchema(
            found: 99, supported: ScanReport.schemaVersion)) {
            try report.validateSchema()
        }
    }

    @Test("A timestamp encodes as a bare integer of milliseconds")
    func timestampIsAScalar() throws {
        let stamp = Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)
        #expect(try encodedText(stamp) == "1756700000000")
        #expect(try roundTrip(stamp) == stamp)
    }
}
