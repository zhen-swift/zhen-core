import Foundation
import Testing
@testable import ZhenCore

// Schema 3: a device is a set of addresses.
//
// The fixtures are real. `report-schema1.json` is a pilot run from the frozen study,
// copied rather than referenced so the study stays untouched. `report-schema2.json` was
// captured from the development network by the build immediately before this change, and
// committed with it, so the migration is checked against what the old writer actually wrote
// rather than against what this code expects it to have written. Before the repository went
// public its device names and hardware addresses were replaced with synthetic values of the
// same shape — vendor prefixes, address classes and lengths kept — and nothing structural.

private let network = IPv4Network("10.10.20.0/24")!
private let at = Timestamp(millisecondsSinceEpoch: 1_790_000_000_000)

private func fixture(_ name: String) throws -> Data {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try Data(contentsOf: url)
}

private let noEvidence = IdentificationEvidence(
    hasDistinctName: false, nameSourceIsSelfSufficient: false, hasModel: false,
    hasVendor: false, hasOSHint: false, independentSources: 0
)

private func device(
    _ addresses: [String], mac: String?, ports: [PortObservation] = [],
    names: [NameCandidate] = [], stability: Stability = .strong
) -> Device {
    Device(
        addresses: Set(addresses.map { IPAddress($0)! }),
        mac: mac.flatMap(MACAddress.init),
        names: names,
        identification: .minimal, identificationEvidence: noEvidence,
        identityStability: stability, ports: ports,
        firstSeen: at, lastSeen: at
    )
}

private func report(_ devices: [Device]) -> ScanReport {
    ScanReport(
        run: ScanRun(
            id: UUID(), startedAt: at, finishedAt: at, target: network, interface: "en0",
            engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing()
        ),
        devices: devices
    )
}

@Suite("Schema 3 reads every schema before it")
struct SchemaMigrationTests {
    /// The old document, parsed without this build's types, so the check does not agree
    /// with itself.
    private func rawDevices(_ data: Data) throws -> [[String: Any]] {
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try #require(object["devices"] as? [[String: Any]])
    }

    @Test("A schema-1 document loads, and every device keeps its one address",
          arguments: ["report-schema1", "report-schema2"])
    func legacyDocumentsLoad(name: String) throws {
        let data = try fixture(name)
        let raw = try rawDevices(data)
        let report = try ScanReport.decoded(from: data)

        #expect(report.devices.count == raw.count)
        #expect(!raw.isEmpty, "a fixture with no devices would pass this vacuously")
        let written = Set(raw.compactMap { $0["ip"] as? String })
        let read = Set(report.devices.map(\.primaryAddress.description))
        #expect(written == read)
        for device in report.devices {
            #expect(device.addresses.count == 1)
            // Every port was made on the device's only address, and says so now.
            for port in device.ports { #expect(port.address == device.primaryAddress) }
        }
    }

    @Test("The schema-2 fixture has ports, so the stamping is exercised")
    func fixtureIsNotVacuous() throws {
        let report = try ScanReport.decoded(from: try fixture("report-schema2"))
        #expect(report.schema == 2)
        #expect(report.devices.flatMap(\.ports).count > 0)
    }

    @Test("A migrated document re-encodes as schema 3 and survives a second read unchanged")
    func migrationIsAFixedPoint() throws {
        var once = try ScanReport.decoded(from: try fixture("report-schema2"))
        once.schema = ScanReport.schemaVersion
        let encoded = try once.encoded()
        let text = try #require(String(data: encoded, encoding: .utf8))
        #expect(!text.contains(#""ip":"#), "schema 3 writes no `ip`")
        #expect(text.contains(#""addresses":["#))
        let twice = try ScanReport.decoded(from: encoded)
        #expect(twice == once)
        #expect(try twice.encoded() == encoded)
    }

    @Test("A schema newer than this build is still refused")
    func newerIsRefused() throws {
        let data = try fixture("report-schema2")
        var text = try #require(String(data: data, encoding: .utf8))
        text = text.replacingOccurrences(of: #""schema":2"#, with: #""schema":4"#)
        #expect(throws: SchemaError.self) { try ScanReport.decoded(from: Data(text.utf8)) }
    }

    @Test("A device with an empty address list is refused, not read as addressless")
    func emptyAddressesAreRefused() {
        let json = #"{"addresses":[],"names":[],"identification":"minimal","identification_evidence":{"has_distinct_name":false,"name_source_is_self_sufficient":false,"has_model":false,"has_vendor":false,"has_os_hint":false,"independent_sources":0},"identity_stability":"weak","ports":[],"first_seen":0,"last_seen":0}"#
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(Device.self, from: Data(json.utf8))
        }
    }

    @Test("Addresses encode in one order however the set was built")
    func addressOrderIsCanonical() throws {
        let forward = device(["10.10.20.5", "fe80::1%en0", "2001:db8::5"], mac: nil)
        let backward = device(["2001:db8::5", "fe80::1%en0", "10.10.20.5"], mac: nil)
        let encoder = ScanReport.makeEncoder()
        let text = try #require(String(data: try encoder.encode(forward), encoding: .utf8))
        #expect(try encoder.encode(forward) == encoder.encode(backward))
        #expect(text.contains(#""addresses":["10.10.20.5","2001:db8::5","fe80::1%en0"]"#))
        #expect(forward.primaryAddress == IPAddress("10.10.20.5"))
    }
}

@Suite("One host at three addresses is one device")
struct FusionTests {
    private let mac = "F2:11:22:33:44:55"

    @Test("One v4 and two v6 addresses sharing a MAC fuse into one device")
    func threeAddressesOneDevice() throws {
        let fused = Device.fusing([
            device(["10.10.20.40"], mac: mac,
                   ports: [PortObservation(port: 22, state: .open, address: IPAddress("10.10.20.40"))]),
            device(["fe80::f011:22ff:fe33:4455%en0"], mac: mac,
                   ports: [PortObservation(port: 22, state: .filtered, address: IPAddress("fe80::f011:22ff:fe33:4455%en0"))]),
            device(["2001:db8::40"], mac: mac),
        ])
        #expect(fused.count == 1)
        let one = try #require(fused.first)
        #expect(one.addresses.count == 3)
        #expect(one.primaryAddress == IPAddress("10.10.20.40"))
        // 22/tcp on two families disagreeing is two observations, not one.
        #expect(one.ports.count == 2)
        #expect(Set(one.ports.map(\.state)) == [.open, .filtered])
        #expect(one.portsByAddress.count == 2)
    }

    @Test("The fused device is one record in the history, not three")
    func historyKeepsOne() {
        let fused = Device.fusing([
            device(["10.10.20.40"], mac: mac),
            device(["fe80::f011:22ff:fe33:4455%en0"], mac: mac),
            device(["2001:db8::40"], mac: mac),
        ])
        var ledger = HistoryLedger()
        ledger.record(report(fused))
        #expect(ledger.devices().count == 1)
        #expect(ledger.devices().first?.device.addresses.count == 3)
    }

    @Test("Two v4 addresses behind one MAC stay two devices, as they were in schema 2")
    func proxyARPIsNotFused() {
        // A router answering ARP for the hosts behind it. Fusing these would re-mean every
        // earlier document on read.
        let fused = Device.fusing([
            device(["10.10.20.1"], mac: mac),
            device(["10.10.20.2"], mac: mac),
            device(["fe80::1%en0"], mac: mac),
        ])
        #expect(fused.count == 3)
    }

    @Test("Without a MAC there is no evidence of one interface, so nothing fuses")
    func noMACNoFusion() {
        let fused = Device.fusing([
            device(["10.10.20.40"], mac: nil),
            device(["fe80::40%en0"], mac: nil),
        ])
        #expect(fused.count == 2)
    }

    @Test("Fusion recomputes identification from the union, not from one part")
    func identificationFromTheUnion() throws {
        let named = device(["fe80::40%en0"], mac: mac,
                           names: [NameCandidate(value: "Office Mac", source: .mdns)])
        let fused = try #require(Device.fusing([device(["10.10.20.40"], mac: mac), named]).first)
        #expect(fused.displayName == "Office Mac")
        #expect(fused.identification == .identified)
    }
}

// ── The real store ──────────────────────────────────────────────────────────────────
//
// Opt-in, because the store is the maintainer's own and lives outside the repository. Point the
// variables at COPIES:
//
//   ZHEN_VERIFY_STORES=/path/a.ndjson:/path/b.ndjson
//   ZHEN_VERIFY_REPORTS=/path/to/a/directory/of/reports
//
// Every line of every store must decode, and every device line must migrate to exactly
// what an independent reading of the old JSON says it should be. Skipped — and shown as
// skipped — when the variables are unset.

private let storePaths = ProcessInfo.processInfo.environment["ZHEN_VERIFY_STORES"]?
    .split(separator: ":").map(String.init) ?? []
private let reportRoot = ProcessInfo.processInfo.environment["ZHEN_VERIFY_REPORTS"]

@Suite("The real history reads back")
struct RealStoreTests {
    @Test("Every line of every store decodes, and every device migrates faithfully",
          .enabled(if: !storePaths.isEmpty))
    func everyLineReadsBack() throws {
        var total = 0, devices = 0, legacy = 0, current = 0
        for path in storePaths {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            var lines = 0, decoded = 0
            for line in data.split(separator: UInt8(ascii: "\n")) where !line.isEmpty {
                lines += 1
                let entry = try JSONDecoder().decode(LogHistoryStore.Line.self, from: Data(line))
                decoded += 1
                guard case .device(let stored) = entry.payload else { continue }
                devices += 1
                // The independent reading: the raw JSON, no Device type involved.
                let object = try #require(try JSONSerialization.jsonObject(with: Data(line)) as? [String: Any])
                let raw = try #require((object["device"] as? [String: Any])?["device"] as? [String: Any])
                if let ip = raw["ip"] as? String {
                    legacy += 1
                    #expect(stored.device.addresses == [IPAddress(ip)!], "\(path): \(ip)")
                    let rawPorts = raw["ports"] as? [[String: Any]] ?? []
                    #expect(stored.device.ports.count == rawPorts.count)
                    #expect(stored.device.ports.allSatisfy { $0.address == IPAddress(ip) })
                    #expect(stored.device.names.count == (raw["names"] as? [Any])?.count ?? 0)
                    #expect(stored.device.mac?.description == raw["mac"] as? String)
                } else {
                    current += 1
                    let written = try #require(raw["addresses"] as? [String])
                    #expect(stored.device.addresses == Set(written.map { IPAddress($0)! }))
                }
            }
            #expect(decoded == lines, "\(path): \(lines - decoded) lines did not decode")
            total += lines
            print("store \(path): \(lines) lines, all decoded")
        }
        print("stores: \(total) lines, \(devices) device records (\(legacy) schema 1/2, \(current) schema 3)")
        #expect(total > 0)
    }

    @Test("Every report under the directory decodes", .enabled(if: reportRoot != nil))
    func everyReportDecodes() throws {
        let root = URL(fileURLWithPath: try #require(reportRoot))
        let walker = try #require(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
        var bySchema: [Int: Int] = [:]
        var devices = 0, stubs = 0
        for case let url as URL in walker where ["json", "out"].contains(url.pathExtension) {
            guard let data = try? Data(contentsOf: url),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let schema = object["schema"] as? Int, object["devices"] != nil
            else { continue }   // not a report: study metadata, captures, nmap XML
            // The study's dry-run harness wrote stubs shaped like reports with
            // `"run":{"id":"stub"}`. No build of zhen ever read them — the build before
            // schema 3 refuses them on `run.id` exactly as this one does — so they are
            // counted and named, not decoded.
            if let run = object["run"] as? [String: Any], let id = run["id"] as? String,
               UUID(uuidString: id) == nil {
                stubs += 1
                continue
            }
            let report = try ScanReport.decoded(from: data)
            #expect(report.devices.count == (object["devices"] as? [Any])?.count, "\(url.path)")
            bySchema[schema, default: 0] += 1
            devices += report.devices.count
        }
        print("reports: \(bySchema.sorted { $0.key < $1.key }.map { "schema \($0.key): \($0.value)" }.joined(separator: ", ")), \(devices) devices; \(stubs) harness stubs with no run id, not reports")
        #expect(!bySchema.isEmpty)
    }
}
