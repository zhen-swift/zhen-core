import Foundation
import Testing
@testable import ZhenCore

// A store written by an older build still loads, folds and compacts with nothing lost —
// and a store this build cannot fully read keeps what it cannot read.
//
// The history file is shared by every build that has ever been installed, and it is never
// rewritten to upgrade it. So the two directions both matter: this build reading what an
// older one wrote, and this build carrying through, untouched, what a newer one wrote.
@Suite("Old stores load, and unknown lines are kept")
struct MigrationTests {
    static let network = IPv4Network("10.10.20.0/24")!

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-migration-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func report(_ devices: [Device], at: Timestamp) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at,
                target: Self.network, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    private func device(ip: String, mac: String, at: Timestamp) -> Device {
        Device(
            observing: HostFacts(ip: IPv4Address(ip)!, mac: MACAddress(mac)),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    /// Records one run, appends `line` by hand, then records enough to compact.
    private func compactAround(_ line: String, in directory: URL) async throws -> String {
        let url = directory.appending(path: "history.ndjson")
        let first = Timestamp(millisecondsSinceEpoch: 1_000_000)
        _ = await LogHistoryStore(url: url).record(
            report([device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1", at: first)], at: first))
        let text = try String(contentsOf: url, encoding: .utf8)
        try (text + line + "\n").write(to: url, atomically: true, encoding: .utf8)

        // A threshold of one line, so the next record certainly rewrites from the ledger.
        let store = LogHistoryStore(url: url, compactionThreshold: 1)
        let later = Timestamp(millisecondsSinceEpoch: 2_000_000)
        _ = await store.record(
            report([device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1", at: later)], at: later))
        let after = try String(contentsOf: url, encoding: .utf8)
        #expect(after.split(separator: "\n").count <= 4, "the file was not compacted, so this proves nothing")
        return after
    }

    // ── The gate: a store 0.6.0 wrote ───────────────────────────────────────────────
    //
    // `Fixtures/history-0.6.0.ndjson` was written by zhen-core 0.6.0's own LogHistoryStore,
    // through `Scripts/make-history-fixture`, which is pinned to that exact release. It has
    // a deep scan, a discovery-only run, a move, a rename, a departure and a return, a MAC
    // rotation, a split record that 0.6.0 joined — which made 0.6.0 compact — and one line
    // from a later build that 0.6.0 carried through its compaction. What it says is read
    // here by plain JSON, independently of the decoder under test.

    /// What the fixture says, read without the store.
    private struct Expected {
        var macs: Set<String> = []
        var portsByMAC: [String: [String]] = [:]
        var eventIDs: [String] = []
        var latestRun: String?
        var foreign: [String] = []
    }

    private func readFixture() throws -> (text: String, expected: Expected) {
        let url = try #require(Bundle.module.url(
            forResource: "history-0.6.0", withExtension: "ndjson", subdirectory: "Fixtures"))
        let text = try String(contentsOf: url, encoding: .utf8)
        var expected = Expected()
        for line in text.split(separator: "\n") {
            let object = try #require(
                try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
            switch object["type"] as? String {
            case "device":
                let device = try #require((object["device"] as? [String: Any])?["device"] as? [String: Any])
                let mac = try #require(device["mac"] as? String)
                expected.macs.insert(mac)
                // Last line wins, as it does in the store.
                expected.portsByMAC[mac] = (device["ports"] as? [[String: Any]] ?? [])
                    .map { "\($0["port"] ?? "")/\($0["state"] ?? "")" }
            case "event":
                expected.eventIDs.append(try #require((object["event"] as? [String: Any])?["id"] as? String))
            case "run":
                expected.latestRun = (object["run"] as? [String: Any])?["id"] as? String
            default:
                expected.foreign.append(String(line))
            }
        }
        return (text, expected)
    }

    @Test("A store 0.6.0 wrote loads, folds and compacts with nothing lost")
    func sixPointOhStoreSurvives() async throws {
        let (text, expected) = try readFixture()
        #expect(expected.macs.count == 5 && expected.eventIDs.count == 11 && expected.foreign.count == 1,
                "the fixture is not the one this test was written against")
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        try text.write(to: url, atomically: true, encoding: .utf8)

        // ── Loads ──
        let loaded = LogHistoryStore(url: url)
        let devices = await loaded.devices()
        let events = await loaded.events()
        let latest = await loaded.latestRun()
        #expect(Set(devices.compactMap { $0.device.mac?.description }) == expected.macs)
        for device in devices {
            let mac = device.device.mac?.description ?? ""
            #expect(device.device.ports.map { "\($0.port)/\($0.state.rawValue)" } == expected.portsByMAC[mac],
                    "ports changed on the way in for \(mac)")
            #expect(device.macHistory.map(\.mac.description) == [mac],
                    "a 0.6.0 record was not seeded with its one MAC")
        }
        #expect(events.map(\.id.uuidString).sorted() == expected.eventIDs.sorted(), "an event did not load")
        #expect(latest?.id.uuidString == expected.latestRun)

        // ── Folds: a run with a port change and a departure, then a port scan ──
        let network = IPv4Network("10.10.20.0/24")!
        let day6 = Timestamp(millisecondsSinceEpoch: 1_788_220_800_000 + 6 * 86_400_000)
        func seen(_ ip: String, _ mac: String, name: String? = nil, ports: [(UInt16, PortState)] = []) -> Device {
            Device(
                observing: HostFacts(
                    ip: IPv4Address(ip)!, mac: MACAddress(mac),
                    allNames: name.map { [NameCandidate(value: $0, source: .mdns, rank: 1)] } ?? [],
                    ports: ports.map { PortObservation(port: $0.0, state: $0.1) }),
                in: network, firstSeen: day6, lastSeen: day6)
        }
        // A threshold of one line, so the fold certainly compacts.
        let store = LogHistoryStore(url: url, compactionThreshold: 1)
        let derived = await store.record(report([
            seen("10.10.20.1", "20:1C:3A:00:00:01"),
            seen("10.10.20.10", "20:1C:3A:00:00:10", name: "Archive", ports: [(22, .open), (445, .open)]),
            seen("10.10.20.42", "DA:00:00:00:00:03", name: "Pixel"),
            seen("10.10.20.60", "20:1C:3A:00:00:60", name: "Printer"),
        ], at: day6))
        #expect(derived.map(\.kind).sorted { $0.rawValue < $1.rawValue } == [.disappeared, .portOpened],
                "the fold of a new run over a 0.6.0 store derived the wrong events")
        let probed = await store.recordPorts(
            PortScanResult(ports: [.v4(IPv4Address("10.10.20.60")!): [PortObservation(port: 9100, state: .closed)]]),
            targeted: [.v4(IPv4Address("10.10.20.60")!)], at: day6)
        #expect(probed.map(\.kind) == [.portClosed])

        // ── Compacts, and nothing is lost ──
        let after = try String(contentsOf: url, encoding: .utf8)
        #expect(after.split(separator: "\n").count < text.split(separator: "\n").count + 10,
                "the file was not compacted, so this proves nothing")
        for line in expected.foreign {
            #expect(after.contains(line), "compaction erased the line a later build wrote")
        }
        let reopened = LogHistoryStore(url: url)
        let finalIDs = Set(await reopened.events().map(\.id.uuidString))
        #expect(Set(expected.eventIDs).isSubset(of: finalIDs), "compaction lost a 0.6.0 event")
        let finalDevices = await reopened.devices()
        #expect(Set(finalDevices.compactMap { $0.device.mac?.description }) == expected.macs,
                "compaction lost a 0.6.0 device")
        let tv = finalDevices.first { $0.device.mac?.description == "20:1C:3A:00:00:50" }
        #expect(tv?.device.ports.map(\.port) == [7000], "an absent device lost its last known ports")
        #expect(tv?.isPresent == false)
    }

    // ── What 0.6.0 got wrong, and 0.7.0 has to get right ─────────────────────────────
    //
    // 0.6.0 kept a line it could not DECODE, and dropped a line it could decode but not
    // understand: an event whose kind it did not know, a device whose key kind it did not
    // know. Those decode as a `Line` and were then skipped — so compaction erased them.
    // That is exactly how a 0.6.0 build erases 0.7.0's port events (questions, Q1), and
    // 0.7.0 adding kinds of its own is what makes the next build's kinds the same risk.

    @Test("An event kind this build does not know survives compaction")
    func unknownEventKindSurvives() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let line = #"{"v":1,"type":"event","event":{"id":"7F1C2E0A-3B4D-4E5F-8A9B-0C1D2E3F4A5B","at_millis":1500000,"kind":"portFlapped","subject":"NAS","detail":"22/tcp flapped","run_id":"0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D"}}"#
        let after = try await compactAround(line, in: directory)
        #expect(after.contains(line), "compaction erased an event a later build wrote")
    }

    @Test("A device whose key kind this build does not know survives compaction")
    func unknownKeyKindSurvives() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        // A real device line, re-keyed by an identifier kind no build has yet.
        let at = Timestamp(millisecondsSinceEpoch: 1_000_000)
        _ = await LogHistoryStore(url: url).record(
            report([device(ip: "10.10.20.9", mac: "20:1C:3A:00:00:09", at: at)], at: at))
        let written = try String(contentsOf: url, encoding: .utf8)
        let deviceLine = try #require(written.split(separator: "\n").first { $0.contains(#""type":"device""#) })
        let future = String(deviceLine)
            .replacing(#""key":"universal_mac|20:1C:3A:00:00:09""#, with: #""key":"wifi_aware_id|abc""#)
        #expect(future != String(deviceLine), "the fixture edit did not apply")
        try FileManager.default.removeItem(at: url)

        let after = try await compactAround(future, in: directory)
        #expect(after.contains(future), "compaction erased a device keyed by a later build's kind")
    }
}
