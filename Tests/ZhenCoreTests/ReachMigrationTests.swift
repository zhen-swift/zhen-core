// ReachMigrationTests.swift — gate G2 of 0.8.0, and the fixture half of G1.
//
// Three files, every line of each written by a real build's own `LogHistoryStore`:
//
//   history-0.7.0.ndjson                     zhen-core 0.7.0, `Scripts/make-history-fixture-0.7.0 write`
//   history-0.8.0.ndjson                     this build, on top of that one, six days with
//                                            first-contact times and one compaction
//                                            (`Scripts/make-history-fixture-0.8.0`)
//   history-0.8.0-rewritten-by-0.7.0.ndjson  0.7.0 again: the 0.8.0 file opened, one run
//                                            folded and compacted (`… -0.7.0 rewrite`)
//
// The third is the one that matters most. The app is pinned to 0.7.0 and shares this file
// with the command line, so a 0.7.0 compaction of a history 0.8.0 wrote is not a corner
// case; it is the next thing that happens on JC's machine. What each file says is read
// here by plain JSON, independently of the decoder under test.

import Foundation
import Testing
@testable import ZhenCore

@Suite("History across 0.7.0 and 0.8.0 (G2)")
struct ReachMigrationTests {
    static let network = IPv4Network("10.10.20.0/24")!

    /// The generators' clock: 2026-10-01T00:00:00Z, and a day per step.
    static func day(_ number: Int) -> Timestamp {
        Timestamp(millisecondsSinceEpoch: 1_790_812_800_000 + Int64(number) * 86_400_000)
    }

    /// What a fixture says, read without the store.
    private struct Expected {
        var text = ""
        var macs: Set<String> = []
        var portsByMAC: [String: [String]] = [:]
        var macHistoryByMAC: [String: [String]] = [:]
        var samplesByKey: [String: [FirstContactSample]] = [:]
        var eventIDs: Set<String> = []
        var latestRun: String?
        /// Lines whose type is neither device, event, run nor first_contact.
        var foreign: [String] = []
        var firstContactLines = 0
    }

    private func fixture(_ name: String) throws -> Expected {
        let url = try #require(Bundle.module.url(
            forResource: name, withExtension: "ndjson", subdirectory: "Fixtures"))
        var expected = Expected()
        expected.text = try String(contentsOf: url, encoding: .utf8)
        for line in expected.text.split(separator: "\n") {
            let object = try #require(
                try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
            switch object["type"] as? String {
            case "device":
                let stored = try #require(object["device"] as? [String: Any])
                let device = try #require(stored["device"] as? [String: Any])
                let mac = try #require(device["mac"] as? String)
                expected.macs.insert(mac)
                // Last line wins, as it does in the store.
                expected.portsByMAC[mac] = (device["ports"] as? [[String: Any]] ?? [])
                    .map { "\($0["port"] ?? "")/\($0["state"] ?? "")" }
                expected.macHistoryByMAC[mac] = (stored["mac_history"] as? [[String: Any]] ?? [])
                    .compactMap { $0["mac"] as? String }
            case "first_contact":
                expected.firstContactLines += 1
                let stored = try #require(object["first_contact"] as? [String: Any])
                let key = try #require(stored["key"] as? String)
                expected.samplesByKey[key] = try #require(stored["first_contact_samples"] as? [[String: Any]])
                    .map { FirstContactSample(millis: ($0["millis"] as? Double) ?? -1, cold: ($0["cold"] as? Bool) ?? false) }
            case "event":
                expected.eventIDs.insert(try #require((object["event"] as? [String: Any])?["id"] as? String))
            case "run":
                expected.latestRun = (object["run"] as? [String: Any])?["id"] as? String
            default:
                expected.foreign.append(String(line))
            }
        }
        return expected
    }

    private func copy(_ expected: Expected) throws -> (URL, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-reach-migration-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appending(path: "history.ndjson")
        try expected.text.write(to: url, atomically: true, encoding: .utf8)
        return (directory, url)
    }

    private func report(_ devices: [Device], at: Timestamp) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at, target: Self.network, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, mode: .discoveryOnly, timing: Timing()
            ),
            devices: devices
        )
    }

    private func seen(_ ip: String, _ mac: String, name: String? = nil, contact: Double, at: Timestamp) -> Device {
        Device(
            observing: HostFacts(
                ip: IPv4Address(ip)!, mac: MACAddress(mac),
                allNames: name.map { [NameCandidate(value: $0, source: .mdns, rank: 1)] } ?? [],
                discoveredVia: [.probeReply],
                firstContact: .milliseconds(contact), firstContactCold: true
            ),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    /// Samples by the key of the record that holds them, as the store sees it.
    private func samples(in devices: [StoredDevice], keyedBy expected: Expected) -> [String: [FirstContactSample]] {
        // A record's key is not on `StoredDevice`; the MAC is, and in these fixtures each
        // record has one current MAC, so the fixture's key → MAC map joins the two.
        var keyByMAC: [String: String] = [:]
        for line in expected.text.split(separator: "\n") {
            guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  object["type"] as? String == "device",
                  let stored = object["device"] as? [String: Any],
                  let key = stored["key"] as? String,
                  let mac = (stored["device"] as? [String: Any])?["mac"] as? String
            else { continue }
            keyByMAC[mac] = key
        }
        var result: [String: [FirstContactSample]] = [:]
        for device in devices where !device.firstContactSamples.isEmpty {
            guard let mac = device.device.mac?.description, let key = keyByMAC[mac] else { continue }
            result[key] = device.firstContactSamples
        }
        return result
    }

    // ── A store 0.7.0 wrote, opened by this build ───────────────────────────────────

    @Test("A store 0.7.0 wrote loads, folds and compacts with nothing lost")
    func sevenPointOhStoreSurvives() async throws {
        let expected = try fixture("history-0.7.0")
        #expect(expected.macs.count == 5 && expected.eventIDs.count == 11
                && expected.foreign.count == 1 && expected.firstContactLines == 0,
                "the fixture is not the one this test was written against")
        let (directory, url) = try copy(expected)
        defer { try? FileManager.default.removeItem(at: directory) }

        // ── Loads ──
        let loaded = LogHistoryStore(url: url)
        let devices = await loaded.devices()
        #expect(Set(devices.compactMap { $0.device.mac?.description }) == expected.macs)
        for device in devices {
            let mac = device.device.mac?.description ?? ""
            #expect(device.device.ports.map { "\($0.port)/\($0.state.rawValue)" } == expected.portsByMAC[mac],
                    "ports changed on the way in for \(mac)")
            #expect(device.macHistory.map(\.mac.description) == expected.macHistoryByMAC[mac],
                    "mac_history changed on the way in for \(mac)")
            #expect(device.firstContactSamples.isEmpty, "a 0.7.0 record came in with samples it never had")
        }
        #expect(Set(await loaded.events().map(\.id.uuidString)) == expected.eventIDs)
        #expect(await loaded.latestRun()?.id.uuidString == expected.latestRun)

        // ── Folds a run with first-contact times, and compacts ──
        let day6 = Self.day(6)
        let store = LogHistoryStore(url: url, compactionThreshold: 1)
        let derived = await store.record(report([
            seen("10.10.20.1", "20:1C:3A:00:00:01", contact: 212, at: day6),
            seen("10.10.20.10", "20:1C:3A:00:00:10", name: "Storage", contact: 230.5, at: day6),
            seen("10.10.20.42", "DA:00:00:00:00:03", name: "Pixel", contact: 640, at: day6),
            seen("10.10.20.60", "20:1C:3A:00:00:60", name: "Printer", contact: 981, at: day6),
        ], at: day6))
        #expect(derived.map(\.kind) == [.disappeared], "the TV, and nothing else")

        // ── Nothing lost ──
        let after = try String(contentsOf: url, encoding: .utf8)
        #expect(after.split(separator: "\n").count < expected.text.split(separator: "\n").count + 8,
                "the file was not compacted, so this proves nothing")
        for line in expected.foreign {
            #expect(after.contains(line), "compaction erased the line a later build wrote")
        }
        let reopened = LogHistoryStore(url: url)
        #expect(expected.eventIDs.isSubset(of: Set(await reopened.events().map(\.id.uuidString))),
                "compaction lost a 0.7.0 event")
        let final = await reopened.devices()
        #expect(Set(final.compactMap { $0.device.mac?.description }) == expected.macs, "compaction lost a device")
        for device in final {
            let mac = device.device.mac?.description ?? ""
            #expect(device.macHistory.map(\.mac.description) == expected.macHistoryByMAC[mac],
                    "compaction changed mac_history for \(mac)")
        }
        let printer = final.first { $0.device.mac?.description == "20:1C:3A:00:00:60" }
        #expect(printer?.firstContactSamples == [FirstContactSample(millis: 981, cold: true)])
        let tv = final.first { $0.device.mac?.description == "20:1C:3A:00:00:50" }
        #expect(tv?.firstContactSamples == [], "an absent device was given a sample")
        #expect(tv?.device.ports.map(\.port) == [7000], "an absent device lost its last known ports")
    }

    // ── A store this build wrote, and what 0.7.0 does to it ─────────────────────────

    @Test("This build reads back every sample it wrote, across its own compaction")
    func eightPointOhStoreLoads() async throws {
        let expected = try fixture("history-0.8.0")
        #expect(expected.samplesByKey.count == 5 && expected.foreign.count == 1,
                "the fixture is not the one this test was written against")
        let (directory, url) = try copy(expected)
        defer { try? FileManager.default.removeItem(at: directory) }
        let devices = await LogHistoryStore(url: url).devices()
        #expect(samples(in: devices, keyedBy: expected) == expected.samplesByKey)
        #expect(devices.map(\.firstContactSamples.count).reduce(0, +) == 29)
    }

    @Test("A 0.7.0 compaction keeps first_contact_samples, and this build reads them back")
    func oldReaderPreservesSamples() async throws {
        let written = try fixture("history-0.8.0")
        let rewritten = try fixture("history-0.8.0-rewritten-by-0.7.0")

        // 0.7.0 carried every samples line, byte for byte, and the foreign line too.
        let writtenLines = written.text.split(separator: "\n")
        let rewrittenLines = Set(rewritten.text.split(separator: "\n"))
        for line in writtenLines where line.contains(#""type":"first_contact""#) || line.contains(#""annotation""#) {
            #expect(rewrittenLines.contains(line), "0.7.0's compaction dropped: \(line.prefix(80))…")
        }
        #expect(rewritten.firstContactLines == written.firstContactLines)
        #expect(rewritten.samplesByKey == written.samplesByKey)

        // 0.7.0 rewrote the device lines itself, ahead of the lines it kept — so every
        // samples line now comes AFTER its device line's replacement, which is what
        // `reload` joins after reading everything.
        let (directory, url) = try copy(rewritten)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = LogHistoryStore(url: url)
        let devices = await store.devices()
        #expect(samples(in: devices, keyedBy: rewritten) == written.samplesByKey,
                "a sample was lost or reattached on the way through 0.7.0")
        // And 0.7.0's own fold is not lost: its run is the latest, and the TV it saw is back.
        #expect(await store.latestRun()?.id.uuidString == rewritten.latestRun)
        #expect(rewritten.latestRun != written.latestRun)
        #expect(devices.first { $0.device.mac?.description == "20:1C:3A:00:00:50" }?.isPresent == true)
        #expect(written.eventIDs.isSubset(of: Set(await store.events().map(\.id.uuidString))))
    }

    // ── G1, from a fixture store ────────────────────────────────────────────────────

    @Test("The expected set and the cold samples come from a real store")
    func planFromFixtureStore() async throws {
        let expected = try fixture("history-0.8.0")
        let (directory, url) = try copy(expected)
        defer { try? FileManager.default.removeItem(at: directory) }
        let devices = await LogHistoryStore(url: url).devices()
        let addresses = (1...254).map { IPv4Address("10.10.20.\($0)")! }
        // The fixture's cold samples, read without the store.
        let cold = expected.samplesByKey.values.flatMap { $0 }.filter(\.cold).map(\.millis)
        #expect(cold.count == 24, "the fixture is not the one this test was written against")

        // The default 30-day window covers the fixture's eleven days: every device seen
        // here is expected, at its CURRENT address only — the phone's earlier .40 and .41
        // are not.
        let now = Timestamp(millisecondsSinceEpoch: Self.day(11).millisecondsSinceEpoch + 3_600_000)
        let plan = ReachPlan.make(
            addresses: addresses, network: Self.network, devices: devices,
            policy: .default, now: now
        )
        let five: Set<IPv4Address> = Set(["10.10.20.1", "10.10.20.10", "10.10.20.42", "10.10.20.50", "10.10.20.60"]
            .map { IPv4Address($0)! })
        #expect(plan.expected == five)
        #expect(!plan.firstScan)
        #expect(plan.historySamples == 24)
        // Nearest rank: ceil(0.97 × 24) = 24, the slowest cold sample — the printer's 1,034 ms.
        #expect(plan.expectedWait == .milliseconds(1_034))
        #expect(plan.expectedWait == .milliseconds(try #require(cold.max())))
        #expect(plan.wait(for: IPv4Address("10.10.20.60")!) == .milliseconds(1_034))
        #expect(plan.attempts(for: IPv4Address("10.10.20.60")!) == 4)
        #expect(plan.wait(for: IPv4Address("10.10.20.41")!) == .zero)
        #expect(plan.attempts(for: IPv4Address("10.10.20.41")!) == 3)

        // A one-day window: the TV, last seen on day 10, is no longer expected — but its
        // samples still teach the network's wait.
        let recent = ReachPlan.make(
            addresses: addresses, network: Self.network, devices: devices,
            policy: .default, settings: ReachSettings(expectedWindow: .seconds(86_400)), now: now
        )
        #expect(recent.expected == five.subtracting([IPv4Address("10.10.20.50")!]))
        #expect(recent.historySamples == 24)

        // Another network's history says nothing about this one.
        let elsewhere = ReachPlan.make(
            addresses: (1...254).map { IPv4Address("10.10.40.\($0)")! },
            network: IPv4Network("10.10.40.0/24")!, devices: devices,
            policy: .default, now: now
        )
        #expect(elsewhere.expected.isEmpty && elsewhere.firstScan && elsewhere.historySamples == 0)
    }
}
