// FirstContactHistoryTests.swift — change 3 of 0.8.0: first-contact time, and its history.
//
// The time is measured in the sweep (ZhenDarwin's tests time it). What is checked here is
// the half that is easy to lose silently: that the time reaches the artifact under the
// brief's keys, that the history keeps the newest 32 per device, and that the samples
// survive a reopen and a compaction of the file.

import Foundation
import Testing
@testable import ZhenCore

@Suite("First contact, and its history")
struct FirstContactHistoryTests {
    static let network = IPv4Network("10.10.20.0/24")!

    private func temporaryURL() throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zhen-contact-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("history.ndjson")
    }

    private func device(_ last: UInt8, millis: Double?, cold: Bool = true, at: Timestamp) -> Device {
        Device(
            observing: HostFacts(
                ip: IPv4Address(raw: 0x0A0A_1400 | UInt32(last)),
                mac: MACAddress(raw: 0x2000_0000_0000 | UInt64(last)),
                firstContact: millis.map { .milliseconds($0) },
                firstContactCold: millis == nil ? nil : cold
            ),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    private func report(_ devices: [Device], at: Timestamp) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at, target: Self.network, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    private func at(_ run: Int) -> Timestamp { Timestamp(millisecondsSinceEpoch: 1_000_000 + Int64(run) * 60_000) }

    @Test("Each host carries first_contact_millis and first_contact_cold in the report")
    func reportKeys() throws {
        let report = report([device(12, millis: 987.5, at: at(0)), device(1, millis: nil, at: at(0))], at: at(0))
        let text = String(decoding: try report.encoded(), as: UTF8.self)
        #expect(text.contains(#""first_contact_cold":true"#))
        #expect(text.contains(#""first_contact_millis":987.5"#))
        let decoded = try ScanReport.decoded(from: Data(text.utf8))
        #expect(decoded.devices.map(\.firstContactMillis) == [nil, 987.5])
        #expect(decoded.devices.map(\.firstContactCold) == [nil, true])
    }

    @Test("A HostFacts event carries the same two keys")
    func hostFactsKeys() throws {
        let facts = HostFacts(ip: IPv4Address("10.10.20.12")!, firstContact: .milliseconds(480), firstContactCold: false)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let text = String(decoding: try encoder.encode(facts), as: UTF8.self)
        #expect(text.contains(#""first_contact_cold":false,"first_contact_millis":480"#))
        let back = try JSONDecoder().decode(HostFacts.self, from: Data(text.utf8))
        #expect(back.firstContact == .milliseconds(480))
        #expect(back.firstContactCold == false)
        // A cold flag with no time is not a measurement.
        #expect(HostFacts(ip: facts.ip, firstContactCold: true).firstContactCold == nil)
    }

    @Test("The ledger keeps the newest 32 samples per device, cold and warm alike")
    func ledgerRetains32() {
        var ledger = HistoryLedger()
        for run in 0..<40 {
            ledger.record(report([device(12, millis: Double(run), cold: run.isMultiple(of: 2), at: at(run))], at: at(run)))
        }
        let samples = ledger.devices()[0].firstContactSamples
        #expect(samples.count == 32)
        #expect(samples.first?.millis == 8)
        #expect(samples.last?.millis == 39)
        #expect(samples.filter(\.cold).count == 16)
    }

    @Test("A run without a time adds no sample, and loses none")
    func untimedRunAddsNothing() {
        var ledger = HistoryLedger()
        ledger.record(report([device(12, millis: 900, at: at(0))], at: at(0)))
        ledger.record(report([device(12, millis: nil, at: at(1))], at: at(1)))
        // Stamped with the run that measured it (F10).
        #expect(ledger.devices()[0].firstContactSamples == [FirstContactSample(millis: 900, cold: true, at: at(0))])
    }

    @Test("Samples survive a reopen and a compaction, written as their own line")
    func survivesTheFile() async throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = LogHistoryStore(url: url, compactionThreshold: 6)
        for run in 0..<5 {
            _ = await store.record(report([
                device(12, millis: 1_000 + Double(run), at: at(run)),
                device(13, millis: 400, cold: false, at: at(run)),
            ], at: at(run)))
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.contains(#""type":"first_contact""#))
        #expect(text.contains(#""first_contact_samples":[{"#))

        let reopened = await LogHistoryStore(url: url).devices()
        let twelve = reopened.first { $0.device.ipv4Addresses == [IPv4Address("10.10.20.12")!] }
        #expect(twelve?.firstContactSamples.map(\.millis) == [1_000, 1_001, 1_002, 1_003, 1_004])
        let thirteen = reopened.first { $0.device.ipv4Addresses == [IPv4Address("10.10.20.13")!] }
        #expect(thirteen?.firstContactSamples.allSatisfy { !$0.cold } == true)
    }

    @Test("A samples line ahead of its device line, or under a merged-away key, still joins")
    func joinsAcrossOrderAndMerge() async throws {
        // What an older build's compaction leaves: its snapshot first, the samples lines
        // it could not read after it — and if it merged two records, a samples line keyed
        // by the loser.
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = LogHistoryStore(url: url)
        _ = await store.record(report([device(12, millis: 700, at: at(0))], at: at(0)))
        var lines = try String(contentsOf: url, encoding: .utf8).split(separator: "\n").map(String.init)
        let samplesLine = try #require(lines.firstIndex { $0.contains(#""type":"first_contact""#) })
        let moved = lines.remove(at: samplesLine)
        // Rekey the samples line to an identifier the record carries but is not keyed by.
        let record = try #require(lines.first { $0.contains(#""type":"device""#) })
        let lease = try #require(record.firstRange(of: #"ip_lease|10.10.20.0\/24@10.10.20.12"#))
        let rekeyed = moved.replacing(#/"key":"[^"]*"/#, with: "\"key\":\"\(record[lease])\"")
        lines.insert(rekeyed, at: 0)
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)

        let devices = await LogHistoryStore(url: url).devices()
        #expect(devices.first?.firstContactSamples == [FirstContactSample(millis: 700, cold: true, at: at(0))])
    }
}
