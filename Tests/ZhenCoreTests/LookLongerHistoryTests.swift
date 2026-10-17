// LookLongerHistoryTests.swift — change 5 of 0.8.0, and the fixture half of gate G7.
//
// G7: look longer on a host taken down and then brought back — it appears, and nobody
// else is marked absent. The sweep half is the ordinary ICMP sweep under a `.fixed`
// plan (ZhenDarwin's reach tests); what is checked here is the half that would quietly
// rewrite the network if it were wrong: what history does with an extension.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Look longer extends the latest run (G7, fixture)")
struct LookLongerHistoryTests {
    static let network = IPv4Network("10.10.20.0/24")!

    static func at(_ minute: Int) -> Timestamp {
        Timestamp(millisecondsSinceEpoch: 1_790_812_800_000 + Int64(minute) * 60_000)
    }

    private func device(_ last: UInt8, name: String? = nil, ports: [UInt16] = [],
                        contact: Double? = nil, at: Timestamp) -> Device {
        Device(
            observing: HostFacts(
                ip: IPv4Address(raw: 0x0A0A_1400 | UInt32(last)),
                mac: MACAddress(raw: 0x2000_0000_0000 | UInt64(last)),
                allNames: name.map { [NameCandidate(value: $0, source: .mdns, rank: 1)] } ?? [],
                ports: ports.map { PortObservation(port: $0, state: .open) },
                discoveredVia: [.probeReply],
                firstContact: contact.map { .milliseconds($0) },
                firstContactCold: contact == nil ? nil : true
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

    /// Two runs: the phone (.42) answers the first and is down for the second.
    private func twoRuns(into ledger: inout HistoryLedger) -> ScanRun {
        ledger.record(report([
            device(1, at: Self.at(0)), device(10, name: "Storage", ports: [22, 445], at: Self.at(0)),
            device(42, name: "Pixel", ports: [62078], at: Self.at(0)), device(60, at: Self.at(0)),
        ], at: Self.at(0)))
        let second = report([
            device(1, at: Self.at(10)), device(10, name: "Storage", ports: [22, 445], at: Self.at(10)),
            device(60, at: Self.at(10)),
        ], at: Self.at(10))
        let events = ledger.record(second)
        #expect(events.map(\.kind) == [.disappeared], "the phone went down for the second run")
        return second.run
    }

    @Test("The host that came back appears, in the latest run; nobody else is marked absent")
    func cameBack() {
        var ledger = HistoryLedger()
        let run = twoRuns(into: &ledger)
        let before = ledger.devices()

        // Look longer, and the phone answers — with no name and no ports, as a sweep sees it.
        let fold = ledger.foldExtension([device(42, contact: 2_400, at: Self.at(11))], of: run.id)
        #expect(fold.events.map(\.kind) == [.appeared])
        #expect(fold.events.first?.subject == "Pixel")
        #expect(fold.events.first?.runID == run.id, "the event belongs to the run it extends")
        #expect(fold.updatedRecords == 1)

        let after = ledger.devices()
        #expect(after.filter(\.isPresent).count == 4, "everyone the run saw, plus the phone")
        // Nobody else changed at all.
        for device in before where device.device.ipv4Addresses != [IPv4Address("10.10.20.42")!] {
            #expect(after.contains(device), "look longer changed \(device.device.primaryAddress)")
        }
        // The latest run is still the latest run.
        #expect(ledger.latestRun == run)
        // The phone keeps what a sweep cannot see, and gains what it saw.
        let phone = try! #require(after.first { $0.device.ipv4Addresses == [IPv4Address("10.10.20.42")!] })
        #expect(phone.isPresent)
        #expect(phone.device.displayName == "Pixel")
        #expect(phone.device.ports.map(\.port) == [62078])
        #expect(phone.device.lastSeen == Self.at(11))
        #expect(phone.firstContactSamples == [FirstContactSample(millis: 2_400, cold: true, at: Self.at(11))])
    }

    @Test("A device the network never had joins the latest run")
    func newDevice() {
        var ledger = HistoryLedger()
        let run = twoRuns(into: &ledger)
        let fold = ledger.foldExtension([device(77, at: Self.at(11))], of: run.id)
        #expect(fold.events.map(\.kind) == [.appeared])
        #expect(fold.events.first?.detail == "joined at 10.10.20.77")
        #expect(ledger.devices().filter(\.isPresent).count == 4)
    }

    @Test("A device the run already had is left exactly as it is")
    func alreadyPresent() {
        var ledger = HistoryLedger()
        let run = twoRuns(into: &ledger)
        let before = ledger.devices()
        let fold = ledger.foldExtension([device(10, at: Self.at(11))], of: run.id)
        #expect(fold.events.isEmpty && fold.updatedRecords == 0)
        #expect(ledger.devices() == before)
    }

    @Test("Only the latest run can be extended")
    func onlyTheLatest() {
        var ledger = HistoryLedger()
        _ = twoRuns(into: &ledger)
        let before = ledger.devices()
        let fold = ledger.foldExtension([device(42, at: Self.at(11))], of: UUID())
        #expect(fold.events.isEmpty)
        #expect(ledger.devices() == before)
    }

    @Test("Through the log store: written without a run line, and read back the same")
    func throughTheLogStore() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-look-longer-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        let store = LogHistoryStore(url: url)
        _ = await store.record(report([device(1, at: Self.at(0)), device(42, name: "Pixel", at: Self.at(0))], at: Self.at(0)))
        let second = report([device(1, at: Self.at(10))], at: Self.at(10))
        _ = await store.record(second)
        let runLines = try String(contentsOf: url, encoding: .utf8).components(separatedBy: #""type":"run""#).count

        let events = await store.recordExtension([device(42, at: Self.at(11))], of: second.run.id)
        #expect(events.map(\.kind) == [.appeared])
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.components(separatedBy: #""type":"run""#).count == runLines, "an extension wrote a run line")

        let reopened = LogHistoryStore(url: url)
        #expect(await reopened.latestRun()?.id == second.run.id)
        let present = await reopened.devices().filter(\.isPresent).map(\.device.primaryAddress)
        #expect(Set(present) == [.v4(IPv4Address("10.10.20.1")!), .v4(IPv4Address("10.10.20.42")!)])
        #expect(await reopened.events().map(\.kind).contains(.appeared))
    }
}
