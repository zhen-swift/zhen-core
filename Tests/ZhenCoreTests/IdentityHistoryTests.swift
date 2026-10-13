import Foundation
import Testing
@testable import ZhenCore

// Every hardware address a device has presented, kept on the ledger's record.
//
// The ledger has always followed a device across a MAC rotation and kept only the newest
// address. These are the rules for keeping the rest: one sighting per MAC, the span it was
// seen over, and how it joined — first, by rotation, or by a merge.
@Suite("A device's hardware addresses are history, kept on its record")
struct IdentityHistoryTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static let epoch: Int64 = 1_700_000_000_000

    private func day(_ number: Int) -> Timestamp {
        Timestamp(millisecondsSinceEpoch: Self.epoch + Int64(number) * 86_400_000)
    }

    private func device(ip: String, mac: String, name: String? = nil, at: Timestamp) -> Device {
        Device(
            observing: HostFacts(
                ip: IPv4Address(ip)!, mac: MACAddress(mac),
                allNames: name.map { [NameCandidate(value: $0, source: .mdns, rank: 1)] } ?? []
            ),
            in: Self.network, firstSeen: at, lastSeen: at
        )
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

    private func mac(_ text: String) -> MACAddress { MACAddress(text)! }

    /// A phone with private addressing, named on Bonjour, rotating once.
    private func rotatingPhone() -> HistoryLedger {
        var ledger = HistoryLedger()
        ledger.fold(report([device(ip: "10.10.20.40", mac: "DA:00:00:00:00:01", name: "Pixel", at: day(0))], at: day(0)))
        ledger.fold(report([device(ip: "10.10.20.40", mac: "DA:00:00:00:00:01", name: "Pixel", at: day(1))], at: day(1)))
        ledger.fold(report([device(ip: "10.10.20.41", mac: "DA:00:00:00:00:02", name: "Pixel", at: day(5))], at: day(5)))
        return ledger
    }

    @Test("One MAC seen twice is one sighting spanning both")
    func oneMACOneRow() throws {
        var ledger = HistoryLedger()
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(0))], at: day(0)))
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(3))], at: day(3)))
        let record = try #require(ledger.records.values.first)
        #expect(record.macHistory == [
            MACSighting(mac: mac("AA:BB:CC:00:00:05"), firstSeen: day(0), lastSeen: day(3), link: .original),
        ])
        #expect(record.priorMACs.isEmpty)
    }

    @Test("A rotation is a second row, joined by the name that did not rotate")
    func rotationIsASecondRow() throws {
        let ledger = rotatingPhone()
        #expect(ledger.records.count == 1, "the rotation split the device")
        let record = try #require(ledger.records.values.first)
        #expect(record.macHistory == [
            MACSighting(mac: mac("DA:00:00:00:00:01"), firstSeen: day(0), lastSeen: day(1), link: .original),
            MACSighting(mac: mac("DA:00:00:00:00:02"), firstSeen: day(5), lastSeen: day(5),
                        link: .rotation(by: .mdnsInstance)),
        ])
        #expect(record.priorMACs.map(\.mac) == [mac("DA:00:00:00:00:01")])
    }

    @Test("The history reaches StoredDevice, which is what a store hands out")
    func storedDeviceCarriesIt() {
        let ledger = rotatingPhone()
        #expect(ledger.devices().first?.macHistory.count == 2,
                "the history is on the record and nowhere a reader can reach")
    }

    @Test("An address that comes back extends its row rather than adding one")
    func returningMACExtends() throws {
        var ledger = rotatingPhone()
        ledger.fold(report([device(ip: "10.10.20.40", mac: "DA:00:00:00:00:01", name: "Pixel", at: day(9))], at: day(9)))
        let record = try #require(ledger.records.values.first)
        #expect(record.macHistory.count == 2, "a returning address became a third row")
        #expect(record.macHistory.first?.lastSeen == day(9), "the returning address's span did not grow")
    }

    @Test("Records joined by reconciliation keep both addresses, the absorbed one as a merge")
    func mergeCarriesTheAbsorbedAddress() throws {
        let old = HostIdentifier.fromMAC(mac("52:A1:8A:5E:04:8A"))
        let new = HostIdentifier.fromMAC(mac("D6:0A:97:5E:06:9C"))
        let name = HostIdentifier.mdnsInstance("alex's macbook pro")
        var ledger = HistoryLedger(
            records: [
                old: HistoryLedger.Record(
                    device: device(ip: "10.10.20.88", mac: "52:A1:8A:5E:04:8A", name: "Alex's MacBook Pro", at: day(0)),
                    firstSeen: day(0), lastRunID: UUID(), identifiers: [old, name], ordinal: 1
                ),
                new: HistoryLedger.Record(
                    device: device(ip: "10.10.20.131", mac: "D6:0A:97:5E:06:9C", at: day(9)),
                    firstSeen: day(9), lastRunID: UUID(), identifiers: [new], ordinal: 7
                ),
            ],
            log: [], latestRun: report([], at: day(10)).run
        )
        ledger.fold(report([device(ip: "10.10.20.131", mac: "D6:0A:97:5E:06:9C",
                                   name: "Alex's MacBook Pro", at: day(11))], at: day(11)))

        let survivor = try #require(ledger.records[old])
        #expect(survivor.macHistory.map(\.mac) == [mac("52:A1:8A:5E:04:8A"), mac("D6:0A:97:5E:06:9C")])
        let absorbed = try #require(survivor.macHistory.last)
        #expect(absorbed.firstSeen == day(9), "the absorbed record's earlier sighting was lost")
        #expect(absorbed.lastSeen == day(11))
        guard case .merge = absorbed.link else {
            Issue.record("the absorbed address was not marked as a merge: \(absorbed.link)")
            return
        }
    }

    @Test("A record from before 0.7.0 starts its history at the record's first-seen")
    func olderRecordIsSeeded() {
        let record = HistoryLedger.Record(
            device: device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(7)),
            firstSeen: day(2), lastRunID: UUID(),
            identifiers: [.fromMAC(mac("AA:BB:CC:00:00:05"))], ordinal: 0
        )
        #expect(record.macHistory == [
            MACSighting(mac: mac("AA:BB:CC:00:00:05"), firstSeen: day(2), lastSeen: day(7), link: .original),
        ])
    }

    @Test("The history survives a reopen of the log, links and all")
    func survivesAReopen() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-identity-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")

        let store = LogHistoryStore(url: url)
        for (index, mac, at) in [(40, "DA:00:00:00:00:01", 0), (41, "DA:00:00:00:00:02", 5)] {
            _ = await store.record(report([device(ip: "10.10.20.\(index)", mac: mac, name: "Pixel", at: day(at))], at: day(at)))
        }
        let devices = await LogHistoryStore(url: url).devices()
        #expect(devices.first?.macHistory == rotatingPhoneHistoryWithoutDayOne())
    }

    @Test("A link a later build wrote reads as original rather than hiding the device")
    func unknownLinkIsLenient() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-identity-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        _ = await LogHistoryStore(url: url).record(
            report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(0))], at: day(0)))

        // Rewrite the one sighting as a later build might: a link and a kind this one
        // has never heard of.
        let text = try String(contentsOf: url, encoding: .utf8)
        let future = text.replacing(#""link":"original""#, with: #""link":"teleported","by":"quantum_id""#)
        #expect(future != text, "the fixture edit did not apply")
        try future.write(to: url, atomically: true, encoding: .utf8)

        let devices = await LogHistoryStore(url: url).devices()
        #expect(devices.count == 1, "an unknown link hid the whole device")
        #expect(devices.first?.macHistory.first?.link == .original)
        #expect(devices.first?.macHistory.first?.mac == mac("AA:BB:CC:00:00:05"))
    }

    private func rotatingPhoneHistoryWithoutDayOne() -> [MACSighting] {
        [
            MACSighting(mac: mac("DA:00:00:00:00:01"), firstSeen: day(0), lastSeen: day(0), link: .original),
            MACSighting(mac: mac("DA:00:00:00:00:02"), firstSeen: day(5), lastSeen: day(5),
                        link: .rotation(by: .mdnsInstance)),
        ]
    }
}
