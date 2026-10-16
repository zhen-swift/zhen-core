// AddressSourcesTests.swift — F4 of the fixes brief (questions, Q11 and Q13).
//
// `discovered_via` is per device, the union over its addresses. On a dual-stack device
// the union can hold `neighbor_resolved` and `neighbor_table` at once, each true of a
// different address. `address_sources` says which address each source is for. Portable.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Each address carries its own discovered_via (F4, R3)")
struct AddressSourcesTests {
    static let network = IPv4Network("10.10.40.0/24")!
    static let v4 = IPv4Address("10.10.40.15")!
    static let v6 = IPv6Address("fe80::aef4:73ff:fe02:36a2")!
    static let mac = MACAddress(raw: 0xEC_75_0C_06_DD_D0)
    static let seen = Timestamp(millisecondsSinceEpoch: 1_790_000_000_000)

    /// Q11's device, as G9 saw it live: the v4 address resolved during the sweep, and
    /// its link-local address was only in a 20-hour-old NDP entry.
    static var dualStack: Device {
        let v4 = Device(
            observing: HostFacts(ip: v4, mac: mac, discoveredVia: [.neighborResolved]),
            in: network, lastSeen: seen
        )
        let v6 = Device(neighbor: IPv6NeighborEntry(address: v6, mac: mac, isPermanent: false), seen: seen)
        let fused = Device.fusing([v4, v6])
        precondition(fused.count == 1)
        return fused[0]
    }

    @Test("Fusion keeps each address's sources; the device's field stays the union")
    func fusedDualStack() {
        let device = Self.dualStack
        #expect(device.discoveredVia == [.neighborResolved, .neighborTable])
        #expect(device.addressSources == [
            .v4(Self.v4): [.neighborResolved],
            .v6(Self.v6): [.neighborTable],
        ])
    }

    @Test("Each entry point records its own address")
    func entryPoints() {
        let observed = Device(
            observing: HostFacts(ip: Self.v4, discoveredVia: [.arpReply, .probeReply]),
            in: Self.network, lastSeen: Self.seen
        )
        #expect(observed.addressSources == [.v4(Self.v4): [.probeReply, .arpReply]])
        #expect(observed.addressSources[.v4(Self.v4)] == observed.discoveredVia)

        let answered = Device(
            neighbor: IPv6NeighborEntry(address: Self.v6, mac: Self.mac, isPermanent: false),
            seen: Self.seen, answeredEcho: true
        )
        #expect(answered.addressSources == [.v6(Self.v6): [.probeReply]])
    }

    @Test("Only the device's own addresses, canonical order, no empty entries")
    func invariant() {
        let stranger = IPAddress.v4(IPv4Address("10.10.40.99")!)
        let device = Device(
            addresses: [.v4(Self.v4)],
            identification: .minimal,
            identificationEvidence: IdentificationEvidence(names: [], vendor: nil, ttl: nil),
            identityStability: .ephemeral,
            firstSeen: Self.seen, lastSeen: Self.seen,
            addressSources: [
                .v4(Self.v4): [.neighborTable, .probeReply, .probeReply],
                stranger: [.probeReply],
                .v6(Self.v6): [],
            ]
        )
        #expect(device.addressSources == [.v4(Self.v4): [.probeReply, .neighborTable]])
    }

    @Test("On the wire: one {address, discovered_via} per address, in address order")
    func wire() throws {
        let data = try JSONEncoder().encode(Self.dualStack)
        struct Wire: Decodable {
            struct Entry: Decodable, Equatable { var address: String; var discovered_via: [String] }
            var address_sources: [Entry]
            var discovered_via: [String]
        }
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        #expect(wire.address_sources == [
            .init(address: "10.10.40.15", discovered_via: ["neighbor_resolved"]),
            .init(address: "fe80::aef4:73ff:fe02:36a2", discovered_via: ["neighbor_table"]),
        ])
        #expect(wire.discovered_via == ["neighbor_resolved", "neighbor_table"])
    }

    @Test("Round trip through a schema-4 report, and a document without the key reads as unrecorded")
    func roundTrip() throws {
        let report = ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: Self.seen, target: Self.network, interface: "en0",
                engine: EngineDescriptor(name: "fixture", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: [Self.dualStack]
        )
        let data = try JSONEncoder().encode(report)
        let back = try JSONDecoder().decode(ScanReport.self, from: data)
        #expect(back == report)
        #expect(back.schema == 4)

        // A schema-4 document from before F4, or a 0.7.0 history line: no key at all.
        var object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var devices = try #require(object["devices"] as? [[String: Any]])
        devices[0]["address_sources"] = nil
        object["devices"] = devices
        let older = try JSONDecoder().decode(
            ScanReport.self, from: JSONSerialization.data(withJSONObject: object)
        )
        #expect(older.devices[0].addressSources.isEmpty)
        #expect(older.devices[0].discoveredVia == [.neighborResolved, .neighborTable])
        let reencoded = String(decoding: try JSONEncoder().encode(older.devices[0]), as: UTF8.self)
        #expect(!reencoded.contains("address_sources"), "not recorded is not written")
    }

    @Test("Phase 3's question: was this device present on an inherited entry alone?")
    func inheritedAlone() {
        // The analysis the brief names: drop a device every one of whose addresses is
        // `neighbor_table` and nothing else.
        let inheritedOnly: (Device) -> Bool = { device in
            !device.addressSources.isEmpty
                && device.addressSources.values.allSatisfy { $0 == [.neighborTable] }
        }
        let ghost = Device(
            neighbor: IPv6NeighborEntry(address: Self.v6, mac: Self.mac, isPermanent: false), seen: Self.seen
        )
        #expect(inheritedOnly(ghost))
        #expect(!inheritedOnly(Self.dualStack))
    }

    @Test("History keeps them: a store writes and reads them back, and look-longer carries them")
    func history() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-address-sources-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        let run = ScanRun(
            id: UUID(), startedAt: Self.seen, target: Self.network, interface: "en0",
            engine: EngineDescriptor(name: "fixture", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing()
        )
        let store = LogHistoryStore(url: url)
        _ = await store.record(ScanReport(run: run, devices: [Self.dualStack]))
        let reread = await LogHistoryStore(url: url).devices()
        #expect(reread.map(\.device.addressSources) == [Self.dualStack.addressSources])

        // Look longer: a device the run did not have joins it with its own sources.
        let back = Device(
            observing: HostFacts(ip: IPv4Address("10.10.40.20")!, mac: MACAddress(raw: 0x02_00_00_00_00_20),
                                 discoveredVia: [.neighborResolved]),
            in: Self.network, lastSeen: Self.seen
        )
        _ = await store.recordExtension([back], of: run.id)
        let extended = await LogHistoryStore(url: url).devices()
            .first { $0.device.addresses.contains(.v4(IPv4Address("10.10.40.20")!)) }
        #expect(extended?.device.addressSources == [.v4(IPv4Address("10.10.40.20")!): [.neighborResolved]])
    }
}
