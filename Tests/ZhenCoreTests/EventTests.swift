import Foundation
import Testing
@testable import ZhenCore

@Suite("Event derivation")
struct EventTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static let run = UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!
    static let at = Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)

    private func device(
        _ ip: String,
        mac: String? = nil,
        name: String? = nil,
        nameSource: NameSource = .mdns,
        vendor: String? = nil,
        openPorts: [UInt16] = [],
        filteredPorts: [UInt16] = []
    ) -> Device {
        let facts = HostFacts(
            ip: IPv4Address(ip)!,
            mac: mac.flatMap(MACAddress.init),
            allNames: name.map { [NameCandidate(value: $0, source: nameSource)] } ?? [],
            vendor: vendor,
            ports: openPorts.map { PortObservation(port: $0, state: .open) }
                 + filteredPorts.map { PortObservation(port: $0, state: .filtered) }
        )
        return Device(observing: facts, in: Self.network, lastSeen: Self.at)
    }

    private func derive(_ previous: [Device], _ current: [Device]) -> [ScanEvent] {
        deriveEvents(previous: previous, current: current, at: Self.at, run: Self.run, network: Self.network)
    }

    @Test("It is pure: the same inputs give the same events, in the same order")
    func deterministic() {
        let before = [device("10.10.20.1", mac: "30:DE:4B:5E:03:10"),
                      device("10.10.20.2", mac: "A8:51:AB:5E:09:6C", name: "Sala de estar principal")]
        let after = [device("10.10.20.2", mac: "A8:51:AB:5E:09:6C", name: "Sala de estar principal"),
                     device("10.10.20.5", mac: "6E:F0:9D:5E:0B:52", name: "New thing")]
        // Run it twice with the inputs in a different order; dictionary iteration
        // inside must not leak into the output.
        #expect(derive(before, after) == derive(before.reversed(), after.reversed()))
    }

    @Test("Appearing and disappearing")
    func appearedAndDisappeared() {
        let events = derive(
            [device("10.10.20.1", mac: "30:DE:4B:5E:03:10")],
            [device("10.10.20.5", mac: "6E:F0:9D:5E:0B:52", name: "New thing")]
        )
        #expect(events.map(\.kind).sorted { $0.rawValue < $1.rawValue }
                == [.hostAppeared, .hostDisappeared])
        let appeared = events.first { $0.kind == .hostAppeared }
        #expect(appeared?.summary == "New thing appeared")
        // Every event names the key it was matched under, so a wrong match is
        // explicable rather than mysterious. 6E:F0:9D:… has the locally administered
        // bit set, so it is a rotating address and the Bonjour name — not the MAC —
        // is what this record is joined on. That is the design working.
        #expect(appeared?.identity?.kind == .mdnsInstance)
    }

    @Test("A device that moved address is one device, not two")
    func ipMoved() {
        // The whole reason the join key is not the address.
        let events = derive(
            [device("10.10.20.20", mac: "30:DE:4B:5E:03:10", name: "Printer")],
            [device("10.10.20.21", mac: "30:DE:4B:5E:03:10", name: "Printer")]
        )
        #expect(events.map(\.kind) == [.ipMoved])
        #expect(events[0].details["from"] == "10.10.20.20")
        #expect(events[0].details["to"] == "10.10.20.21")
        #expect(events[0].ip.description == "10.10.20.21")
    }

    @Test("Two devices swapping leases do not turn into each other")
    func leaseSwapDoesNotCrossWire() {
        // The anti-collapse case. If addresses were join keys, this would produce two
        // spurious nameChanged events claiming each device became the other.
        let before = [
            device("10.10.20.30", mac: "30:DE:4B:5E:03:10", name: "Printer"),
            device("10.10.20.31", mac: "A8:51:AB:5E:09:6C", name: "Apple TV"),
        ]
        let after = [
            device("10.10.20.31", mac: "30:DE:4B:5E:03:10", name: "Printer"),
            device("10.10.20.30", mac: "A8:51:AB:5E:09:6C", name: "Apple TV"),
        ]
        let events = derive(before, after)
        #expect(events.allSatisfy { $0.kind == .ipMoved })
        #expect(events.count == 2)
        #expect(!events.contains { $0.kind == .nameChanged })
    }

    @Test("A name arriving is routine; a name changing is a warning")
    func nameChangeSeverity() {
        let arriving = derive(
            [device("10.10.20.4", mac: "30:DE:4B:5E:03:10")],
            [device("10.10.20.4", mac: "30:DE:4B:5E:03:10", name: "Mac Studio de Luis")]
        )
        // mDNS is slower than ICMP; the second run naming what the first only found
        // is the normal sequence, not an incident.
        #expect(arriving.first { $0.kind == .nameChanged }?.severity == .info)

        let changing = derive(
            [device("10.10.20.4", mac: "30:DE:4B:5E:03:10", name: "Mac Studio de Luis")],
            [device("10.10.20.4", mac: "30:DE:4B:5E:03:10", name: "Something Else")]
        )
        // Either the device was renamed or the identity join is wrong, and the second
        // is the expensive possibility.
        #expect(changing.first { $0.kind == .nameChanged }?.severity == .warning)
    }

    @Test("Only transitions in and out of open are port events")
    func portTransitions() {
        let events = derive(
            [device("10.10.20.6", mac: "30:DE:4B:5E:03:10", openPorts: [22, 80])],
            [device("10.10.20.6", mac: "30:DE:4B:5E:03:10", openPorts: [80, 443])]
        )
        let opened = events.filter { $0.kind == .portOpened }
        let closed = events.filter { $0.kind == .portClosed }
        #expect(opened.map { $0.details["port"] } == ["443"])
        #expect(closed.map { $0.details["port"] } == ["22"])
    }

    @Test("A port going from closed to filtered is not an event")
    func filteredIsNotAPortEvent() {
        // The host stopped answering; nothing about the service changed. Reporting it
        // would bury the real signal.
        let before = Device(
            observing: HostFacts(ip: IPv4Address("10.10.20.6")!, mac: MACAddress("30:DE:4B:5E:03:10"),
                                 ports: [PortObservation(port: 22, state: .closed)]),
            in: Self.network, lastSeen: Self.at
        )
        let after = Device(
            observing: HostFacts(ip: IPv4Address("10.10.20.6")!, mac: MACAddress("30:DE:4B:5E:03:10"),
                                 ports: [PortObservation(port: 22, state: .filtered)]),
            in: Self.network, lastSeen: Self.at
        )
        #expect(derive([before], [after]).isEmpty)
    }

    @Test("A device with no stable key at all still diffs, on its address")
    func fallsBackToAddress() {
        // The fully anonymous device: no MAC, no name. The address is the best key
        // available, and the event records that so a reader can see how weak it was.
        let events = derive([device("10.10.20.8")], [device("10.10.20.8")])
        #expect(events.isEmpty)

        let moved = derive([device("10.10.20.8")], [device("10.10.20.9")])
        #expect(moved.map(\.kind).sorted { $0.rawValue < $1.rawValue }
                == [.hostAppeared, .hostDisappeared])
        #expect(moved.allSatisfy { $0.identity?.kind == .ipLease })
    }

    @Test("Events round-trip through the wire format")
    func eventsRoundTrip() throws {
        let events = derive(
            [device("10.10.20.20", mac: "30:DE:4B:5E:03:10", name: "Printer", vendor: "HP", openPorts: [9100])],
            [device("10.10.20.21", mac: "30:DE:4B:5E:03:10", name: "Printer 2", vendor: "HP Inc.")]
        )
        #expect(!events.isEmpty)
        let data = try ScanReport.makeEncoder().encode(events)
        #expect(try ScanReport.makeDecoder().decode([ScanEvent].self, from: data) == events)
    }

    @Test("A merge is never derived here — it needs the store's identifier table")
    func mergesAreNotDerivable() {
        let events = derive(
            [device("10.10.20.3", mac: "DA:5C:22:5E:08:0A"), device("10.10.20.3", mac: "F2:3A:91:5E:0A:44")],
            [device("10.10.20.3", mac: "DA:5C:22:5E:08:0A", name: "Alex's MacBook Pro")]
        )
        #expect(!events.contains { $0.kind == .hostsMerged })
    }
}
