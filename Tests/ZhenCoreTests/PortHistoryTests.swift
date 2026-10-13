import Foundation
import Testing
@testable import ZhenCore

// Ports in history: a port scan folded in without being a run, and the events a port's
// change of state derives.
//
// Until 0.7.0 a port scan could not be kept. `zhen ports` wrote nothing, and the app,
// which wanted its results kept, recorded the probe as a run of one address — which then
// became the latest run and took every other device offline. These are the rules that
// replaced that, tested as rules on the ledger and once more through the file.
@Suite("Port scans are kept, and port changes are events")
struct PortHistoryTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static let epoch: Int64 = 1_700_000_000_000

    private func day(_ number: Int) -> Timestamp {
        Timestamp(millisecondsSinceEpoch: Self.epoch + Int64(number) * 86_400_000)
    }

    private func port(
        _ number: UInt16, _ state: PortState, at ip: String, proto: TransportProtocol = .tcp
    ) -> PortObservation {
        PortObservation(port: number, proto: proto, state: state, address: .v4(IPv4Address(ip)!))
    }

    private func device(
        ip: String, mac: String, ports: [PortObservation] = [], at: Timestamp
    ) -> Device {
        Device(
            observing: HostFacts(ip: IPv4Address(ip)!, mac: MACAddress(mac), ports: ports),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    private func report(_ devices: [Device], at: Timestamp, target: IPv4Network = network) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at,
                target: target, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    /// What an engine hands back: observations without an address, keyed by the host.
    private func scan(_ ports: [String: [(UInt16, PortState)]]) -> PortScanResult {
        PortScanResult(ports: Dictionary(uniqueKeysWithValues: ports.map { ip, list in
            (IPAddress.v4(IPv4Address(ip)!), list.map { PortObservation(port: $0.0, state: $0.1) })
        }))
    }

    private func targets(_ ips: String...) -> [IPAddress] { ips.map { .v4(IPv4Address($0)!) } }

    /// Two devices, both present after one full run.
    private func twoDevices() -> HistoryLedger {
        var ledger = HistoryLedger()
        ledger.fold(report([
            device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(0)),
            device(ip: "10.10.20.6", mac: "AA:BB:CC:00:00:06", at: day(0)),
        ], at: day(0)))
        return ledger
    }

    private func stored(_ ledger: HistoryLedger, _ ip: String) -> StoredDevice? {
        ledger.devices().first { $0.device.addresses.contains(.v4(IPv4Address(ip)!)) }
    }

    // ── Change 1: a port scan is kept, and is not a run ──────────────────────────────

    @Test("A port scan updates the ports of the device it reached")
    func portScanUpdatesPorts() {
        var ledger = twoDevices()
        ledger.foldPorts(scan(["10.10.20.5": [(22, .open), (80, .closed)]]),
                         targeted: targets("10.10.20.5"), at: day(1))
        let ports = stored(ledger, "10.10.20.5")?.device.ports ?? []
        #expect(ports.map(\.port) == [22, 80], "the scan's observations were not kept")
        #expect(ports.allSatisfy { $0.address == .v4(IPv4Address("10.10.20.5")!) },
                "an observation was kept without the address it was made on")
        #expect(stored(ledger, "10.10.20.6")?.device.ports.isEmpty == true,
                "a device the scan did not reach gained ports")
    }

    @Test("A port scan touches presence not at all")
    func portScanIsNotARun() {
        var ledger = twoDevices()
        let before = ledger.latestRun
        let fold = ledger.foldPorts(scan(["10.10.20.5": [(22, .open)]]),
                                    targeted: targets("10.10.20.5"), at: day(1))
        #expect(ledger.latestRun == before, "a port scan became the latest run")
        #expect(ledger.devices().allSatisfy { $0.isPresent },
                "a port scan of one address took another device offline")
        #expect(!fold.events.contains { $0.kind == .appeared || $0.kind == .disappeared },
                "a port scan derived a presence event")
    }

    @Test("A host no record holds is skipped, not invented")
    func unknownHostIsSkipped() {
        var ledger = twoDevices()
        ledger.foldPorts(scan(["10.10.20.99": [(443, .open)]]),
                         targeted: targets("10.10.20.99"), at: day(1))
        #expect(ledger.records.count == 2, "a port answer was turned into a device")
        #expect(ledger.devices().allSatisfy { $0.device.ports.isEmpty },
                "a port answer from an unknown host was given to a device history holds")
    }

    @Test("A host the scan was not asked about is not folded")
    func untargetedHostIsSkipped() {
        var ledger = twoDevices()
        ledger.foldPorts(scan(["10.10.20.6": [(22, .open)]]),
                         targeted: targets("10.10.20.5"), at: day(1))
        #expect(stored(ledger, "10.10.20.6")?.device.ports.isEmpty == true)
    }

    @Test("An absent device's address is not trusted with what answers there now")
    func absentRecordIsNotUpdated() {
        var ledger = twoDevices()
        // A second run in which .6 did not answer: its address may be anybody's now.
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(1))], at: day(1)))
        ledger.foldPorts(scan(["10.10.20.6": [(22, .open)]]),
                         targeted: targets("10.10.20.6"), at: day(2))
        #expect(stored(ledger, "10.10.20.6")?.device.ports.isEmpty == true,
                "ports that answered at an absent device's old address were given to it")
    }

    @Test("A port that was not asked about is not closed")
    func notAskedIsNotClosed() {
        var ledger = twoDevices()
        ledger.foldPorts(scan(["10.10.20.5": [(22, .open), (80, .open)]]),
                         targeted: targets("10.10.20.5"), at: day(1))
        let fold = ledger.foldPorts(scan(["10.10.20.5": [(22, .closed)]]),
                                    targeted: targets("10.10.20.5"), at: day(2))
        let ports = stored(ledger, "10.10.20.5")?.device.ports ?? []
        #expect(ports.first { $0.port == 80 }?.state == .open,
                "a port the second scan did not ask about lost its last known state")
        #expect(fold.events.map(\.kind) == [.portClosed],
                "expected exactly one event, for the port that was asked about")
    }

    // ── Change 2: which transitions are events ──────────────────────────────────────

    static let everyPair: [(PortState, PortState)] = PortState.allCases.flatMap { before in
        PortState.allCases.map { (before, $0) }
    }

    @Test("Only a transition involving open is an event", arguments: everyPair)
    func onlyOpenTransitionsAreEvents(before: PortState, after: PortState) {
        var ledger = twoDevices()
        ledger.foldPorts(scan(["10.10.20.5": [(22, before)]]), targeted: targets("10.10.20.5"), at: day(1))
        let fold = ledger.foldPorts(scan(["10.10.20.5": [(22, after)]]),
                                    targeted: targets("10.10.20.5"), at: day(2))
        let expected: [DerivedEvent.Kind] = switch (before == .open, after == .open) {
        case (false, true): [.portOpened]
        case (true, false): [.portClosed]
        default: []
        }
        #expect(fold.events.map(\.kind) == expected, "\(before) → \(after)")
    }

    @Test("A port seen for the first time is not an event, open or not")
    func firstObservationIsQuiet() {
        var ledger = twoDevices()
        let fold = ledger.foldPorts(scan(["10.10.20.5": [(22, .open), (443, .open)]]),
                                    targeted: targets("10.10.20.5"), at: day(1))
        #expect(fold.events.isEmpty, "a first look at a port was reported as a change")
    }

    @Test("A port event names the port, the address and what it was")
    func eventSentence() throws {
        var ledger = twoDevices()
        ledger.foldPorts(scan(["10.10.20.5": [(22, .filtered)]]), targeted: targets("10.10.20.5"), at: day(1))
        let fold = ledger.foldPorts(scan(["10.10.20.5": [(22, .open)]]),
                                    targeted: targets("10.10.20.5"), at: day(2))
        let event = try #require(fold.events.first)
        #expect(event.detail == "22/tcp open at 10.10.20.5 · was filtered")
        #expect(event.at == day(2))
        #expect(ledger.events().first == event, "the event was returned but not logged")
    }

    @Test("A full run with ports derives port events, in the same place as the others")
    func fullRunDerivesPortEvents() {
        var ledger = HistoryLedger()
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05",
                                   ports: [port(22, .open, at: "10.10.20.5")], at: day(0))], at: day(0)))
        let fold = ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05",
                                              ports: [port(22, .closed, at: "10.10.20.5")], at: day(1))], at: day(1)))
        #expect(fold.events.map(\.kind) == [.portClosed])
    }

    @Test("A run that did not scan ports keeps the ports history knew, and says nothing")
    func runWithoutPortsKeepsThem() {
        var ledger = HistoryLedger()
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05",
                                   ports: [port(22, .open, at: "10.10.20.5")], at: day(0))], at: day(0)))
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(1))], at: day(1)))
        #expect(stored(ledger, "10.10.20.5")?.device.ports.map(\.state) == [.open],
                "a run without a port stage erased the ports history knew")
        let fold = ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05",
                                              ports: [port(22, .open, at: "10.10.20.5")], at: day(2))], at: day(2)))
        #expect(fold.events.isEmpty,
                "a run without a port stage forgot port 22, and the next one reported it opening")
    }

    @Test("Ports at an address the device no longer holds are not kept")
    func portsFollowTheAddress() {
        var ledger = HistoryLedger()
        ledger.fold(report([device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05",
                                   ports: [port(22, .open, at: "10.10.20.5")], at: day(0))], at: day(0)))
        ledger.fold(report([device(ip: "10.10.20.7", mac: "AA:BB:CC:00:00:05", at: day(1))], at: day(1)))
        #expect(stored(ledger, "10.10.20.7")?.device.ports.isEmpty == true,
                "a port observed at an address the device left is still claimed for it")
    }

    // ── Through the file ────────────────────────────────────────────────────────────

    private func temporaryLog() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-ports-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appending(path: "history.ndjson")
    }

    @Test("Port results survive a reopen, which is what the app was losing")
    func portResultsSurviveAReopen() async throws {
        let url = try temporaryLog()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let first = LogHistoryStore(url: url)
        let run = report([
            device(ip: "10.10.20.5", mac: "AA:BB:CC:00:00:05", at: day(0)),
            device(ip: "10.10.20.6", mac: "AA:BB:CC:00:00:06", at: day(0)),
        ], at: day(0))
        _ = await first.record(run)
        _ = await first.recordPorts(scan(["10.10.20.5": [(22, .open)]]),
                                    targeted: targets("10.10.20.5"), at: day(1))
        _ = await first.recordPorts(scan(["10.10.20.5": [(22, .closed)]]),
                                    targeted: targets("10.10.20.5"), at: day(2))

        let reopened = LogHistoryStore(url: url)
        let devices = await reopened.devices()
        let five = devices.first { $0.device.addresses.contains(.v4(IPv4Address("10.10.20.5")!)) }
        #expect(five?.device.ports.map(\.state) == [.closed], "the port scan did not survive a reopen")
        #expect(devices.allSatisfy { $0.isPresent }, "a recorded port scan took a device offline")
        let latest = await reopened.latestRun()
        let events = await reopened.events()
        #expect(latest?.id == run.run.id, "a port scan wrote a run line")
        #expect(events.map(\.kind) == [.portClosed], "the port event did not survive a reopen")
    }
}
