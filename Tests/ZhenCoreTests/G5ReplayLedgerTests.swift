// G5ReplayLedgerTests.swift — gate R11 of the fixes brief, addendum 3 (F10).
//
// Gate T's G5 (2026-10-17) replayed through the ledger: the two primes and ten scans,
// with `.12` and `.13` seen exactly as the run's artifacts recorded them — first
// contacts, MACs, the two MAC-less sightings, the scans that missed them — and the
// eight other responders answering every time. The IPv6 cache keeps both slow hosts'
// link-locals, so a run where `.12` is MAC-less or missing on v4 also reports its
// link-local as a device of its own, as `Device.fusing` does in the pipeline.
//
// Before F10 this reproduced the artifact's columns exactly: expected 11, 11, 11, 11,
// 10, 9, 11, 11, 9, 9, 9 and history samples 10, 20, 30, 40, 44, 48, 67, 77, 72, 80, 88.
// Portable: it runs on Linux.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Gate T's G5, replayed through history (R11)")
struct G5ReplayLedgerTests {
    static let network = IPv4Network("192.168.64.0/24")!
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0xC0A8_4000 | UInt32(last)) }
    static func mac(_ last: UInt8) -> MACAddress { MACAddress("52:55:55:00:00:\(String(last, radix: 16))")! }
    static let mac12 = MACAddress("52:55:55:A9:01:64")!
    static let mac13 = MACAddress("52:55:55:BF:A1:05")!
    static let v6of12 = IPv6Address("fe80::5055:55ff:fea9:164%bridge100")!
    static let v6of13 = IPv6Address("fe80::5055:55ff:febf:a105%bridge100")!
    static let start = Timestamp(millisecondsSinceEpoch: 1_792_200_000_000)

    /// How `.12` or `.13` showed up in one run.
    enum Sighting {
        /// Found with its MAC, and this first contact (nil: found with none).
        case withMAC(Double?)
        /// Found without a MAC, with this first contact.
        case withoutMAC(Double)
        /// Not found.
        case missed
    }

    /// From the artifacts: `g5-prime-1`, `g5-prime-2`, `g5-1` … `g5-10`.
    static let runs: [(name: String, twelve: Sighting, thirteen: Sighting)] = [
        ("prime 1", .withMAC(500.342334), .withMAC(1424.362917)),
        ("prime 2", .withMAC(502.036958), .withMAC(354.032792)),
        ("1", .withMAC(520.178125), .withMAC(520.163708)),
        ("2", .withMAC(503.7975), .withMAC(503.783583)),
        ("3", .withMAC(nil), .missed),
        ("4", .withoutMAC(443.552084), .missed),
        ("5", .withMAC(132.546834), .withMAC(52.2525)),
        ("6", .withMAC(46.442792), .withMAC(502.085833)),
        ("7", .withoutMAC(433.511791), .withoutMAC(433.479166)),
        ("8", .missed, .missed),
        ("9", .missed, .missed),
        ("10", .missed, .missed),
    ]

    /// The devices one run reports, fused as the pipeline fuses them.
    static func devices(twelve: Sighting, thirteen: Sighting, at: Timestamp) -> [Device] {
        // This Mac's own address on the bridge: a warm sample every run.
        var facts = [HostFacts(
            ip: ip(1), mac: mac(1), discoveredVia: [.probeReply, .localInterface],
            firstContact: .milliseconds(10), firstContactCold: false
        )]
        // `.4`–`.11`, cold, at their testbed delays.
        for last in UInt8(4)...11 {
            let delay: Double = [4: 10, 5: 11, 6: 20, 7: 20, 8: 54, 9: 54, 10: 106, 11: 106][last]!
            facts.append(HostFacts(
                ip: ip(last), mac: mac(last), discoveredVia: [.probeReply],
                firstContact: .milliseconds(delay), firstContactCold: true
            ))
        }
        var neighbours: [IPv6NeighborEntry] = []
        for (last, sighting, hardware, v6) in [(UInt8(12), twelve, mac12, v6of12), (13, thirteen, mac13, v6of13)] {
            switch sighting {
            case .withMAC(let millis):
                facts.append(HostFacts(
                    ip: ip(last), mac: hardware, discoveredVia: [.probeReply],
                    firstContact: millis.map { .milliseconds($0) }, firstContactCold: millis.map { _ in true }
                ))
            case .withoutMAC(let millis):
                facts.append(HostFacts(
                    ip: ip(last), discoveredVia: [.probeReply],
                    firstContact: .milliseconds(millis), firstContactCold: true
                ))
            case .missed:
                break
            }
            neighbours.append(IPv6NeighborEntry(address: v6, mac: hardware, isPermanent: false))
        }
        return Device.fusing(
            facts.map { Device(observing: $0, in: network, firstSeen: at, lastSeen: at) }
                + neighbours.map { Device(neighbor: $0, seen: at) }
        )
    }

    static func report(_ devices: [Device], at: Timestamp) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at, target: network, interface: "bridge100",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    /// Replays every run; returns the plan each scan was made with, and the ledger after.
    static func replay() -> (plans: [ReachPlan], ledger: HistoryLedger) {
        var ledger = HistoryLedger()
        var plans: [ReachPlan] = []
        for (index, run) in runs.enumerated() {
            let at = Timestamp(millisecondsSinceEpoch: start.millisecondsSinceEpoch + Int64(index) * 3_000)
            plans.append(ReachPlan.make(
                addresses: network.hosts, network: network, devices: ledger.devices(),
                policy: .default, now: at
            ))
            ledger.fold(report(devices(twelve: run.twelve, thirteen: run.thirteen, at: at), at: at))
        }
        return (plans, ledger)
    }

    @Test("The slow hosts stay expected through all twelve runs")
    func slowHostsStayExpected() {
        let plans = Self.replay().plans
        // Before F10: 0, 11, 11, 11, 11, 10, 9, 11, 11, 9, 9, 9.
        #expect(plans.map(\.expected.count) == [0, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11])
        for (plan, run) in zip(plans, Self.runs).dropFirst() {
            #expect(plan.expected.isSuperset(of: [Self.ip(12), Self.ip(13)]), "run \(run.name)")
        }
    }

    @Test("No cold sample leaves the network's count")
    func samplesSurvive() {
        let plans = Self.replay().plans
        // Before F10: 0, 10, 20, 30, 40, 44, 48, 67, 77, 72, 80, 88. Each run adds one per
        // cold host it timed: ten, eight in runs 3 and 8–10, nine in run 4.
        #expect(plans.map(\.historySamples) == [0, 10, 20, 30, 40, 48, 57, 67, 77, 87, 95, 103])
    }

    @Test(".12 and .13 keep one record each, with their MAC, link-local and every sample")
    func recordsKeepTheirMAC() throws {
        let ledger = Self.replay().ledger
        let devices = ledger.devices()
        for (last, hardware, v6, samples) in [
            (UInt8(12), Self.mac12, Self.v6of12,
             [500.342334, 502.036958, 520.178125, 503.7975, 443.552084, 132.546834, 46.442792, 433.511791]),
            (13, Self.mac13, Self.v6of13,
             [1424.362917, 354.032792, 520.163708, 503.783583, 52.2525, 502.085833, 433.479166]),
        ] {
            let holders = devices.filter { $0.device.addresses.contains(.v4(Self.ip(last))) }
            #expect(holders.count == 1, ".\(last) is one record")
            let record = try #require(holders.first)
            #expect(record.device.mac == hardware)
            #expect(record.device.addresses == [.v4(Self.ip(last)), .v6(v6)])
            #expect(record.device.identityStability != .ephemeral)
            #expect(record.firstContactSamples.map(\.millis) == samples, "oldest first, none lost")
            #expect(record.firstContactSamples.allSatisfy { $0.cold })
        }
        // Eleven devices, as the testbed has: nothing split off.
        #expect(devices.count == 11)
    }

    @Test("A sighting with no MAC joins the device at that address now, not an older lease record")
    func macLessSightingJoinsTheCurrentHolder() throws {
        let earlier = Timestamp(millisecondsSinceEpoch: Self.start.millisecondsSinceEpoch - 86_400_000)
        let moved = Timestamp(millisecondsSinceEpoch: Self.start.millisecondsSinceEpoch - 3_600_000)
        // An older record keyed by `.12`'s lease alone: something answered there once
        // without a MAC. Then a device with a MAC, first at `.30`, that has since moved
        // to `.12` — so two records hold `.12`, and only one of them is there now.
        var ledger = HistoryLedger()
        ledger.fold(Self.report(
            [Device(observing: HostFacts(ip: Self.ip(12), discoveredVia: [.probeReply]),
                    in: Self.network, firstSeen: earlier, lastSeen: earlier)],
            at: earlier
        ))
        ledger.fold(Self.report(
            [Device(observing: HostFacts(ip: Self.ip(30), mac: Self.mac12, discoveredVia: [.probeReply]),
                    in: Self.network, firstSeen: moved, lastSeen: moved)],
            at: moved
        ))
        ledger.fold(Self.report(
            [Device(observing: HostFacts(ip: Self.ip(12), mac: Self.mac12, discoveredVia: [.probeReply]),
                    in: Self.network, firstSeen: Self.start, lastSeen: Self.start)],
            at: Self.start
        ))
        // The lease rule alone would hand the MAC-less sighting to the record keyed by the
        // lease; it belongs to the MAC'd one.
        let later = Timestamp(millisecondsSinceEpoch: Self.start.millisecondsSinceEpoch + 3_000)
        ledger.fold(Self.report(
            [Device(observing: HostFacts(
                ip: Self.ip(12), discoveredVia: [.probeReply],
                firstContact: .milliseconds(510), firstContactCold: true
            ), in: Self.network, firstSeen: later, lastSeen: later)],
            at: later
        ))
        let macd = try #require(ledger.records.values.first { $0.device.mac == Self.mac12 })
        #expect(macd.device.lastSeen == later)
        #expect(macd.firstContactSamples.map(\.millis) == [510])
        let leaseOnly = try #require(ledger.records.values.first { $0.device.mac == nil })
        #expect(leaseOnly.device.lastSeen == earlier)
        #expect(leaseOnly.firstContactSamples.isEmpty)
    }

    @Test("A merge keeps the newest 32 samples by time, whichever record held them")
    func mergeKeepsTheNewest() throws {
        func at(_ second: Int) -> Timestamp {
            Timestamp(millisecondsSinceEpoch: Self.start.millisecondsSinceEpoch + Int64(second) * 1_000)
        }
        func record(_ last: UInt8, ordinal: Int, seconds: Range<Int>, millis: Double) -> HistoryLedger.Record {
            var device = Device(
                observing: HostFacts(ip: Self.ip(last), mac: Self.mac(last)),
                in: Self.network, firstSeen: at(seconds.lowerBound), lastSeen: at(seconds.upperBound)
            )
            device.names = [NameCandidate(value: "phone", source: .mdns)]
            var record = HistoryLedger.Record(
                device: device, firstSeen: at(seconds.lowerBound), lastRunID: UUID(),
                identifiers: [.fromMAC(Self.mac(last)), .mdnsInstance("phone")], ordinal: ordinal
            )
            record.firstContactSamples = seconds.map { FirstContactSample(millis: millis, cold: true, at: at($0)) }
            return record
        }
        // The survivor (lower ordinal) holds the older twenty; the record it absorbs, the
        // newer twenty — a device whose MAC rotated and kept being scanned.
        let older = record(20, ordinal: 0, seconds: 0..<20, millis: 100)
        let newer = record(21, ordinal: 1, seconds: 100..<120, millis: 200)
        var ledger = HistoryLedger(
            records: [.fromMAC(Self.mac(20)): older, .fromMAC(Self.mac(21)): newer],
            log: [], latestRun: nil
        )
        ledger.reconcile(at: at(200), runID: UUID())
        #expect(ledger.records.count == 1)
        let merged = try #require(ledger.records.values.first)
        #expect(merged.firstContactSamples.count == 32)
        // Before F10 the absorbed record's samples went first and the last 32 were kept:
        // eight of the twenty newest were dropped.
        #expect(merged.firstContactSamples.filter { $0.millis == 200 }.count == 20)
        #expect(merged.firstContactSamples.map(\.at) == (8..<20).map(at) + (100..<120).map(at))
    }

    @Test("Samples carry when they were taken, and a sample without it still decodes")
    func sampleTimeOnTheWire() throws {
        let timed = FirstContactSample(millis: 500.5, cold: true, at: Self.start)
        let text = String(decoding: try JSONEncoder().encode(timed), as: UTF8.self)
        #expect(text.contains(#""at_millis":1792200000000"#))
        #expect(try JSONDecoder().decode(FirstContactSample.self, from: Data(text.utf8)) == timed)
        let untimed = try JSONDecoder().decode(FirstContactSample.self, from: Data(#"{"millis":212,"cold":true}"#.utf8))
        #expect(untimed == FirstContactSample(millis: 212, cold: true))
        // Untimed sorts as the oldest, keeping its order.
        let newest = FirstContactSample.newest([timed, untimed, FirstContactSample(millis: 1, cold: false)])
        #expect(newest.map(\.millis) == [212, 1, 500.5])
    }
}
