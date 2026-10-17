// MissBackoffTests.swift — gate R14 of the fixes brief, addendum 4 (F13).
//
// A miss counts. An expected address that ends a scan without evidence adds one to its
// device's miss streak; each miss multiplies the device's next wait by `missBackoff`,
// capped; any evidence resets it. Stored with the first-contact samples, on the line 0.7.0
// keeps verbatim. Portable: it runs on Linux.

import Foundation
import Testing
@testable import ZhenCore

@Suite("A miss counts: the next wait grows until the device is heard (R14)")
struct MissBackoffTests {
    static let network = IPv4Network("192.168.64.0/24")!
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0xC0A8_4000 | UInt32(last)) }
    static let start = Timestamp(millisecondsSinceEpoch: 1_792_200_000_000)
    static func at(_ run: Int) -> Timestamp {
        Timestamp(millisecondsSinceEpoch: start.millisecondsSinceEpoch + Int64(run) * 3_000)
    }

    /// `.4`–`.11` answer every run; `.12` answers with this first contact, or not at all.
    static func report(run: Int, twelve: Double?, missing: [IPv4Address] = []) -> ScanReport {
        var facts = (UInt8(4)...11).map {
            HostFacts(ip: ip($0), mac: MACAddress("52:55:55:00:00:\(String($0, radix: 16))")!,
                      discoveredVia: [.probeReply], firstContact: .milliseconds(20), firstContactCold: true)
        }
        if let twelve {
            facts.append(HostFacts(ip: ip(12), mac: MACAddress("52:55:55:A9:01:64")!, discoveredVia: [.probeReply],
                                   firstContact: .milliseconds(twelve), firstContactCold: true))
        }
        return ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at(run), finishedAt: at(run), target: network, interface: "bridge100",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing(),
                reach: ReachReport(policy: "history", expectedCount: 9, expectedMissing: missing)
            ),
            devices: facts.map { Device(observing: $0, in: network, firstSeen: at(run), lastSeen: at(run)) }
        )
    }

    /// Three runs that teach `.12` its 500, 502 and 520 ms.
    static func taught() -> HistoryLedger {
        var ledger = HistoryLedger()
        for (run, millis) in [500.0, 502, 520].enumerated() { ledger.fold(report(run: run, twelve: millis)) }
        return ledger
    }

    static func plan(_ ledger: HistoryLedger, run: Int, settings: ReachSettings = ReachSettings()) -> ReachPlan {
        ReachPlan.make(
            addresses: network.hosts, network: network, devices: ledger.devices(),
            policy: .default, settings: settings, now: at(run)
        ).atSweepStart(addresses: network.hosts, complete: [])
    }

    static func streak(_ ledger: HistoryLedger) -> Int? {
        ledger.devices().first { $0.device.ipv4Addresses == [ip(12)] }?.missStreak
    }

    @Test("Two misses give four times the wait; a third is capped at 5 s; one reply resets it")
    func twoMissesThenAReply() throws {
        var ledger = Self.taught()
        #expect(Self.streak(ledger) == 0)
        #expect(Self.plan(ledger, run: 3).wait(for: Self.ip(12)) == .milliseconds(650))

        ledger.fold(Self.report(run: 3, twelve: nil, missing: [Self.ip(12)]))
        #expect(Self.streak(ledger) == 1)
        #expect(Self.plan(ledger, run: 4).wait(for: Self.ip(12)) == .milliseconds(1_300))

        ledger.fold(Self.report(run: 4, twelve: nil, missing: [Self.ip(12)]))
        #expect(Self.streak(ledger) == 2)
        let twice = Self.plan(ledger, run: 5)
        #expect(twice.wait(for: Self.ip(12)) == .milliseconds(2_600))
        #expect(twice.attempts(for: Self.ip(12)) == 7)
        #expect(twice.isBackedOff(Self.ip(12)))
        #expect(try #require(twice.paths).backedOff == 1)
        #expect(ReachReport(plan: twice, found: []).paths?.backedOff == 1)
        // Nobody else's wait moved: the other devices answered every time.
        #expect(!twice.isBackedOff(Self.ip(4)))

        ledger.fold(Self.report(run: 5, twelve: nil, missing: [Self.ip(12)]))
        #expect(Self.plan(ledger, run: 6).wait(for: Self.ip(12)) == .seconds(5))

        // One reply: the streak is gone, and so is the backoff.
        ledger.fold(Self.report(run: 6, twelve: 510))
        #expect(Self.streak(ledger) == 0)
        let heard = Self.plan(ledger, run: 7)
        #expect(!heard.isBackedOff(Self.ip(12)))
        #expect(heard.wait(for: Self.ip(12)) == .milliseconds(650))
        #expect(try #require(heard.paths).backedOff == 0)
    }

    @Test("--reach-miss-backoff 1 turns it off; the streak is still kept")
    func off() {
        var ledger = Self.taught()
        ledger.fold(Self.report(run: 3, twelve: nil, missing: [Self.ip(12)]))
        ledger.fold(Self.report(run: 4, twelve: nil, missing: [Self.ip(12)]))
        let plan = Self.plan(ledger, run: 5, settings: ReachSettings(missBackoff: 1))
        #expect(plan.wait(for: Self.ip(12)) == .milliseconds(650))
        #expect(!plan.isBackedOff(Self.ip(12)))
        #expect(Self.streak(ledger) == 2)
    }

    @Test("A device with no samples of its own backs off from the network's value")
    func fallbackBacksOffToo() throws {
        // `.13` answered once without a timed first contact, then was missed twice.
        var ledger = Self.taught()
        var seen = Self.report(run: 3, twelve: 500)
        seen.devices.append(Device(
            observing: HostFacts(ip: Self.ip(13), mac: MACAddress("52:55:55:BF:A1:05")!, discoveredVia: [.neighborResolved]),
            in: Self.network, firstSeen: Self.at(3), lastSeen: Self.at(3)
        ))
        ledger.fold(seen)
        ledger.fold(Self.report(run: 4, twelve: 500, missing: [Self.ip(13)]))
        ledger.fold(Self.report(run: 5, twelve: 500, missing: [Self.ip(13)]))
        let plan = Self.plan(ledger, run: 6)
        #expect(plan.path(for: Self.ip(13)) == .coldPercentile)
        let network = try #require(plan.expectedWait)
        #expect(plan.wait(for: Self.ip(13)) == min(network * 4, .seconds(5)))
        #expect(plan.isBackedOff(Self.ip(13)))
    }

    @Test("A cached expected address isn't waited for, streak or not")
    func inheritedIsNotBackedOff() {
        var ledger = Self.taught()
        ledger.fold(Self.report(run: 3, twelve: nil, missing: [Self.ip(12)]))
        let plan = ReachPlan.make(
            addresses: Self.network.hosts, network: Self.network, devices: ledger.devices(),
            policy: .default, now: Self.at(4)
        ).atSweepStart(addresses: Self.network.hosts, complete: [Self.ip(12)])
        #expect(plan.path(for: Self.ip(12)) == .inherited)
        #expect(plan.wait(for: Self.ip(12)) == .zero)
        #expect(!plan.isBackedOff(Self.ip(12)))
    }

    @Test("The streak is stored beside the samples, survives a reload, and leaves the line when reset")
    func stored() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-miss-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        let store = LogHistoryStore(url: url)
        for (run, millis) in [500.0, 502, 520].enumerated() { _ = await store.record(Self.report(run: run, twelve: millis)) }
        _ = await store.record(Self.report(run: 3, twelve: nil, missing: [Self.ip(12)]))
        _ = await store.record(Self.report(run: 4, twelve: nil, missing: [Self.ip(12)]))

        let text = try String(contentsOf: url, encoding: .utf8)
        let last = try #require(text.split(separator: "\n").last { $0.contains(#""type":"first_contact""#) && $0.contains("A9:01:64") })
        #expect(last.contains(#""miss_streak":2"#))
        let reopened = await LogHistoryStore(url: url).devices()
        #expect(reopened.first { $0.device.ipv4Addresses == [Self.ip(12)] }?.missStreak == 2)
        #expect(reopened.filter { $0.missStreak > 0 }.count == 1)

        _ = await store.record(Self.report(run: 5, twelve: 505))
        let after = try String(contentsOf: url, encoding: .utf8)
        let latest = try #require(after.split(separator: "\n").last { $0.contains(#""type":"first_contact""#) && $0.contains("A9:01:64") })
        #expect(!latest.contains("miss_streak"))
        #expect(await LogHistoryStore(url: url).devices().allSatisfy { $0.missStreak == 0 })
    }

    @Test("A 0.7.0 log still loads, with no streaks, and takes one")
    func sevenPointOhLogLoads() async throws {
        let fixture = try #require(Bundle.module.url(forResource: "history-0.7.0", withExtension: "ndjson", subdirectory: "Fixtures"))
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-miss-070-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        try FileManager.default.copyItem(at: fixture, to: url)

        let store = LogHistoryStore(url: url)
        let loaded = await store.devices()
        #expect(!loaded.isEmpty)
        #expect(loaded.allSatisfy { $0.missStreak == 0 })
        // A run on its network that expected one of its devices and missed it.
        let network = IPv4Network("10.10.20.0/24")!
        let victim = try #require(loaded.first { !$0.device.ipv4Addresses.isEmpty }?.device.ipv4Addresses.first)
        let later = Timestamp(millisecondsSinceEpoch: (loaded.map(\.device.lastSeen).max() ?? Self.start).millisecondsSinceEpoch + 60_000)
        _ = await store.record(ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: later, finishedAt: later, target: network, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing(),
                reach: ReachReport(policy: "history", expectedCount: 1, expectedMissing: [victim])
            ),
            devices: []
        ))
        let reopened = await LogHistoryStore(url: url).devices()
        #expect(reopened.count == loaded.count)
        #expect(reopened.first { $0.device.ipv4Addresses.contains(victim) }?.missStreak == 1)
    }
}
