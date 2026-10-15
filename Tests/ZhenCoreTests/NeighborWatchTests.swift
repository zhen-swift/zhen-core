// NeighborWatchTests.swift — change 1 of 0.8.0: what counts as resolved during a sweep.
//
// The watch itself is a timer and a sysctl, and lives in ZhenDarwin. The rules — how
// often to read, and which entries are this run's evidence rather than the kernel's
// memory — are here, so they hold on Linux too.

import Foundation
import Testing
@testable import ZhenCore

@Suite("Neighbour watch")
struct NeighborWatchTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }
    static func mac(_ last: UInt8) -> MACAddress { MACAddress(raw: 0x0200_0000_0000 | UInt64(last)) }

    @Test("25 ms up to 1,024 targets, then in proportion: a /16 polls every 1.6 s")
    func intervalScales() {
        #expect(NeighborWatch.interval(targets: 1) == .milliseconds(25))
        #expect(NeighborWatch.interval(targets: 254) == .milliseconds(25))
        #expect(NeighborWatch.interval(targets: 1_024) == .milliseconds(25))
        #expect(NeighborWatch.interval(targets: 2_048) == .milliseconds(50))
        #expect(NeighborWatch.interval(targets: 65_536) == .milliseconds(1_600))
    }

    @Test("Only entries that became complete after the baseline are this run's evidence")
    func onlyNewlyComplete() {
        let entries = [
            // Complete before the sweep: inherited, never resolved by it.
            NeighborEntry(ip: Self.ip(1), mac: Self.mac(1)),
            // Complete now, absent before: resolved during the sweep.
            NeighborEntry(ip: Self.ip(12), mac: Self.mac(12)),
            // Asked and not answered: absence, not presence.
            NeighborEntry(ip: Self.ip(13), mac: MACAddress(raw: 0), isComplete: false),
            // Already reported by an earlier read.
            NeighborEntry(ip: Self.ip(11), mac: Self.mac(11)),
            // Outside the target network.
            NeighborEntry(ip: IPv4Address("10.10.21.5")!, mac: Self.mac(5)),
            NeighborEntry(ip: Self.ip(3), mac: Self.mac(3)),
        ]
        let resolved = NeighborWatch.newlyResolved(
            entries, baseline: [Self.ip(1)], reported: [Self.ip(11)], in: Self.network
        )
        #expect(resolved.map(\.ip) == [Self.ip(3), Self.ip(12)])
    }

    @Test("The watch report round-trips with its wire keys")
    func reportRoundTrips() throws {
        let report = NeighborWatchReport(
            enabled: true, mechanism: "poll", pollIntervalMillis: 25, polls: 40,
            largestDumpBytes: 36_860, resolved: 2
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let text = String(decoding: try encoder.encode(report), as: UTF8.self)
        #expect(text == #"{"enabled":true,"largest_dump_bytes":36860,"mechanism":"poll","poll_interval_millis":25,"polls":40,"resolved":2}"#)
        #expect(try JSONDecoder().decode(NeighborWatchReport.self, from: Data(text.utf8)) == report)
    }
}
