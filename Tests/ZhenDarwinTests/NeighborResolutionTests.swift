// Apple-only, like the target it tests.
#if canImport(Darwin)

import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// Change 1 of 0.8.0: a neighbour entry that resolves during the sweep is this run's
/// evidence, at the moment the watch saw it.
@Suite("Neighbour resolution during a sweep")
struct NeighborResolutionTests {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }
    static let mac = MACAddress(raw: 0x0200_0000_0011)

    private func sentState(_ addresses: [IPv4Address]) async -> (SweepState, [ProbeAssignment], MonotonicInstant) {
        let state = SweepState(pending: addresses, neighbors: [:], attempts: 3, counters: ProbeCounters())
        let due = await state.dueProbes(limit: 512)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))
        return (state, due, sentAt)
    }

    @Test("An ARP-only host is found as neighbor_resolved, with its MAC, and counts as answered")
    func arpOnlyHostIsFound() async {
        // `.11` on the testbed answers ARP and ignores echo. Before the watch it was
        // reported from the table read after the sweep, labelled like an entry from an
        // hour ago; now it is found when it resolves.
        let host = Self.ip(11)
        let (state, _, sentAt) = await sentState([host])
        let event = await state.recordResolution(host, mac: Self.mac, at: sentAt.advanced(by: .milliseconds(480)))
        guard case .hostFound(let facts) = event else {
            Issue.record("expected hostFound, got \(String(describing: event))")
            return
        }
        #expect(facts.discoveredVia == [.neighborResolved])
        #expect(facts.mac == Self.mac)
        #expect(await state.everyoneAnswered)
        #expect(await state.discovered().map(\.ip) == [host])
    }

    @Test("An echo after the resolution is an update, the strongest source wins, and nothing double-counts")
    func echoAfterResolution() async {
        let host = Self.ip(12)
        let other = Self.ip(13)
        let (state, due, sentAt) = await sentState([host, other])
        _ = await state.recordResolution(host, mac: Self.mac, at: sentAt.advanced(by: .milliseconds(500)))
        let probe = due.first { $0.address == host }!
        let event = await state.record(ICMPReply(
            source: host, sequence: probe.sequence, token: probe.token,
            receivedAt: sentAt.advanced(by: .milliseconds(990)), ttl: 64
        ))
        guard case .hostUpdated(let facts) = event else {
            Issue.record("expected hostUpdated, got \(String(describing: event))")
            return
        }
        #expect(facts.discoveredVia == [.probeReply])
        // The MAC the watch learned is carried by the reply's facts.
        #expect(facts.mac == Self.mac)
        // One of two answered, not two of two.
        #expect(!(await state.everyoneAnswered))
    }

    @Test("A resolution for a host that already answered adds its MAC and nothing else")
    func resolutionAfterEcho() async {
        let host = Self.ip(14)
        let (state, due, sentAt) = await sentState([host])
        _ = await state.record(ICMPReply(
            source: host, sequence: due[0].sequence, token: due[0].token,
            receivedAt: sentAt.advanced(by: .milliseconds(2)), ttl: 64
        ))
        let event = await state.recordResolution(host, mac: Self.mac, at: .now)
        guard case .hostUpdated(let facts) = event else {
            Issue.record("expected hostUpdated, got \(String(describing: event))")
            return
        }
        #expect(facts.discoveredVia == [.probeReply])
        #expect(facts.mac == Self.mac)
        // Said once: a second read of the same entry has nothing new to report.
        #expect(await state.recordResolution(host, mac: Self.mac, at: .now) == nil)
    }

    @Test("An address the sweep was not asked about is ignored")
    func outsideTheSweepIsIgnored() async {
        let (state, _, _) = await sentState([Self.ip(1)])
        #expect(await state.recordResolution(Self.ip(200), mac: Self.mac, at: .now) == nil)
        #expect(await state.discovered().isEmpty)
    }
}

#endif
