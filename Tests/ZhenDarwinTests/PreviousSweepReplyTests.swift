// Apple-only, like the target it tests.
#if canImport(Darwin)

import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// F9 (gate R10): a reply to the previous sweep's probe is not this sweep's evidence.
///
/// Gate T's G5 ran scans back to back with 500 ms hosts. The token sat in the payload and
/// started at 1 on every sweep, and the addresses went out in the same order, so token k
/// meant the same address in every scan. A reply to the previous scan's first probe to
/// `.12` arrived during the next one, matched that scan's token for `.12`, and was
/// recorded as a first contact of 46 ms, then fed the cold percentile.
@Suite("A reply to another sweep's probe (R10)")
struct PreviousSweepReplyTests {
    /// The testbed's ten responders, in the order a sweep sends them.
    static let addresses = (4...13).map { IPv4Address(raw: 0xC0A8_4000 | UInt32($0)) }
    static let slow = IPv4Address(raw: 0xC0A8_400C)   // 192.168.64.12

    /// A sweep that has sent its first wave, every address cold, at `sentAt`.
    private func sentSweep(at sentAt: MonotonicInstant) async -> (SweepState, [ProbeAssignment]) {
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters()
        )
        let wave = await state.dueProbes(limit: 512, now: sentAt)
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: wave.map { ($0.token, sentAt) }))
        return (state, wave)
    }

    @Test("A late reply to the previous sweep's probe is a stray, not a 46 ms first contact")
    func previousSweepsReplyIsAStray() async throws {
        let start = MonotonicInstant.now
        let (_, earlierWave) = await sentSweep(at: start)
        let earlier = try #require(earlierWave.first { $0.address == Self.slow })

        // The next scan starts about half a second later, before the slow host has
        // answered the earlier one.
        let nextStart = start.advanced(by: .milliseconds(510))
        let (state, wave) = await sentSweep(at: nextStart)
        let own = try #require(wave.first { $0.address == Self.slow })

        // The earlier probe's reply, 46 ms into the next sweep: the right source, and the
        // earlier sweep's token.
        let late = ICMPReply(
            source: Self.slow, sequence: earlier.sequence, token: earlier.token,
            receivedAt: nextStart.advanced(by: .milliseconds(46)), ttl: 64
        )
        let event = await state.record(late)

        #expect(event == nil, "no host is found from another sweep's reply")
        #expect(await state.strayReplies == 1)
        #expect(await state.discovered().isEmpty)
        // The sweep's own reply, a second after its own send, is still the first contact.
        let reply = ICMPReply(
            source: Self.slow, sequence: own.sequence, token: own.token,
            receivedAt: nextStart.advanced(by: .milliseconds(990)), ttl: 64
        )
        let found = await state.record(reply)
        guard case .hostFound(let facts)? = found else {
            Issue.record("the sweep's own reply should find the host, got \(String(describing: found))")
            return
        }
        let firstContact = try #require(facts.firstContact)
        #expect(firstContact == .milliseconds(990))
        #expect(await state.strayReplies == 1)
    }

    @Test("A previous sweep's reply that beats this sweep's own send isn't held for it")
    func previousSweepsReplyBeforeOwnSend() async throws {
        let start = MonotonicInstant.now
        let (_, earlierWave) = await sentSweep(at: start)
        let earlier = try #require(earlierWave.first { $0.address == Self.slow })

        // The next sweep has assigned its first wave and not yet recorded the sends:
        // a reply arriving now used to be stashed for the matching token, and folded in
        // with an arrival before the send it was attributed to.
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters()
        )
        let nextStart = start.advanced(by: .milliseconds(510))
        let wave = await state.dueProbes(limit: 512, now: nextStart)
        let late = ICMPReply(
            source: Self.slow, sequence: earlier.sequence, token: earlier.token,
            receivedAt: nextStart.advanced(by: .milliseconds(1)), ttl: 64
        )
        #expect(await state.record(late) == nil)
        let events = await state.recordSends(
            Dictionary(uniqueKeysWithValues: wave.map { ($0.token, nextStart.advanced(by: .milliseconds(2))) })
        )
        #expect(events.isEmpty, "nothing was waiting for this sweep's probes")
        #expect(await state.strayReplies == 1)
        #expect(await state.discovered().isEmpty)
    }

    @Test("Two sweeps of the same addresses share no token")
    func sweepsDrawTheirOwnTokens() async {
        let start = MonotonicInstant.now
        let (_, first) = await sentSweep(at: start)
        let (_, second) = await sentSweep(at: start)
        #expect(Set(first.map(\.token)).isDisjoint(with: second.map(\.token)))
        // Within one sweep, still one token per transmission.
        #expect(Set(first.map(\.token)).count == first.count)
    }
}

#endif
