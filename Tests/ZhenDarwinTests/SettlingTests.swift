// Apple-only, like the target it tests.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// Change 6 of 0.8.0: the sweep says when only expected addresses remain.
@Suite("Settling: only expected addresses remain")
struct SettlingTests {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }
    static let addresses = (1...20).map { ip(UInt8($0)) }

    private func history(expected: Set<IPv4Address>) -> SweepState {
        SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: ReachPlan(policy: .default, expected: expected, historySamples: 24,
                             expectedWait: .milliseconds(1_034))
        )
    }

    /// Runs the transmit schedule on a fake clock, 1 ms a tick, until `stop` is true or
    /// everything is settled, answering `answering` on their first transmission.
    @discardableResult
    private func run(
        _ state: SweepState, from start: MonotonicInstant, answering: Set<IPv4Address> = [],
        until stop: Duration? = nil
    ) async -> MonotonicInstant {
        var now = start
        for _ in 0..<10_000 {
            let due = await state.dueProbes(limit: 512, now: now)
            _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, now) }))
            for probe in due where answering.contains(probe.address) {
                _ = await state.record(ICMPReply(
                    source: probe.address, sequence: probe.sequence, token: probe.token,
                    receivedAt: now, ttl: 64))
            }
            if let stop, now.duration(since: start) >= stop { break }
            if stop == nil, await state.isSettled { break }
            now = now.advanced(by: .milliseconds(1))
        }
        return now
    }

    @Test("Once the learned path is done and its tail has run out, the expected silent are named")
    func namesTheExpected() async {
        let start = MonotonicInstant.now
        let state = history(expected: [Self.ip(12), Self.ip(13)])
        // Mid-schedule: the learned path is still transmitting.
        await run(state, from: start, until: .milliseconds(50))
        #expect(await state.settlingMissing(now: start.advanced(by: .milliseconds(50))) == nil)
        // Every learned transmission sent and expired; the tail is still running.
        let end = await run(state, from: start)
        let tail = try! #require(await state.declarationInstant())
        if end < tail {
            #expect(await state.settlingMissing(now: end) == nil, "settling before the tail ran out")
        }
        #expect(await state.settlingMissing(now: tail) == [Self.ip(12), Self.ip(13)])
    }

    @Test("An answer shrinks the list, and the last one ends it")
    func answersShrinkIt() async {
        let start = MonotonicInstant.now
        let state = history(expected: [Self.ip(12), Self.ip(13)])
        let due = await state.dueProbes(limit: 512, now: start)
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, start) }))
        let end = await run(state, from: start)
        let tail = try! #require(await state.declarationInstant())
        let after = max(end, tail)
        _ = await state.recordResolution(Self.ip(12), mac: MACAddress(raw: 0x0200_0000_0012), at: after)
        #expect(await state.settlingMissing(now: after) == [Self.ip(13)])
        let probe = due.first { $0.address == Self.ip(13) }!
        _ = await state.record(ICMPReply(
            source: Self.ip(13), sequence: probe.sequence, token: probe.token, receivedAt: after, ttl: 64))
        #expect(await state.settlingMissing(now: after) == nil, "nothing missing is nothing to settle for")
    }

    @Test("Replies on the learned path are counted off, so settling still arrives")
    func learnedRepliesCount() async {
        let start = MonotonicInstant.now
        let state = history(expected: [Self.ip(12)])
        let end = await run(state, from: start, answering: [Self.ip(1), Self.ip(2), Self.ip(13)])
        let tail = try! #require(await state.declarationInstant())
        #expect(await state.settlingMissing(now: max(end, tail)) == [Self.ip(12)])
    }

    @Test("Never without a plan, under learned, or while unexpected addresses still wait")
    func notWhenOthersWait() async {
        let start = MonotonicInstant.now
        let none = SweepState(pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters())
        let end = await run(none, from: start)
        #expect(await none.settlingMissing(now: end.advanced(by: .seconds(2))) == nil)

        // A first scan: everyone waits 1.5 s, so an expected address is never alone
        // until the others' waits are over too.
        let first = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: ReachPlan(policy: .default, expected: [Self.ip(12)], firstScan: true)
        )
        await run(first, from: start)
        #expect(await first.settlingMissing(now: start.advanced(by: .milliseconds(1_400))) == nil)
    }
}

#endif
