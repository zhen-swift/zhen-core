// Apple-only, like the target it tests.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// Change 4 of 0.8.0: the sweep honours the plan. Each address is asked as often and
/// waited for as long as the plan says, and the sweep ends at the latest per-address
/// deadline — or earlier, once every expected address has answered.
///
/// Driven through `SweepState` with injected instants, so nothing here sleeps.
@Suite("The sweep honours the reach plan")
struct ReachSweepTests {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }
    static let addresses = (1...20).map { ip(UInt8($0)) }
    static let expected = ip(12)

    /// A plan as `.history` builds it on a network with history: `.12` expected, waited
    /// for `wait`.
    static func history(wait: Duration, expected: Set<IPv4Address> = [expected]) -> ReachPlan {
        ReachPlan(
            policy: .default, expected: expected, historySamples: 24, expectedWait: wait
        )
    }

    /// Sends everything due at `instant` and records it as sent then.
    @discardableResult
    private func send(_ state: SweepState, at instant: MonotonicInstant) async -> [ProbeAssignment] {
        let due = await state.dueProbes(limit: 512, now: instant)
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, instant) }))
        return due
    }

    /// Runs the transmit schedule to completion on a fake clock, 1 ms a tick, and returns
    /// how many transmissions each address got and when its last went out.
    private func transmitAll(
        _ state: SweepState, from start: MonotonicInstant
    ) async -> (count: [IPv4Address: Int], last: [IPv4Address: Duration]) {
        var count: [IPv4Address: Int] = [:]
        var last: [IPv4Address: Duration] = [:]
        var now = start
        for _ in 0..<10_000 {
            for probe in await send(state, at: now) {
                count[probe.address, default: 0] += 1
                last[probe.address] = now.duration(since: start)
            }
            if await state.isSettled { break }
            now = now.advanced(by: .milliseconds(1))
        }
        return (count, last)
    }

    @Test("No plan and a learned plan are the same schedule: study 1's")
    func learnedIsUnchanged() async {
        let start = MonotonicInstant.now
        let none = SweepState(pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters())
        let learned = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: ReachPlan(policy: .learned)
        )
        let noneExtends = await none.extendsWaits
        let learnedExtends = await learned.extendsWaits
        #expect(!noneExtends && !learnedExtends)
        let a = await transmitAll(none, from: start)
        let b = await transmitAll(learned, from: start)
        #expect(a.count == b.count && a.last == b.last)
        #expect(Set(a.count.values) == [3])
        let noneEnd = await none.declarationInstant()
        let learnedEnd = await learned.declarationInstant()
        #expect(noneEnd == learnedEnd)
        #expect(await learned.pendingExtended() == 0)
    }

    @Test("An expected address gets the plan's attempts, spread across its own wait")
    func expectedIsSpread() async {
        let start = MonotonicInstant.now
        // P97 = 1,034 ms → four attempts, a slot of 258.5 ms.
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: Self.history(wait: .milliseconds(1_034))
        )
        #expect(await state.extendsWaits)
        let sent = await transmitAll(state, from: start)
        #expect(sent.count[Self.expected] == 4)
        #expect(sent.count[Self.ip(13)] == 3, "an address history does not expect keeps the base")
        // The final transmission to `.12` goes out inside its own wait, about one slot
        // before the deadline (the gap before it is scattered ±25%), and well after the
        // learned path has finished transmitting.
        let final = try! #require(sent.last[Self.expected])
        // Typed apart from the `#expect`: inline, the literal arithmetic against every
        // `.milliseconds` overload ran out the type checker's time budget.
        let earliest: Int = 1_034 * 2 / 4 + 1_034 / 4 * 3 / 4 - 2
        #expect(final > .milliseconds(earliest))
        #expect(final < .milliseconds(1_034))
        #expect(final > (sent.last[Self.ip(13)] ?? .zero) + .milliseconds(300))
    }

    @Test("The learned path's tail is anchored on its own transmissions, not the expected one's")
    func anchorIgnoresExtended() async {
        let start = MonotonicInstant.now
        let plain = SweepState(pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters())
        let planned = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: Self.history(wait: .milliseconds(1_034))
        )
        _ = await transmitAll(plain, from: start)
        _ = await transmitAll(planned, from: start)
        // One address fewer on the learned path ends its schedule no later.
        let a = try! #require(await plain.declarationInstant())
        let b = try! #require(await planned.declarationInstant())
        #expect(b <= a)
    }

    @Test("Ends at the deadline when an expected address stays silent, and says which")
    func deadlineRetires() async {
        let start = MonotonicInstant.now
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: Self.history(wait: .milliseconds(1_034))
        )
        await send(state, at: start)
        #expect(await state.pendingExtended(now: start.advanced(by: .milliseconds(1_033))) == 1)
        #expect(await state.expectedMissing() == [Self.expected])
        #expect(await state.pendingExtended(now: start.advanced(by: .milliseconds(1_035))) == 0)
        #expect(await state.reachExpired == [Self.expected])
    }

    @Test("Ends early when the expected address answers")
    func evidenceEndsTheWait() async {
        let start = MonotonicInstant.now
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: Self.history(wait: .milliseconds(1_034))
        )
        let due = await send(state, at: start)
        let probe = due.first { $0.address == Self.expected }!
        _ = await state.record(ICMPReply(
            source: Self.expected, sequence: probe.sequence, token: probe.token,
            receivedAt: start.advanced(by: .milliseconds(900)), ttl: 64
        ))
        #expect(await state.pendingExtended(now: start.advanced(by: .milliseconds(901))) == 0)
        #expect(await state.expectedMissing().isEmpty)
        #expect(await state.reachExpired.isEmpty)
    }

    @Test("A resolution is evidence too: an ARP-only expected host ends the wait")
    func resolutionEndsTheWait() async {
        let start = MonotonicInstant.now
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: Self.history(wait: .milliseconds(1_034))
        )
        await send(state, at: start)
        _ = await state.recordResolution(
            Self.expected, mac: MACAddress(raw: 0x0200_0000_0012), at: start.advanced(by: .milliseconds(700)))
        #expect(await state.pendingExtended(now: start.advanced(by: .milliseconds(701))) == 0)
    }

    @Test("Under history the learned tail floors a short expected wait; under fixed it does not")
    func tailFloor() async {
        let start = MonotonicInstant.now
        // 50 ms is below the tail, which is 400 ms before any reply has taught it anything.
        let history = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: Self.history(wait: .milliseconds(50))
        )
        await send(history, at: start)
        let tail = await history.tailBudget()
        #expect(await history.pendingExtended(now: start.advanced(by: .milliseconds(60))) == 1)
        #expect(await history.pendingExtended(now: start.advanced(by: tail + .milliseconds(1))) == 0)

        let fixed = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: ReachPlan(policy: .fixed(.milliseconds(50)))
        )
        await send(fixed, at: start)
        #expect(await fixed.pendingExtended(now: start.advanced(by: .milliseconds(60))) == 0)
        #expect(await fixed.reachExpired.count == Self.addresses.count)
    }

    @Test("A first scan waits 1.5 s everywhere with five attempts, and no tail decides it")
    func firstScan() async {
        let start = MonotonicInstant.now
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3, counters: ProbeCounters(),
            reach: ReachPlan(policy: .default, firstScan: true)
        )
        let sent = await transmitAll(state, from: start)
        #expect(Set(sent.count.values) == [5])
        #expect(sent.last.values.allSatisfy { $0 < .milliseconds(1_500) && $0 > .milliseconds(900) })
        // Nothing went out on the learned path, so there is no network-wide tail.
        #expect(await state.declarationInstant() == nil)
        #expect(await state.pendingExtended(now: start.advanced(by: .milliseconds(1_499))) == Self.addresses.count)
        #expect(await state.pendingExtended(now: start.advanced(by: .milliseconds(1_501))) == 0)
        // Nothing is expected on a first scan, so nothing is "missing".
        #expect(await state.expectedMissing().isEmpty)
    }
}

#endif
