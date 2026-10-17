// Apple-only, like the target it tests.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// Gate R2 of the fixes brief (F2, questions Q9).
///
/// An expected host that answers ARP and not echo, whose entry is already complete when
/// the sweep starts, is reported present as `neighbor_table` — the final report accepts
/// the entry. So the sweep must not wait for evidence it has already accepted: it ends at
/// the learned tail, not at the wait the plan would otherwise give the address.
///
/// Driven through `SweepState` on injected instants, so nothing here sleeps.
@Suite("An inherited expected address does not hold the sweep (R2)")
struct InheritedExpectedSweepTests {
    static func ip(_ last: UInt8) -> IPv4Address { ReachSweepTests.ip(last) }
    static let addresses = ReachSweepTests.addresses
    static let network = IPv4Network("10.10.20.0/24")!
    static let now = Timestamp(millisecondsSinceEpoch: 1_790_000_000_000)
    static let arpOnly = ip(12)
    static let answers = ip(13)
    static let mac = MACAddress(raw: 0xAA_BB_CC_DD_EE_12)

    /// History expects `.12` and `.13`, and the network holds 20 cold samples up to
    /// 1,000 ms and 20 warm ones of 1,200 ms — so F1 alone would have held `.12`, warm, for
    /// 1.2 s. The samples are a device's last seen 40 days ago, so `.12` and `.13` have
    /// none of their own and take the network's rules (F11's fallback).
    static var plan: ReachPlan {
        let cold = (1...20).map { FirstContactSample(millis: Double($0) * 50, cold: true) }
        let warm = (1...20).map { _ in FirstContactSample(millis: 1_200, cold: false) }
        let aged = Timestamp(millisecondsSinceEpoch: now.millisecondsSinceEpoch - 40 * 86_400_000)
        let devices = [arpOnly, answers].map { address in
            StoredDevice(
                device: Device(observing: HostFacts(ip: address), in: network, lastSeen: now),
                isPresent: true
            )
        } + [StoredDevice(
            device: Device(observing: HostFacts(ip: ip(200)), in: network, lastSeen: aged),
            isPresent: false, firstContactSamples: cold + warm
        )]
        return ReachPlan.make(
            addresses: addresses, network: network, devices: devices, policy: .default, now: now
        )
    }

    /// Runs the transmit schedule on a fake clock, 1 ms a tick, answering `.13`'s first
    /// transmission 5 ms after it goes out, and returns each address's transmissions.
    private func run(_ state: SweepState, from start: MonotonicInstant) async -> [IPv4Address: Int] {
        var count: [IPv4Address: Int] = [:]
        var now = start
        for _ in 0..<10_000 {
            let due = await state.dueProbes(limit: 512, now: now)
            _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, now) }))
            for probe in due {
                count[probe.address, default: 0] += 1
                if probe.address == Self.answers, count[probe.address] == 1 {
                    _ = await state.record(ICMPReply(
                        source: Self.answers, sequence: probe.sequence, token: probe.token,
                        receivedAt: now.advanced(by: .milliseconds(5)), ttl: 64
                    ))
                }
            }
            if await state.isSettled { break }
            now = now.advanced(by: .milliseconds(1))
        }
        return count
    }

    @Test("An expected, inherited, ARP-only address ends the sweep at the learned tail")
    func endsAtTheLearnedTail() async throws {
        let plan = Self.plan
        #expect(plan.warmExpectedWait == .milliseconds(1_200), "the wait F1 alone would have armed")
        let start = MonotonicInstant.now
        let state = SweepState(
            pending: Self.addresses, neighbors: [Self.arpOnly: Self.mac], attempts: 3,
            counters: ProbeCounters(), reach: plan
        )
        let resolved = try #require(state.resolvedReach)
        #expect(resolved.isInherited(Self.arpOnly))
        #expect(resolved.path(for: Self.answers) == .coldPercentile)
        #expect(await state.extendsWaits, ".13 still waits the cold P97")

        let sent = await run(state, from: start)
        // Asked on the learned schedule, like any address nothing waits for.
        #expect(sent[Self.arpOnly] == 3)
        #expect(await state.expectedMissing().isEmpty, "the inherited entry is evidence")

        // The learned tail is where the sweep ends: nothing pending there, and nothing to
        // settle for. It is well before .12's 1.2 s.
        let tailEnd = try #require(await state.declarationInstant())
        #expect(tailEnd < start.advanced(by: .milliseconds(1_200)))
        #expect(await state.pendingExtended(now: tailEnd) == 0)
        #expect(await state.settlingMissing(now: tailEnd.advanced(by: .milliseconds(1))) == nil)
        #expect(await state.reachExpired.isEmpty)
        // It never answered, so the sweep has no facts for it: the final table read
        // reports it, as `neighbor_table`, exactly as before.
        #expect(await state.discovered().map(\.ip) == [Self.answers])
    }

    @Test("The same silence with no entry at the start is waited for, until its deadline")
    func coldIsStillWaitedFor() async throws {
        let start = MonotonicInstant.now
        let state = SweepState(
            pending: Self.addresses, neighbors: [:], attempts: 3,
            counters: ProbeCounters(), reach: Self.plan
        )
        let resolved = try #require(state.resolvedReach)
        #expect(!resolved.isInherited(Self.arpOnly))
        #expect(resolved.path(for: Self.arpOnly) == .coldPercentile)
        _ = await run(state, from: start)
        let tailEnd = try #require(await state.declarationInstant())
        #expect(await state.pendingExtended(now: tailEnd) == 1)
        #expect(await state.expectedMissing() == [Self.arpOnly])
        #expect(await state.settlingMissing(now: tailEnd.advanced(by: .milliseconds(1))) == [Self.arpOnly])
    }

    @Test("Inherited is .history's: a fixed wait still waits for an expected warm address")
    func fixedIsUnchanged() async throws {
        let state = SweepState(
            pending: Self.addresses, neighbors: [Self.arpOnly: Self.mac], attempts: 3,
            counters: ProbeCounters(),
            reach: ReachPlan(policy: .fixed(.seconds(2)), expected: [Self.arpOnly])
        )
        let resolved = try #require(state.resolvedReach)
        #expect(!resolved.isInherited(Self.arpOnly))
        #expect(await state.expectedMissing() == [Self.arpOnly])
    }
}

#endif
