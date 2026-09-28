// Apple-only, like the target it tests.
//
// `ZhenDarwin`'s sources are each wrapped this way so a Linux build produces an
// empty module rather than a failure. Its tests were not, which meant `swift test` could
// not run at all on Linux — so core's own tests, which are portable and are the ones
// worth running there, could only ever be compiled. Same rule, same reason.
#if canImport(Darwin)

import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

@Suite("Per-host adaptive timeouts")
struct AdaptiveTimeoutTests {
    static let network = IPv4Network("10.10.20.0/24")!
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }

    /// Builds a reply for a probe, arriving `after` its send.
    private func reply(
        _ assignment: ProbeAssignment, sentAt: MonotonicInstant, after: Duration
    ) -> ICMPReply {
        ICMPReply(
            source: assignment.address,
            sequence: assignment.sequence,
            token: assignment.token,
            receivedAt: sentAt.advanced(by: after),
            ttl: 64
        )
    }

    @Test("A slow host is still found on a network of fast ones")
    func slowHostSurvivesFastNeighbours() async {
        // The defect this replaced: a single global round wait converged on the fast
        // majority, so a 180 ms Wi-Fi device on a LAN whose other hosts answer in
        // hundreds of microseconds was missed on EVERY run — deterministically, not
        // occasionally, which is the worst kind.
        let fast = (1...20).map { Self.ip(UInt8($0)) }
        let slow = Self.ip(99)
        let state = SweepState(
            pending: fast + [slow], neighbors: [:], attempts: 3, counters: ProbeCounters()
        )

        // First pass: everything goes out together.
        let first = await state.dueProbes(limit: 512)
        #expect(first.count == 21)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: first.map { ($0.token, sentAt) }))

        // The fast hosts answer immediately, teaching the network estimator that this
        // is a sub-millisecond LAN.
        for assignment in first where assignment.address != slow {
            _ = await state.record(reply(assignment, sentAt: sentAt, after: .microseconds(400)))
        }
        // The slow one answers 180 ms later — after every fast host has reported, which
        // is precisely when a shared timeout would already have given up on it.
        let slowProbe = first.first { $0.address == slow }!
        _ = await state.record(reply(slowProbe, sentAt: sentAt, after: .milliseconds(180)))

        let found = await state.discovered()
        #expect(found.count == 21)
        #expect(found.contains { $0.ip == slow })
        // And it is reported with its real round trip, not the network's.
        let slowFacts = found.first { $0.ip == slow }
        #expect((slowFacts?.rtt?.millis ?? 0) > 150)
    }

    @Test("The first probe's window is tight, and the tail is what covers slowness")
    func firstWindowIsTightByDesign() async {
        // Deliberately the opposite of what an earlier version did. Making the FIRST
        // probe's window generous enough for the slowest host on the network meant
        // every dead address waited that long, three times each. The window is now the
        // cheap question — "should I resend?" — and it is answered tightly; the
        // expensive question is asked once at the end.
        let state = SweepState(
            pending: [Self.ip(1), Self.ip(2)], neighbors: [:], attempts: 3, counters: ProbeCounters()
        )
        let due = await state.dueProbes(limit: 512)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))

        // Nothing is due again immediately — it is a real window, not a token one —
        // but it is bounded well below the tail.
        #expect(await state.dueProbes(limit: 512).isEmpty)
        let wait = await state.timeUntilNextExpiry() ?? .zero
        #expect(wait > .milliseconds(20))
        #expect(wait <= .milliseconds(150))
        // And the tail, which is what a slow host is actually caught by, is longer.
        #expect(await state.tailBudget() > wait)
    }

    @Test("Karn keys off the probe, so a straggler from the first attempt is a clean sample")
    func karnKeysOffTheProbe() async throws {
        // The defect: the ambiguity flag was read at REPLY time from a round counter,
        // so a reply to the first attempt arriving after the second had gone out was
        // discarded — and a sweep could finish having accepted no samples at all,
        // leaving the estimator knowing nothing.
        let host = Self.ip(5)
        let state = SweepState(pending: [host], neighbors: [:], attempts: 3, counters: ProbeCounters())

        let firstAttempt = await state.dueProbes(limit: 8)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends([firstAttempt[0].token: sentAt])

        // Force it to expire and retransmit, so a second attempt is outstanding.
        try? await Task.sleep(for: .milliseconds(1))
        let secondAttempt = await state.dueProbes(limit: 8, now: sentAt.advanced(by: .seconds(2)))
        try #require(secondAttempt.count == 1)
        _ = await state.recordSends([secondAttempt[0].token: MonotonicInstant.now])

        // Now the FIRST attempt's reply arrives. It is unambiguous — its token says
        // exactly which transmission it answers — so it must be used.
        _ = await state.record(reply(firstAttempt[0], sentAt: sentAt, after: .milliseconds(300)))
        let found = await state.discovered()
        #expect(found.count == 1)
        #expect(found[0].rtt != nil, "a straggler with a known token is a usable sample")
        #expect(found[0].rtt?.samples == 1)
    }

    @Test("A reply that beats its own send registration is not lost")
    func earlyReplyIsStashed() async {
        // A whole /24 is handed to the socket in one batch that takes about ten
        // milliseconds; a host on the same switch answers in four hundred
        // microseconds. Its reply is decoded and delivered while the batch is still
        // being sent, before the send has been recorded — and dropping it made the
        // FASTEST hosts the ones most likely to be reported absent.
        let host = Self.ip(7)
        let state = SweepState(pending: [host], neighbors: [:], attempts: 3, counters: ProbeCounters())
        let due = await state.dueProbes(limit: 8)
        let sentAt = MonotonicInstant.now

        // Reply first, send registration second.
        #expect(await state.record(reply(due[0], sentAt: sentAt, after: .microseconds(400))) == nil)
        let events = await state.recordSends([due[0].token: sentAt])
        #expect(events.count == 1)
        #expect(await state.discovered().count == 1)
    }

    @Test("Silence does not widen the window; only evidence of slowness does")
    func noBackoffWithoutEvidence() async throws {
        // Backoff answers slowness. Silence is absence, and doubling the window for the
        // two hundred and forty dead addresses of a home /24 spends the whole sweep
        // budget on nothing.
        //
        // Driven with `.uniform` spacing deliberately. Since correction C8 the gap
        // before the FINAL transmission is widened on purpose, so a test that measured
        // the second attempt's window under the default policy would be measuring the
        // spread and calling it backoff. The property this test is about — that
        // silence alone never widens anything — is a property of the base interval,
        // and `spreadIsNotBackoff` below shows the widening is confined to one gap.
        let dead = Self.ip(200)
        let state = SweepState(pending: [dead], neighbors: [:], attempts: 3,
                               counters: ProbeCounters(), spacing: .uniform)
        let first = await state.dueProbes(limit: 8)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends([first[0].token: sentAt])
        let firstWait = await state.timeUntilNextExpiry() ?? .zero

        let second = await state.dueProbes(limit: 8, now: sentAt.advanced(by: .seconds(3)))
        try #require(second.count == 1)
        let secondSentAt = MonotonicInstant.now
        _ = await state.recordSends([second[0].token: secondSentAt])
        let secondWait = await state.timeUntilNextExpiry() ?? .zero

        // Within a small tolerance: the second attempt waits the same as the first.
        #expect(secondWait < firstWait * 1.6)
    }
}

/// Correction C8 of `Study/THEORY.md`: three transmissions spaced by a low quantile of
/// round-trip time span less than a Wi-Fi power-save outage, so one outage takes all
/// three and a host that was present the whole time is reported absent.
///
/// The measurement that motivated these, at a fixed 15% marginal loss rate with only
/// the distribution of that loss in time varying:
///
///     mean outage        indep    50ms   100ms   250ms   500ms      1s
///     three tight        0.998   0.948   0.910   0.884   0.870   0.859
///     spread             0.998   0.986   0.976   0.946   0.914   0.889
@Suite("Transmission spacing under correlated loss")
struct SpacingTests {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }

    /// Runs a sweep of a small LAN — three hosts that answer at once, and one that is
    /// unreachable for `outage` — and reports whether the sleeping one was found.
    ///
    /// The responsive hosts are not scenery. The spread is bought out of measured slack
    /// between the tail budget and what a reply actually needs, so a sweep in which
    /// nothing has answered yet has no evidence to buy it with and correctly declines
    /// to spread anything. A test with only the sleeping host in it would be testing a
    /// network that does not exist.
    ///
    /// The clock is driven rather than slept through: every instant comes from the
    /// window the state machine actually armed, so the test measures the schedule the
    /// implementation chose instead of a schedule the test assumed.
    private func sweep(
        spacing: SweepSpacing, outage: Duration, attempts: Int = 3
    ) async -> (found: Bool, sends: [Duration]) {
        let sleeper = Self.ip(42)
        let awake = [Self.ip(10), Self.ip(11), Self.ip(12)]
        let state = SweepState(
            pending: awake + [sleeper], neighbors: [:], attempts: attempts,
            counters: ProbeCounters(), spacing: spacing
        )
        let start = MonotonicInstant.now
        var now = start
        var sends: [Duration] = []

        // First wave: everything goes out, and the responsive hosts answer promptly.
        let first = await state.dueProbes(limit: 16, now: now)
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: first.map { ($0.token, now) }))
        sends.append(now.duration(since: start))
        for probe in first where probe.address != sleeper {
            _ = await state.record(ICMPReply(
                source: probe.address, sequence: probe.sequence, token: probe.token,
                receivedAt: now.advanced(by: .milliseconds(2)), ttl: 64
            ))
        }

        for _ in 1..<attempts {
            let armed = (await state.armedBudgets())[sleeper] ?? .milliseconds(100)
            now = now.advanced(by: armed)
            let due = await state.dueProbes(limit: 16, now: now)
            guard let probe = due.first(where: { $0.address == sleeper }) else { break }
            _ = await state.recordSends([probe.token: now])
            let offset = now.duration(since: start)
            sends.append(offset)
            if offset >= outage {
                // The station is awake by now, so this transmission is answered.
                _ = await state.record(ICMPReply(
                    source: sleeper, sequence: probe.sequence, token: probe.token,
                    receivedAt: now.advanced(by: .milliseconds(2)), ttl: 64
                ))
                break
            }
        }
        let found = await state.discovered().contains { $0.ip == sleeper }
        return (found, sends)
    }

    @Test("The widening is confined to the gap before the final transmission")
    func spreadIsNotBackoff() async {
        // Backoff widens every subsequent window in response to evidence of slowness.
        // This widens exactly one gap, by design, and the transmission after it is back
        // on the base interval — so a reader cannot mistake one for the other, and a
        // future change that reintroduced backoff would fail here.
        let host = Self.ip(7)
        let awake = [Self.ip(10), Self.ip(11)]
        let state = SweepState(
            pending: awake + [host], neighbors: [:], attempts: 3,
            counters: ProbeCounters(), spacing: .spreadIntoTail
        )
        var armed: [Duration] = []
        var now = MonotonicInstant.now

        let first = await state.dueProbes(limit: 16, now: now)
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: first.map { ($0.token, now) }))
        for probe in first where probe.address != host {
            _ = await state.record(ICMPReply(
                source: probe.address, sequence: probe.sequence, token: probe.token,
                receivedAt: now.advanced(by: .milliseconds(2)), ttl: 64
            ))
        }
        let base = await state.retransmitBudget()
        let spread = await state.spreadBudget()
        #expect(spread > base, "a fast LAN's tail budget is its floor, so there is slack")
        armed.append((await state.armedBudgets())[host] ?? .zero)

        for _ in 1..<3 {
            now = now.advanced(by: armed.last ?? .zero)
            let due = await state.dueProbes(limit: 16, now: now)
            guard let probe = due.first(where: { $0.address == host }) else { break }
            _ = await state.recordSends([probe.token: now])
            armed.append((await state.armedBudgets())[host] ?? .zero)
        }
        #expect(armed.count == 3)
        // armed[0] is not compared against `base`: the first wave is armed before any
        // reply has arrived, so its window is the estimator's no-samples default rather
        // than the measured interval. That is the same evidence rule the spread obeys.
        #expect(armed[1] > base, "the gap before the final transmission is the spread one")
        #expect(armed[2] == base, "nothing follows the final transmission, so its own window is base")
        #expect(armed[1] > armed[2], "the widening does not carry into the next gap")
    }

    @Test("Spreading does not move the instant the sweep stops listening")
    func spreadIsPaidOutOfTheTailWindow() async {
        // The whole argument for the default being free. The declaration instant is
        // anchored to the last TIGHT transmission, so a final transmission sent into
        // the tail window does not push the end of the sweep out — it is sent during
        // time the sweep was already going to spend waiting.
        func declaration(_ spacing: SweepSpacing) async -> Duration {
            let host = Self.ip(9)
            let awake = [Self.ip(10), Self.ip(11)]
            let state = SweepState(
                pending: awake + [host], neighbors: [:], attempts: 3,
                counters: ProbeCounters(), spacing: spacing
            )
            let start = MonotonicInstant.now
            var now = start
            let first = await state.dueProbes(limit: 16, now: now)
            _ = await state.recordSends(
                Dictionary(uniqueKeysWithValues: first.map { ($0.token, now) })
            )
            for probe in first where probe.address != host {
                _ = await state.record(ICMPReply(
                    source: probe.address, sequence: probe.sequence, token: probe.token,
                    receivedAt: now.advanced(by: .milliseconds(2)), ttl: 64
                ))
            }
            for _ in 1..<3 {
                now = now.advanced(by: (await state.armedBudgets())[host] ?? .zero)
                let due = await state.dueProbes(limit: 16, now: now)
                guard let probe = due.first(where: { $0.address == host }) else { break }
                _ = await state.recordSends([probe.token: now])
            }
            let end = await state.declarationInstant() ?? start
            return end.duration(since: start)
        }

        let tight = await declaration(.uniform)
        let spread = await declaration(.spreadIntoTail)
        // Not merely "no worse": the same instant, because the tail window absorbed the
        // whole spread. A tolerance of one base interval, since the tight schedule's
        // last transmission is itself one interval later than the spread schedule's
        // last tight one.
        #expect(spread <= tight + .milliseconds(1),
                "spread declared at \(spread.milliseconds) ms, tight at \(tight.milliseconds) ms")
    }

    @Test("Nothing has answered yet, so there is no measured slack to spread into")
    func noEvidenceMeansNoSpread() async {
        // The defect this catches cost 280 ms of wall clock on a real network. Before
        // any reply arrives both the tail budget and the reply allowance are the values
        // the estimators shipped with, and their difference is not slack — it is the
        // gap between two guesses. Spreading on it stretched every sweep of a network
        // whose hosts answer more slowly than the first retransmit window.
        let state = SweepState(
            pending: (1...8).map { Self.ip(UInt8($0)) }, neighbors: [:], attempts: 3,
            counters: ProbeCounters(), spacing: .spreadIntoTail
        )
        #expect(await state.spreadBudget() == .zero)
        let due = await state.dueProbes(limit: 16)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))
        // One reply is not enough: a single outlier must not set the whole schedule.
        let probe = due[0]
        _ = await state.record(ICMPReply(
            source: probe.address, sequence: probe.sequence, token: probe.token,
            receivedAt: sentAt.advanced(by: .milliseconds(2)), ttl: 64
        ))
        #expect(await state.spreadBudget() == .zero)
        // Two is.
        let second = due[1]
        _ = await state.record(ICMPReply(
            source: second.address, sequence: second.sequence, token: second.token,
            receivedAt: sentAt.advanced(by: .milliseconds(2)), ttl: 64
        ))
        #expect(await state.spreadBudget() > .zero)
    }

    @Test("A network whose tail budget is genuinely its tail gets no spread, and says so")
    func noHeadroomMeansNoSpread() async {
        // The honest limit of the technique. The spread is bought out of the gap
        // between the tail budget and what a reply actually needs, and on a network
        // with a 600 ms host on it there is no such gap. Reporting zero is the correct
        // answer: C8 is not closed on that network for free, and the artifact should
        // not imply that it was.
        let state = SweepState(
            pending: (60...63).map { Self.ip(UInt8($0)) }, neighbors: [:], attempts: 3,
            counters: ProbeCounters(), spacing: .spreadIntoTail
        )
        let due = await state.dueProbes(limit: 8)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))
        // Slow replies teach the network estimator that this is not a fast LAN, so its
        // tail budget is its own tail rather than the 250 ms floor.
        for probe in due {
            _ = await state.record(ICMPReply(
                source: probe.address, sequence: probe.sequence, token: probe.token,
                receivedAt: sentAt.advanced(by: .milliseconds(600)), ttl: 64
            ))
        }

        let tail = await state.tailBudget()
        let allowance = await state.replyAllowance()
        #expect(allowance >= tail, "a 600 ms host should consume the whole tail budget")
        #expect(await state.spreadBudget() == .zero)
    }

    @Test("Per-host scatter is deterministic, bounded, and actually scatters")
    func scatterIsDeterministicAndBounded() {
        // Deterministic because two scans of the same network must probe on the same
        // schedule or a difference between them cannot be attributed. Scattered because
        // one fixed gap can land on a periodic power-save cycle and put every
        // transmission to a host at the same phase of it.
        let policy = SweepSpacing.spreadIntoTail
        let addresses = (1...254).map { Self.ip(UInt8($0)) }
        let factors = addresses.map { policy.scatter(for: $0) }

        for address in addresses {
            #expect(policy.scatter(for: address) == policy.scatter(for: address))
        }
        #expect(factors.allSatisfy { $0 >= 1 - policy.jitter && $0 <= 1 + policy.jitter })
        #expect(Set(factors.map { ($0 * 1000).rounded() }).count > 150,
                "the scatter must actually vary between addresses")
        // Adjacent addresses must not land on adjacent phases: sleeping devices are
        // often a contiguous DHCP range, and scattering them together scatters nothing.
        let adjacent = zip(factors, factors.dropFirst()).map { abs($0 - $1) }
        let mean = adjacent.reduce(0, +) / Double(adjacent.count)
        #expect(mean > policy.jitter * 0.4, "adjacent addresses are too correlated: \(mean)")

        #expect(SweepSpacing.uniform.scatter(for: addresses[0]) == 1)
    }
}

@Suite("Descriptor lifetime")
struct DescriptorLifetimeTests {
    /// How many descriptors this process currently holds.
    ///
    /// Counted rather than checking one number: descriptor numbers are reissued the
    /// instant they are freed, and with tests running in parallel a freed number is
    /// usually valid again by the time it is looked at — which is precisely the reuse
    /// hazard, and makes an identity check on it flaky rather than wrong.
    static func openDescriptors() -> Int {
        (0..<Int32(getdtablesize())).reduce(into: 0) { total, fd in
            if fcntl(fd, F_GETFD) != -1 { total += 1 }
        }
    }

    @Test("Probing thousands of ports leaks no descriptors")
    func probesDoNotLeak() async {
        // Closing while a DispatchSource is still registered is a use-after-close;
        // NOT closing is a leak, and at twenty-five thousand probes a leak exhausts the
        // process limit and fails the scan. The fix has to do exactly one of them, and
        // this is the half a count can see.
        let loopback = IPv4Address("127.0.0.1")!
        let before = Self.openDescriptors()
        for _ in 0..<3 {
            await withTaskGroup(of: Void.self) { group in
                for port in UInt16(9)...UInt16(108) {
                    group.addTask {
                        // Bound, not discarded with `_ = await`. The two are the same
                        // program, and Swift 6.3.3's debug build aborts on the second
                        // ("freed pointer was not the last allocation", in this closure's
                        // swift_task_dealloc) once `PortObservation` carries an
                        // `IPv6Address?`. Reproduced on a clean tree by adding that one
                        // field; `String?`, `IPv4Address?` and `[IPAddress]` do not trigger
                        // it, ASan is clean, and production binds its result. See the
                        // C2 section of Docs/V6-progress.md.
                        let outcome = await TCPConnectScanEngine.probe(
                            .init(ip: loopback, port: port), budget: .milliseconds(80)
                        )
                        _ = outcome
                    }
                }
                await group.waitForAll()
            }
        }
        // Give any cancel handlers a moment to run; they are asynchronous by design.
        try? await Task.sleep(for: .milliseconds(200))
        let after = Self.openDescriptors()
        // A tolerance for descriptors other parallel tests happen to hold, but three
        // hundred probes leaking would show up as three hundred.
        #expect(after - before < 32, "before \(before), after \(after)")
    }

    @Test("Heavy concurrent probing never fabricates an open port")
    func reuseDoesNotFabricateOpenPorts() async {
        // The reuse hazard, exercised as directly as it can be without racing the
        // kernel deliberately: hundreds of short-lived descriptors opened and closed as
        // fast as possible against a port nothing is listening on. A stale source
        // firing on a reissued descriptor would read SO_ERROR of 0 and report the port
        // open with a sub-millisecond round trip.
        let loopback = IPv4Address("127.0.0.1")!
        let probes = (0..<300).map { _ in TCPConnectScanEngine.Probe(ip: loopback, port: 9) }
        var openCount = 0
        await withTaskGroup(of: Bool.self) { group in
            for probe in probes {
                group.addTask {
                    if case .observed(let observation, _) =
                        await TCPConnectScanEngine.probe(probe, budget: .milliseconds(150)) {
                        return observation.state == .open
                    }
                    return false
                }
            }
            for await wasOpen in group where wasOpen { openCount += 1 }
        }
        #expect(openCount == 0, "port 9 on loopback is not open; an 'open' here is fabricated")
    }

    @Test("A cancelled probe reports nothing rather than claiming silence")
    func cancellationDoesNotFabricateEvidence() async {
        // `.filtered` is a positive claim — "we asked and heard nothing". Manufacturing
        // it out of the fact that we stopped asking means Ctrl-C invents port evidence
        // for every host it interrupted.
        let task = Task {
            await TCPConnectScanEngine.probe(
                // A routable-but-silent address, so the probe waits rather than resolving.
                .init(ip: IPv4Address("10.255.255.1")!, port: 65_000),
                budget: .seconds(30)
            )
        }
        try? await Task.sleep(for: .milliseconds(60))
        task.cancel()
        let result = await task.value
        if case .cancelled = result {
            // Correct.
        } else {
            Issue.record("a cancelled probe must not report a port state, got \(result)")
        }
    }
}

@Suite("Counters describe the scanner, not the flags")
struct ConcurrencyAccountingTests {
    @Test("Peak concurrency never exceeds the configured window")
    func peakRespectsTheWindow() async {
        // `probeCompleted()` was never called anywhere, so in-flight only ever grew and
        // peak concurrency reported probes SENT. The one number in the artifact that
        // describes the scanner's own behaviour was a restatement of the work list.
        let window = 8
        let engine = TCPConnectScanEngine(concurrency: window)
        let result = await engine.scan(
            (1...12).map { IPv4Address(raw: 0x7F00_0000 | UInt32($0)) },
            ports: PortSpec([9, 19, 79]),
            perHostDeadline: .milliseconds(80),
            deadline: Deadline(after: .seconds(10))
        )
        let peak = result.timing.peakConcurrency
        #expect(peak > 0, "peak concurrency must be measured, not left at zero")
        #expect(peak <= window, "peak \(peak) exceeded the window of \(window)")
        // And the probes-sent count is genuinely the whole work list.
        #expect(result.timing.probesSent == 36)
    }

    @Test("Every probe that starts also completes")
    func inFlightReturnsToZero() {
        let counters = ProbeCounters()
        for _ in 0..<50 { counters.probeSent() }
        for _ in 0..<50 { counters.probeCompleted() }
        let snapshot = counters.snapshot()
        #expect(snapshot.inFlight == 0)
        #expect(snapshot.peakConcurrency == 50)
        #expect(snapshot.probesSent == 50)
    }
}

@Suite("Descriptor limits reflect what the kernel will issue")
struct DescriptorCeilingTests {
    @Test("The reported limit never exceeds kern.maxfilesperproc")
    func respectsPerProcessCeiling() {
        // RLIMIT_NOFILE is not the real ceiling. On this machine the hard limit reports
        // 9,223,372,036,854,775,807 while the kernel will not issue more than
        // kern.maxfilesperproc descriptors to one process — so deriving a window from
        // the former promises what cannot be delivered.
        let ceiling = DarwinResourceLimits.perProcessCeiling()
        #expect(ceiling > 0)
        let granted = DarwinResourceLimits().raiseDescriptorLimit()
        #expect(granted <= ceiling, "granted \(granted) exceeds the kernel ceiling \(ceiling)")
        #expect(granted >= 256)
        #expect(ConcurrencyBudget.fromDescriptorLimit(granted) <= 512)
    }

    @Test("An infinite hard limit does not overflow into a nonsense window")
    func infinityIsClamped() {
        #expect(DarwinResourceLimits.clamp(rlim_t.max) == 1_048_576)
        #expect(DarwinResourceLimits.clamp(256) == 256)
    }
}

@Suite("The receive loop drains the socket")
struct DrainTests {
    @Test("A datagram that is not an echo reply does not end the drain")
    func foreignDatagramIsNotEndOfQueue() throws {
        // The bug: the drain loop stopped at the first datagram it could not decode.
        // Destination-unreachable messages arrive routinely on an ICMP socket — one per
        // dead address a router bothers to answer for — so a burst of real replies was
        // left sitting in the buffer until the next readiness wake-up, and then stamped
        // with THAT wake-up's arrival time. The RTTs were inflated by however long the
        // socket sat idle, and those inflated numbers fed the adaptive timeout.
        //
        // Exercised over loopback UDP, which has the same recvmsg semantics.
        let receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        #expect(receiver >= 0)
        defer { close(receiver) }
        var bind4 = socketAddress(IPv4Address("127.0.0.1")!, port: 0)
        let bound = withUnsafePointer(to: &bind4) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
                bind(receiver, addr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        #expect(bound == 0)
        var actual = sockaddr_in()
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
                getsockname(receiver, addr, &size)
            }
        }
        _ = setNonBlocking(receiver)

        let sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        defer { close(sender) }
        var destination = actual
        // Two datagrams: neither is a valid echo reply, so neither decodes.
        for _ in 0..<2 {
            var junk: [UInt8] = [0x03, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]
            _ = junk.withUnsafeBytes { payload in
                withUnsafePointer(to: &destination) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
                        sendto(sender, payload.baseAddress, payload.count, 0,
                               addr, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        }
        // Give the loopback a moment.
        usleep(20_000)

        // Both must report as datagrams we could not use, NOT as an empty socket —
        // otherwise the loop stops and whatever is behind them waits for the next wake.
        for attempt in 1...2 {
            switch ICMPSocket.receive(receiver, at: .now) {
            case .datagram(let reply):
                #expect(reply == nil, "junk must not decode")
            case .drained:
                Issue.record("datagram \(attempt) ended the drain instead of being skipped")
            }
        }
        // And only once the socket is genuinely empty does it report drained.
        switch ICMPSocket.receive(receiver, at: .now) {
        case .drained: break
        case .datagram: Issue.record("socket should be empty")
        }
    }
}

@Suite("Bugs that were caught against a live network, not by a test")
struct LiveCaughtRegressionTests {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }

    @Test("The retransmit budget does not depend on dictionary iteration order")
    func budgetIsIndependentOfHashOrder() async throws {
        // A timeout that depends on hash order is not a timeout. The budget used to be
        // recomputed inside the loop over the send batch, and draining a stashed reply
        // updated the estimator mid-loop — so probes later in the batch got a different
        // window from probes earlier in it, and which addresses those were varied
        // between runs of the same scan.
        //
        // Asserted from the outside, over shuffled input, rather than by inspecting the
        // map: the property is that the assignment is a function of the measurements
        // alone, and an implementation that reintroduced the dependency by iterating a
        // different collection would still pass an inspection test.
        let addresses = (1...60).map { Self.ip(UInt8($0)) }

        func budgets(shuffling seed: Int) async -> [IPv4Address: Duration] {
            var generator = SplitMix(seed: UInt64(seed))
            let order = addresses.shuffled(using: &generator)
            let state = SweepState(
                pending: order, neighbors: [:], attempts: 3, counters: ProbeCounters()
            )
            let due = await state.dueProbes(limit: 512)
            let sentAt = MonotonicInstant.now
            // The instants are handed over as a dictionary, which is exactly where the
            // ordering entered.
            _ = await state.recordSends(
                Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) })
            )
            return await state.armedBudgets()
        }

        let first = await budgets(shuffling: 1)
        #expect(first.count == addresses.count)
        for seed in 2...6 {
            let next = await budgets(shuffling: seed)
            #expect(next == first, "budget assignment differed at seed \(seed)")
        }
        // And within one run every address got the SAME budget, which is the invariant
        // the snapshot exists to hold.
        #expect(Set(first.values).count == 1)
    }

    @Test("A reply that beats its own send registration is folded in, not dropped")
    func earlyReplyIsNotLost() async throws {
        // Caught only against a real network: a whole /24 is handed to the socket in one
        // batch taking about ten milliseconds, and a host on the same switch answers in
        // four hundred microseconds — so its reply arrived, decoded, and was delivered
        // before the send that caused it had been recorded. Dropping those made the
        // FASTEST hosts the ones most likely to be reported absent.
        let fast = Self.ip(1)
        let slow = Self.ip(2)
        let state = SweepState(pending: [fast, slow], neighbors: [:], attempts: 3, counters: ProbeCounters())
        let due = await state.dueProbes(limit: 8)
        let sentAt = MonotonicInstant.now
        let fastProbe = try #require(due.first { $0.address == fast })

        // Reply arrives first.
        let early = ICMPReply(source: fast, sequence: fastProbe.sequence, token: fastProbe.token,
                              receivedAt: sentAt.advanced(by: .microseconds(400)), ttl: 64)
        // Bound to a local rather than called inside `#expect`, which is the same
        // shape the `Span` parses elsewhere in these tests need.
        //
        // The inline form `#expect(await state.record(early) == nil)` started failing
        // when `HostFacts` gained its `Set` of discovery sources, and took the test
        // process down with SIGSEGV. The returned value is genuinely `nil` — printing
        // it from a local says so, and every assertion below about what the state then
        // does passes — so what broke is the macro form and not the behaviour. I could
        // not reduce it to a minimal case: an actor returning an optional Set-bearing
        // struct inside `#expect` is fine on its own, and `#expect` evaluates its
        // expression exactly once, so the trigger is narrower than either of those.
        // Recorded here rather than explained, because an explanation I cannot
        // demonstrate is a guess.
        let held = await state.record(early)
        #expect(held == nil, "held, not discarded")
        #expect(await state.discovered().isEmpty)

        // Registration second: the held reply is folded in, and it emits the event the
        // display would otherwise never have seen.
        let events = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))
        #expect(events.count == 1)
        let found = await state.discovered()
        #expect(found.count == 1)
        #expect(found[0].ip == fast)
        // Timed against its own send instant, so the batch position is not counted as
        // network latency.
        #expect((found[0].rtt?.millis ?? 99) < 1)
    }

    @Test("A reply that arrives after its window closed is counted as late")
    func lateReplyIsCounted() async throws {
        // `lateReplies` was declared, documented, and read to raise the degradation that
        // tells someone their per-host budgets are too tight — and incremented by
        // nothing, anywhere, so that degradation could never fire. `strayReplies`, which
        // is incremented, was read by nothing. The two were crossed, and the symptom was
        // silence: a network running tight looked exactly like one answering promptly.
        //
        // Found by checking an artifact against a packet capture. A host was reported
        // from the neighbour table while the capture plainly held an echo reply from it,
        // and the counter that exists to say "this network is answering slower than the
        // budgets allow" had been reporting zero the whole time.
        let host = Self.ip(3)
        let state = SweepState(pending: [host], neighbors: [:], attempts: 3, counters: ProbeCounters())
        let due = await state.dueProbes(limit: 4)
        let probe = try #require(due.first)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends([probe.token: sentAt])

        // Nothing late yet.
        let before = await state.lateReplies
        #expect(before == 0)

        // Push the clock past this probe's expiry, which marks it expired and leaves it
        // in flight so a straggler can still be attributed.
        _ = await state.dueProbes(limit: 4, now: sentAt.advanced(by: .seconds(5)))

        let straggler = ICMPReply(
            source: probe.address, sequence: probe.sequence, token: probe.token,
            receivedAt: sentAt.advanced(by: .seconds(4)), ttl: 64
        )
        let event = await state.record(straggler)
        #expect(event != nil, "a late reply is still a found host")
        let after = await state.lateReplies
        #expect(after == 1)
        // And it is not a stray: the token attributed it exactly.
        let strays = await state.strayReplies
        #expect(strays == 0)
    }

    @Test("Probes the kernel refuses do not requeue forever")
    func refusedSendsTerminate() async {
        // The requeue loop: an address whose send was refused was pushed back onto the
        // pending list with its attempt count decremented, so it was retried
        // indefinitely and the sweep ran to its full deadline on every single run.
        // A refused send spends the attempt.
        let state = SweepState(
            pending: (1...20).map { Self.ip(UInt8($0)) },
            neighbors: [:], attempts: 3, counters: ProbeCounters()
        )
        // Every batch is assigned and NOTHING is confirmed sent, which is what a kernel
        // refusing every datagram looks like from here.
        var batches = 0
        while batches < 50 {
            let due = await state.dueProbes(limit: 512, now: MonotonicInstant.now.advanced(by: .seconds(60)))
            if due.isEmpty { break }
            _ = await state.recordSends([:])
            batches += 1
        }
        #expect(batches < 50, "the transmit phase never terminated")
        #expect(await state.isSettled, "state must settle once attempts are spent")
        // Three attempts for twenty addresses, and not one more.
        #expect(batches <= 3)
    }
}

/// A deterministic generator, so a shuffle is reproducible and a failure can be rerun.
struct SplitMix: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { self.state = seed &* 0x9E37_79B9_7F4A_7C15 &+ 1 }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

@Suite("The sweep's two budgets are two different questions")
struct BudgetSplitTests {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }

    @Test("A slow outlier moves the tail budget and leaves the retransmit budget alone")
    func outlierMovesOnlyTheTail() async {
        // The arithmetic the split exists for. One 600 ms host among fast ones used to
        // widen the interval that 244 dead addresses each waited out three times.
        let state = SweepState(
            pending: (1...12).map { Self.ip(UInt8($0)) },
            neighbors: [:], attempts: 3, counters: ProbeCounters()
        )
        let due = await state.dueProbes(limit: 512)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))

        // Eleven fast hosts and one very slow one.
        for probe in due.dropLast() {
            _ = await state.record(ICMPReply(
                source: probe.address, sequence: probe.sequence, token: probe.token,
                receivedAt: sentAt.advanced(by: .milliseconds(10)), ttl: 64))
        }
        let retransmitBefore = await state.retransmitBudget()
        let tailBefore = await state.tailBudget()

        let slow = due.last!
        _ = await state.record(ICMPReply(
            source: slow.address, sequence: slow.sequence, token: slow.token,
            receivedAt: sentAt.advanced(by: .milliseconds(600)), ttl: 64))

        let retransmitAfter = await state.retransmitBudget()
        let tailAfter = await state.tailBudget()

        // The tail must notice: it is what stops the slow host being declared absent.
        #expect(tailAfter > tailBefore)
        // The retransmit interval must NOT: it is paid by every dead address, twice.
        #expect(retransmitAfter <= retransmitBefore + .milliseconds(5))
        // And it stays tight in absolute terms.
        #expect(retransmitAfter <= .milliseconds(150))
    }

    @Test("The retransmit interval tracks the low end, not the maximum")
    func retransmitTracksTheLowEnd() async {
        let state = SweepState(
            pending: (1...9).map { Self.ip(UInt8($0)) },
            neighbors: [:], attempts: 3, counters: ProbeCounters()
        )
        let due = await state.dueProbes(limit: 512)
        let sentAt = MonotonicInstant.now
        _ = await state.recordSends(Dictionary(uniqueKeysWithValues: due.map { ($0.token, sentAt) }))
        // Eight hosts at 8 ms, one at two seconds.
        for (index, probe) in due.enumerated() {
            let rtt: Duration = index == due.count - 1 ? .seconds(2) : .milliseconds(8)
            _ = await state.record(ICMPReply(
                source: probe.address, sequence: probe.sequence, token: probe.token,
                receivedAt: sentAt.advanced(by: rtt), ttl: 64))
        }
        // Median of the samples is 8 ms, so the interval is near its floor — the
        // two-second outlier does not enter it at all.
        #expect(await state.retransmitBudget() <= .milliseconds(30))
        // While the tail is dominated by exactly that outlier.
        #expect(await state.tailBudget() >= .milliseconds(250))
    }

    @Test("Quantiles are quantiles")
    func quantileArithmetic() {
        var samples = RTTQuantiles()
        #expect(samples.quantile(0.5) == nil)
        for value in [50, 10, 30, 20, 40] { samples.record(.milliseconds(value)) }
        #expect(samples.quantile(0) == .milliseconds(10))
        #expect(samples.quantile(0.5) == .milliseconds(30))
        #expect(samples.quantile(1) == .milliseconds(50))
        // Negative durations are not observations.
        samples.record(.milliseconds(-5))
        #expect(samples.count == 5)
    }
}


@Suite("What the artifact says about a privileged engine that did not run")
struct PrivilegedNoticeTests {
    @Test("Silence for the two states that are normal, a sentence for the rest")
    func noticeSuppression() {
        // Not being root is the normal state of this program, and so is having no
        // helper installed — most people never will. Either one producing a degradation
        // on every scan would train a reader to skip the list, which is exactly where
        // the things that cost them hosts appear.
        #expect(DarwinScanner.notice(for: .notPrivileged) == nil)
        #expect(DarwinScanner.notice(for: .helperAbsent) == nil)
        #expect(DarwinScanner.notice(for: nil) == nil)

        // A helper that is INSTALLED and refused is not normal and is reported, with
        // what it said, because that is a thing somebody can act on.
        let refused = DarwinScanner.notice(for: .helperRefused("it declined"))
        #expect(refused != nil)
        #expect(refused?.reason.contains("it declined") == true)
        #expect(refused?.recoverable == true)

        // So is a device held by tcpdump or Wireshark.
        #expect(DarwinScanner.notice(for: .allDevicesBusy(tried: 4)) != nil)
        #expect(DarwinScanner.notice(for: .notEthernet(dataLinkType: 12)) != nil)
    }
}

#endif
