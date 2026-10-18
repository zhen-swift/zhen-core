import Foundation
import Testing
@testable import ZhenCore

@Suite("Fan-out and counters")
struct ConcurrencyTests {
    @Test("Counters are relaxed atomics and still count correctly under fan-out")
    func countersAreCorrect() async {
        let counters = ProbeCounters()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<200 {
                group.addTask {
                    counters.probeSent()
                    counters.replySeen()
                    counters.probeCompleted()
                }
            }
        }
        let snapshot = counters.snapshot()
        // Relaxed ordering does not mean lossy: the increments are atomic, they just
        // do not order anything else.
        #expect(snapshot.probesSent == 200)
        #expect(snapshot.repliesSeen == 200)
        #expect(snapshot.inFlight == 0)
        #expect(snapshot.peakConcurrency >= 1)
        #expect(snapshot.peakConcurrency <= 200)
    }

    @Test("Peak concurrency records the high-water mark, not the current one")
    func peakIsAHighWaterMark() {
        let counters = ProbeCounters()
        for _ in 0..<8 { counters.probeSent() }
        for _ in 0..<8 { counters.probeCompleted() }
        let snapshot = counters.snapshot()
        #expect(snapshot.inFlight == 0)
        #expect(snapshot.peakConcurrency == 8)
    }

    @Test("The lock fallback counts what the atomics count", arguments: [false, true])
    func storagesAgree(locked: Bool) async {
        // Run on this machine, `ProbeCounters()` always takes the atomics. This drives each
        // storage directly, so the macOS 14 path is not left to the one OS CI never runs.
        func fresh() -> ProbeCounters? {
            if locked { return ProbeCounters(storage: LockedCounters()) }
            if #available(macOS 15, iOS 18, *) { return ProbeCounters(storage: AtomicCounters()) }
            return nil
        }
        guard let counters = fresh(), let peaks = fresh() else { return }
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<200 {
                group.addTask {
                    counters.probeSent()
                    counters.replySeen()
                    counters.probeCompleted()
                }
            }
        }
        #expect(counters.snapshot().probesSent == 200)
        #expect(counters.snapshot().repliesSeen == 200)
        #expect(counters.snapshot().inFlight == 0)

        for _ in 0..<8 { peaks.probeSent() }
        for _ in 0..<8 { peaks.probeCompleted() }
        #expect(peaks.snapshot().inFlight == 0)
        #expect(peaks.snapshot().peakConcurrency == 8)
    }

    @Test("Discarding fan-out visits everything and keeps nothing")
    func fanOutVisitsEverything() async {
        let counters = ProbeCounters()
        await discardingFanOut(
            over: Array(1...500),
            concurrency: 16,
            deadline: Deadline(after: .seconds(10))
        ) { _ in
            counters.probeSent()
            counters.probeCompleted()
        }
        #expect(counters.snapshot().probesSent == 500)
    }

    @Test("Discarding fan-out honours its concurrency window")
    func fanOutIsBounded() async {
        let counters = ProbeCounters()
        await discardingFanOut(
            over: Array(1...200),
            concurrency: 8,
            deadline: Deadline(after: .seconds(10))
        ) { _ in
            counters.probeSent()
            try? await Task.sleep(for: .milliseconds(1))
            counters.probeCompleted()
        }
        // Bounding what is in flight is what bounds the latency tail; an unbounded
        // fan-out here would show a peak of 200.
        #expect(counters.snapshot().peakConcurrency <= 8)
        #expect(counters.snapshot().probesSent == 200)
    }

    @Test("Discarding fan-out returns at its deadline with work unfinished")
    func fanOutStopsAtDeadline() async {
        let counters = ProbeCounters()
        let watch = Stopwatch()
        await discardingFanOut(
            over: Array(1...10_000),
            concurrency: 4,
            deadline: Deadline(after: .milliseconds(150))
        ) { _ in
            counters.probeSent()
            try? await Task.sleep(for: .milliseconds(5))
            counters.probeCompleted()
        }
        #expect(watch.elapsedMillis < 3000)
        #expect(counters.snapshot().probesSent < 10_000)
    }

    @Test("Concurrency is derived from the descriptor limit actually granted")
    func concurrencyFromDescriptorLimit() {
        // The macOS default. A quarter of 256 is 64 — not the 25,400 probes a /24
        // deep scan wants, which is exactly why this must not be a constant.
        #expect(ConcurrencyBudget.fromDescriptorLimit(256) == 64)
        // Raised to a typical hard limit.
        #expect(ConcurrencyBudget.fromDescriptorLimit(10_240) == 512)
        // Never zero, whatever the limit says.
        #expect(ConcurrencyBudget.fromDescriptorLimit(0) == 1)
        #expect(ConcurrencyBudget.fromDescriptorLimit(2) == 1)
    }

    @Test("The rate-derived window is still clamped by the descriptors that exist")
    func rateIsClampedByDescriptors() {
        // Little's law wants 1,000 in flight; 256 descriptors permit 64.
        let window = ConcurrencyBudget.forRate(
            probesPerSecond: 5000, meanRTT: .milliseconds(200), descriptorLimit: 256
        )
        #expect(window == 64)

        // With headroom, the measurement wins.
        let roomy = ConcurrencyBudget.forRate(
            probesPerSecond: 5000, meanRTT: .milliseconds(200), descriptorLimit: 10_240
        )
        #expect(roomy == 512)
    }
}

@Suite("Backpressure is declared")
struct ProbeStreamTests {
    @Test("There is no unbounded buffering policy to reach for")
    func noUnboundedPolicy() {
        // The absence is the design: a progress stream that can accumulate 65,000
        // events while a list renders 30 is a memory leak with a progress bar on it.
        // `BufferingPolicy` is not Equatable, so this is asserted structurally — the
        // switch is exhaustive, and adding an `.unbounded` case to StreamBuffering
        // would stop it compiling and force the argument to be had in review.
        for buffering in [StreamBuffering.progress, .newest(10), .oldest(10)] {
            switch buffering {
            case .progress, .newest, .oldest: break
            }
        }
    }

    @Test("An oldest-first stream keeps the beginning of the sequence")
    func oldestWins() async {
        let (stream, continuation) = ProbeStream.make(buffering: .oldest(2))
        for index in 0..<10 {
            continuation.yield(.stageProgress(.discovery, completed: index, total: 10))
        }
        continuation.finish()

        var seen: [Int] = []
        for await event in stream {
            if case .stageProgress(_, let completed, _) = event { seen.append(completed) }
        }
        #expect(seen == [0, 1])
    }

    @Test("A lossy progress stream drops the oldest events, keeping current state")
    func newestWins() async {
        let (stream, continuation) = ProbeStream.make(buffering: .newest(2))
        for index in 0..<10 {
            continuation.yield(.stageProgress(.discovery, completed: index, total: 10))
        }
        continuation.finish()

        var seen: [Int] = []
        for await event in stream {
            if case .stageProgress(_, let completed, _) = event { seen.append(completed) }
        }
        // A consumer that fell behind wants the current state, not a replay.
        #expect(seen == [8, 9])
    }

    @Test("onTermination fires on consumer cancellation, which is where sockets close")
    func terminationFiresOnCancellation() async {
        let closed = ProbeCounters()
        let (stream, continuation) = ProbeStream.make(buffering: .progress) { _ in
            closed.replySeen()
        }
        continuation.yield(.stageStarted(.discovery))

        let consumer = Task {
            for await _ in stream { break }
        }
        await consumer.value
        continuation.finish()
        // Give the termination handler a turn to run.
        try? await Task.sleep(for: .milliseconds(50))
        #expect(closed.snapshot().repliesSeen >= 1)
    }

    @Test("The sink bridges an engine's emissions into the stream")
    func sinkFeedsStream() async {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        sink(.stageStarted(.discovery))
        sink(.degraded(Degradation(stage: .naming, reason: "no responder", recoverable: true)))
        finish()

        var kinds: [String] = []
        for await event in stream {
            switch event {
            case .stageStarted: kinds.append("started")
            case .degraded: kinds.append("degraded")
            default: kinds.append("other")
            }
        }
        #expect(kinds == ["started", "degraded"])
    }
}

@Suite("Bounded pool semantics")
struct BoundedPoolSemanticsTests {
    @Test("Silence is dropped, so the result count is probes answered not probes sent")
    func silenceIsDropped() async {
        // This is the bug the original signature had: with `-> Out?`, Out bound to the
        // Optional and every silent probe was stored, making a dead network look fully
        // populated.
        let results = await boundedPool(
            over: Array(1...100),
            concurrency: 8,
            deadline: Deadline(after: .seconds(5))
        ) { item in
            item.isMultiple(of: 10) ? .observed(item) : .silent
        }
        #expect(results.results.count == 10)
        #expect(results.results[7] == nil)
        #expect(results.results[70] == 70)
    }

    @Test("ProbeOutcome bridges from an Optional explicitly when a boundary forces one")
    func bridgesFromOptional() {
        #expect(ProbeOutcome(42).value == 42)
        #expect(ProbeOutcome(Int?.none).value == nil)
        #expect(ProbeOutcome<Int>.silent.value == nil)
    }

    @Test("Zero concurrency or no items is an empty result, not a hang")
    func degenerateInputs() async {
        let none = await boundedPool(over: [Int](), concurrency: 8, deadline: Deadline(after: .seconds(1))) {
            ProbeOutcome.observed($0)
        }
        #expect(none.results.isEmpty)

        let stalled = await boundedPool(over: [1, 2], concurrency: 0, deadline: Deadline(after: .seconds(1))) {
            ProbeOutcome.observed($0)
        }
        #expect(stalled.results.isEmpty)
    }

    @Test("An already-expired deadline returns immediately with what it has")
    func expiredDeadlineReturnsFast() async {
        let watch = Stopwatch()
        let results = await boundedPool(
            over: Array(1...1000),
            concurrency: 4,
            deadline: .expired
        ) { item in
            try? await Task.sleep(for: .milliseconds(50))
            return .observed(item)
        }
        #expect(watch.elapsedMillis < 2000)
        #expect(results.results.count < 1000)
    }
}
