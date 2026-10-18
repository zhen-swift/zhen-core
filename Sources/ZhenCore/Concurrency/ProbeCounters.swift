// ProbeCounters.swift — statistics off the fan-out path.
//
// Probes sent, replies seen and peak concurrency are incremented from every probe
// task, which on a /24 deep scan is roughly 25,000 tasks and a comparable number of
// increments. They are statistics: nothing in the scanner reads one to decide
// anything, and nothing else is ordered against them.
//
// So they are `Atomic` with `.relaxed` ordering, not a `Mutex` and not sequential
// consistency. Relaxed is the correct memory ordering for a counter that orders
// nothing — acquiring and releasing on every increment buys a happens-before edge
// nobody consumes, and pays for it in cache-line traffic on exactly the path that has
// to stay fast. This is the specialization paper's fifth principle at the smallest
// possible scale: no data-structure locking and no cache-line contention on the
// fan-out path (Marinos et al., SIGCOMM '14).
//
// The consequence to be honest about: a snapshot taken while probes are in flight can
// observe counters that are individually current and mutually inconsistent — more
// replies than probes, briefly. That is fine here, because the snapshot that reaches
// the artifact is taken after the stage has retired, and an intermediate snapshot is
// feeding a progress indicator that is about to be redrawn anyway.
//
// Below macOS 15 there is no `Atomic`, and the counters sit behind a lock instead
// (`LockedCounters`). That trades the argument above for a floor of 14, on the one OS
// where there is no other choice, and nowhere else.

import Foundation
import Synchronization

/// An immutable reading of the counters.
public struct ProbeCounterSnapshot: Sendable, Hashable {
    /// Probes put on the wire.
    public var probesSent: Int
    /// Replies received.
    public var repliesSeen: Int
    /// The high-water mark of simultaneously in-flight probes.
    public var peakConcurrency: Int
    /// How many probes are in flight at the moment of the snapshot.
    public var inFlight: Int

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(probesSent: Int, repliesSeen: Int, peakConcurrency: Int, inFlight: Int) {
        self.probesSent = probesSent
        self.repliesSeen = repliesSeen
        self.peakConcurrency = peakConcurrency
        self.inFlight = inFlight
    }
}

/// Shared counters for one stage of a scan.
///
/// A final class rather than a struct because every probe task shares one instance.
/// Where `Atomic` exists it holds only atomics, so it is `Sendable` without an actor
/// and without a lock. Below macOS 15 it holds a lock instead. See `LockedCounters`.
public final class ProbeCounters: Sendable {
    private let storage: any CounterStorage

    /// Fresh counters at zero.
    public convenience init() {
        if #available(macOS 15, iOS 18, *) {
            self.init(storage: AtomicCounters())
        } else {
            self.init(storage: LockedCounters())
        }
    }

    /// Counters over the given storage. Internal so a test can run both against the
    /// same expectations; a caller gets the one its OS allows.
    init(storage: any CounterStorage) {
        self.storage = storage
    }

    /// Records a probe going out, and the in-flight count rising.
    ///
    /// Pair with `probeCompleted()`. The peak is maintained here rather than sampled
    /// on a timer because the interesting moment is by definition the busiest one and
    /// a sampler would miss it.
    public func probeSent() { storage.probeSent() }

    /// Records a probe finishing, answered or not.
    public func probeCompleted() { storage.probeCompleted() }

    /// Records a reply arriving.
    public func replySeen() { storage.replySeen() }

    /// Reads all four counters.
    ///
    /// Not a consistent snapshot across the four — see the file header. Take it after
    /// a stage retires if you need one that is.
    public func snapshot() -> ProbeCounterSnapshot { storage.snapshot() }
}

/// Where the four counts live. Two conformances, because `Atomic` is macOS 15+ and
/// the package floor is 14.
protocol CounterStorage: Sendable {
    func probeSent()
    func probeCompleted()
    func replySeen()
    func snapshot() -> ProbeCounterSnapshot
}

/// The counters as relaxed atomics. What every OS with Synchronization gets, and the
/// reasoning in the file header is about this one.
@available(macOS 15, iOS 18, *)
final class AtomicCounters: CounterStorage {
    private let sent = Atomic<Int>(0)
    private let replies = Atomic<Int>(0)
    private let flight = Atomic<Int>(0)
    private let peak = Atomic<Int>(0)

    func probeSent() {
        sent.wrappingAdd(1, ordering: .relaxed)
        let now = flight.wrappingAdd(1, ordering: .relaxed).newValue
        // Compare-exchange loop rather than a plain store: two tasks raising the peak
        // at once would otherwise race and the lower one could land last. Relaxed on
        // both sides — the loop's correctness comes from the exchange being atomic,
        // not from any ordering against other memory.
        var observed = peak.load(ordering: .relaxed)
        while now > observed {
            let (exchanged, current) = peak.compareExchange(
                expected: observed, desired: now, ordering: .relaxed
            )
            if exchanged { break }
            observed = current
        }
    }

    func probeCompleted() {
        flight.wrappingSubtract(1, ordering: .relaxed)
    }

    func replySeen() {
        replies.wrappingAdd(1, ordering: .relaxed)
    }

    func snapshot() -> ProbeCounterSnapshot {
        ProbeCounterSnapshot(
            probesSent: sent.load(ordering: .relaxed),
            repliesSeen: replies.load(ordering: .relaxed),
            peakConcurrency: peak.load(ordering: .relaxed),
            inFlight: flight.load(ordering: .relaxed)
        )
    }
}

/// The counters behind one lock, for macOS 14, where `Atomic` does not exist.
///
/// It is the contention the file header argues against, and it is accepted here
/// because it is bounded. A /24 deep scan is about 25,000 increments, each holding the
/// lock for a few additions, against probes that each wait milliseconds on the
/// network. It also gives the one thing the atomics do not: a snapshot that is
/// consistent across all four.
///
/// `@unchecked Sendable`: every stored `var` is read and written only inside
/// `lock.withLock`, and `lock` is a `let`.
final class LockedCounters: CounterStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var counts = ProbeCounterSnapshot(probesSent: 0, repliesSeen: 0, peakConcurrency: 0, inFlight: 0)

    func probeSent() {
        lock.withLock {
            counts.probesSent += 1
            counts.inFlight += 1
            counts.peakConcurrency = max(counts.peakConcurrency, counts.inFlight)
        }
    }

    func probeCompleted() {
        lock.withLock { counts.inFlight -= 1 }
    }

    func replySeen() {
        lock.withLock { counts.repliesSeen += 1 }
    }

    func snapshot() -> ProbeCounterSnapshot {
        lock.withLock { counts }
    }
}
