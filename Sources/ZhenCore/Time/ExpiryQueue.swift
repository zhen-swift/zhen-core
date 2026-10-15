// ExpiryQueue.swift — what is due next, without looking at everything that was sent.
//
// ── Why this exists ───────────────────────────────────────────────────────────────
//
// Every engine that retransmits — the ICMP sweep, the layer-2 ARP sweep, the half-open
// SYN scan — runs the same loop: wake every one to ten milliseconds, ask which probes
// are due, send them, sleep until the next one is. Each of the three answered "which
// are due" and "when is the next one" by walking every probe it held. The ICMP sweep
// also keeps expired probes, so a late reply can still be attributed, which meant the
// walk grew with everything ever sent rather than with what was outstanding.
//
// That is O(N·k) per wake: about 760 entries on a /24, which is free, and about
// 196,000 on a /16, which is not. Worse than the CPU, the reply reader shares the
// engine's actor, so on a large target the bookkeeping delayed the reply timestamps
// the timing learns from. A scanner whose speed claim rests on measuring round trips
// cannot afford to inflate them with its own housekeeping.
//
// ── What it is ────────────────────────────────────────────────────────────────────
//
// A binary min-heap of deadlines with lazy deletion. Scheduling and popping are
// O(log n); cancelling is O(1) and leaves a stale entry that is discarded when it
// reaches the top. When stale entries outnumber live ones the heap is rebuilt in
// O(n), so memory stays proportional to what is outstanding and the amortised cost per
// operation stays logarithmic.
//
// Ties break on scheduling order. Two probes armed for the same instant come out in the
// order they were armed, so a schedule never depends on hash order — a defect this
// codebase has had twice already and tests for.
//
// Portable and free of I/O on purpose: it is the one piece of the three engines' timing
// that can be tested on Linux, and the complexity claim above is asserted there
// (`ExpiryQueueTests`) by counting comparisons rather than timing a machine.

/// Deadlines for outstanding probes, ordered by when each is due.
///
/// One entry per key: scheduling a key that is already scheduled replaces its deadline.
public struct ExpiryQueue<Key: Hashable & Sendable>: Sendable {
    private struct Entry: Sendable {
        var at: MonotonicInstant
        var order: UInt64
        var key: Key
    }

    private var heap: [Entry] = []
    /// The scheduling order of each key's CURRENT entry. An entry in the heap whose
    /// order does not match is stale — cancelled, popped, or superseded.
    private var live: [Key: UInt64] = [:]
    private var nextOrder: UInt64 = 0

    /// Element comparisons performed so far. Test support for the complexity claim:
    /// counting work is deterministic where timing it is not.
    internal private(set) var comparisons = 0

    /// An empty queue.
    public init() {}

    /// How many keys are scheduled.
    public var count: Int { live.count }

    /// Whether nothing is scheduled.
    public var isEmpty: Bool { live.isEmpty }

    /// Whether `key` is scheduled.
    public func contains(_ key: Key) -> Bool { live[key] != nil }

    /// Schedules `key` to fall due at `instant`, replacing any earlier schedule for it.
    public mutating func schedule(_ key: Key, at instant: MonotonicInstant) {
        let order = nextOrder
        nextOrder &+= 1
        live[key] = order
        heap.append(Entry(at: instant, order: order, key: key))
        siftUp(from: heap.count - 1)
        compactIfMostlyStale()
    }

    /// Unschedules `key`. A no-op when it is not scheduled.
    public mutating func cancel(_ key: Key) {
        guard live.removeValue(forKey: key) != nil else { return }
        compactIfMostlyStale()
    }

    /// The earliest deadline still scheduled.
    ///
    /// Mutating because it discards stale entries it finds on top — which is where the
    /// cost of a cancellation is actually paid.
    public mutating func nextDeadline() -> MonotonicInstant? {
        dropStaleTop()
        return heap.first?.at
    }

    /// Removes and returns the earliest key whose deadline is at or before `now`.
    public mutating func popFirst(dueBy now: MonotonicInstant) -> Key? {
        dropStaleTop()
        guard let top = heap.first, top.at <= now else { return nil }
        removeTop()
        live[top.key] = nil
        return top.key
    }

    // ── Heap ──────────────────────────────────────────────────────────────────────

    private mutating func precedes(_ a: Int, _ b: Int) -> Bool {
        comparisons += 1
        let lhs = heap[a], rhs = heap[b]
        return lhs.at == rhs.at ? lhs.order < rhs.order : lhs.at < rhs.at
    }

    private func isCurrent(_ entry: Entry) -> Bool { live[entry.key] == entry.order }

    private mutating func dropStaleTop() {
        while let top = heap.first, !isCurrent(top) { removeTop() }
    }

    private mutating func removeTop() {
        let last = heap.removeLast()
        guard !heap.isEmpty else { return }
        heap[0] = last
        siftDown(from: 0)
    }

    private mutating func siftUp(from index: Int) {
        var child = index
        while child > 0 {
            let parent = (child - 1) / 2
            guard precedes(child, parent) else { return }
            heap.swapAt(child, parent)
            child = parent
        }
    }

    private mutating func siftDown(from index: Int) {
        var parent = index
        while true {
            let left = 2 * parent + 1
            guard left < heap.count else { return }
            let right = left + 1
            var first = left
            if right < heap.count, precedes(right, left) { first = right }
            guard precedes(first, parent) else { return }
            heap.swapAt(first, parent)
            parent = first
        }
    }

    /// Rebuilds without stale entries once they are the majority.
    ///
    /// The threshold keeps memory proportional to what is live, and because a rebuild
    /// costs O(n) and only happens after at least n/2 cancellations, its cost spread
    /// over those operations is constant.
    private mutating func compactIfMostlyStale() {
        guard heap.count > 64, heap.count > 2 * live.count else { return }
        // Read through a copy: a closure capturing `self` while `heap` is being mutated
        // is an overlapping access, and the compiler is right to refuse it.
        let current = live
        heap.removeAll { current[$0.key] != $0.order }
        var index = heap.count / 2
        while index > 0 {
            index -= 1
            siftDown(from: index)
        }
    }
}
