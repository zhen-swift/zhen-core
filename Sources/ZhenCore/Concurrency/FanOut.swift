// FanOut.swift — fan-out that must not accumulate.
//
// `boundedPool` returns a dictionary, so it has to retain every child's result until
// the group retires. That is correct when the caller wants the results and wrong when
// they are being delivered through a continuation as they arrive: a regular
// `withTaskGroup` over 25,000 probes holds 25,000 results the caller already consumed.
//
// `withDiscardingTaskGroup` is the fix — it retains nothing — and this is the shape
// the streaming half of every engine is built on. Memory stays flat regardless of how
// many addresses are swept.
//
// Bounding concurrency inside a discarding group needs a different technique than in a
// regular one, and the difference is easy to get wrong. A `DiscardingTaskGroup` has no
// `next()`, so there is no completion to await and no way to refill a sliding window.
// The alternative usually reached for is a counting semaphore, which means
// continuations, which means a cancellation path where a waiter can be left suspended
// forever and the group never retires. Instead: spawn exactly `concurrency` worker
// tasks and have them pull from a shared cursor. No continuations, no semaphore, exact
// concurrency, and cancellation works because a worker checks between items and the
// cursor never suspends for long.

/// Hands out items to a fixed set of workers.
///
/// An actor because the workers share it; it holds an index and nothing else, so the
/// hop is cheap relative to the network probe on the other side of it.
private actor ItemCursor<Item: Sendable> {
    private let items: [Item]
    private var next = 0

    init(_ items: [Item]) { self.items = items }

    func take() -> Item? {
        guard next < items.count else { return nil }
        defer { next += 1 }
        return items[next]
    }
}

/// Runs `work` over `items` with at most `concurrency` in flight, discarding results,
/// stopping at `deadline`.
///
/// For fan-out where results are delivered through a continuation rather than
/// returned. Never throws; returns when the work is done, the budget expires, or the
/// calling task is cancelled.
///
/// - Parameters:
///   - items: what to probe.
///   - concurrency: how many workers to run. Derived, not guessed — see
///     `ConcurrencyBudget`.
///   - deadline: when to stop.
///   - work: the probe. Its result is discarded; it delivers through a continuation
///     or a counter.
public func discardingFanOut<Item: Sendable>(
    over items: [Item],
    concurrency: Int,
    deadline: Deadline,
    work: @escaping @Sendable (Item) async -> Void
) async {
    guard !items.isEmpty, concurrency > 0 else { return }
    let cursor = ItemCursor(items)
    let workers = min(concurrency, items.count)

    // The discarding group cannot cancel itself on a timer — a child has no handle on
    // its own group. So the timer is a sibling in an enclosing regular group of two,
    // whose results are two Voids rather than 25,000 probe results. Whichever finishes
    // first, cancelling the enclosing group propagates into the discarding group's
    // children, and the workers observe it between items.
    await withTaskGroup(of: Void.self) { outer in
        outer.addTask {
            try? await Task.sleep(for: deadline.remaining)
        }
        outer.addTask {
            await withDiscardingTaskGroup { group in
                for _ in 0..<workers {
                    group.addTask {
                        while !Task.isCancelled, let item = await cursor.take() {
                            await work(item)
                        }
                    }
                }
            }
        }
        await outer.next()
        outer.cancelAll()
    }
}

/// How many probes to keep in flight.
///
/// Both derivations are here rather than at call sites so the reasoning is in one
/// place and testable without a socket.
public enum ConcurrencyBudget {
    /// The ceiling imposed by the descriptor limit actually granted.
    ///
    /// `RLIMIT_NOFILE` is 256 soft on macOS. A /24 across 100 ports is roughly 25,400
    /// probes, and at 256 descriptors the first deep scan fails confusingly rather
    /// than slowly. The platform raises the limit to the hard value at startup, and
    /// this derives the window from what was actually granted — never from a
    /// constant, because the granted value differs by machine and by how the process
    /// was launched.
    ///
    /// The quarter is headroom for everything else the process has open: the store,
    /// a TLS session, stdio, and the dozen descriptors a Swift runtime holds without
    /// being asked.
    public static func fromDescriptorLimit(_ limit: Int) -> Int {
        max(1, min(512, limit / 4))
    }

    /// The window a target rate implies, given measured latency.
    ///
    /// Little's law: in-flight = rate × mean time in system. 5,000 probes per second
    /// against a 200 ms mean RTT needs 1,000 outstanding. This is why the window is
    /// derived from measurement rather than chosen, and why it must move as the sweep
    /// learns the network — a window sized for the internet is an order of magnitude
    /// too large for a LAN, and oversubscribing produces exactly the long timeout tail
    /// that costs more wall-clock than it saves.
    ///
    /// Always clamped by `fromDescriptorLimit`: the arithmetic does not know how many
    /// descriptors exist.
    public static func forRate(
        probesPerSecond: Double,
        meanRTT: Duration,
        descriptorLimit: Int
    ) -> Int {
        let wanted = RTTEstimator.inFlightForRate(probesPerSecond: probesPerSecond, meanRTT: meanRTT)
        return max(1, min(wanted, fromDescriptorLimit(descriptorLimit)))
    }
}
