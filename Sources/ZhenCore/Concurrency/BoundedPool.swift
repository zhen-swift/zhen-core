// BoundedPool.swift — bounded concurrency with a hard wall-clock ceiling.
//
// The non-throwing shape is the point: a probe that gets no reply is a data point,
// not an error. Throwing would discard the partial work of every sibling, and partial
// results are a normal outcome here.
//
// Why the window is bounded at all, rather than firing everything at once: latency
// variance comes from queueing, and bounding what is in flight bounds the tail far
// better than going faster does (Grosvenor et al., NSDI '15). The naive scanner that
// fires 25,000 probes simultaneously produces a long tail of timeouts that costs more
// wall-clock than the queue ever saved. Little's law then says what the window should
// be — see `RTTEstimator.inFlightForRate(probesPerSecond:meanRTT:)` — and it must move
// as the sweep learns the network's real latency rather than being a constant.
//
// This does NOT make blocking work interruptible. `Task.cancel()` is cooperative: a
// task blocked in `connect()` stays blocked, and the group will not return until its
// child does. Every leaf operation must be non-blocking or carry a kernel timeout.
// This is the single most likely way the implementation above this file goes wrong.
//
// ── Closing the gap in the original signature ────────────────────────────────────
//
// The brief specifies:
//
//     public func boundedPool<Item: Sendable, Out: Sendable>(
//         over items: [Item], concurrency: Int, deadline: Deadline,
//         onProgress: (@Sendable (Int, Int) -> Void)? = nil,
//         work: @Sendable @escaping (Item) async -> Out?
//     ) async -> [Item: Out]
//
// which does not compile: `Item` is a dictionary key and must be `Hashable`. That is
// the obvious half. The half that actually bites is `work: (Item) async -> Out?`
// together with `-> [Item: Out]`, and it is worth spelling out because it compiles
// and is wrong.
//
// Given a closure whose body has type `Int?`, the solver has two valid bindings:
// `Out == Int` (the intended one) and `Out == Int?` (where the "absent" case is a
// perfectly good value of `Out`). It picks the second. The result is a
// `[Int: Int?]` in which nothing is ever dropped, every silent probe is stored as a
// present-but-nil entry, and `results.count` equals the number of probes SENT rather
// than the number ANSWERED. In a scanner, that is the difference between "every host
// on the network is up" and the truth. The failing `nilResultsAreDropped` test in the
// existing suite is exactly this bug, caught.
//
// The fix is to stop overloading `Optional` to mean two things at once. `work`
// returns `ProbeOutcome<Out>`, which has no second reading. The old ambiguous shape
// is kept as an `@available(*, unavailable)` overload so that writing it is a compile
// error with an explanation, rather than silently resolving to something else.

/// Whether a probe produced an observation.
///
/// Deliberately not `Optional`. Beyond the inference problem in the file header, the
/// domain distinction is real and worth a name: silence is a *result* in this system,
/// not a missing one. It is what separates `.filtered` from `.closed`, and modelling
/// it as "no value" is the same collapse this project refuses to make about ports.
public enum ProbeOutcome<Value: Sendable>: Sendable {
    /// Something answered.
    case observed(Value)
    /// Nothing answered within the budget. Not an error.
    case silent

    /// The observation, if there was one.
    public var value: Value? {
        switch self {
        case .observed(let value): value
        case .silent: nil
        }
    }

    /// Bridges from an `Optional` at a boundary where one is unavoidable.
    ///
    /// Explicit rather than implicit: at a call site the conversion is visible and
    /// deliberate, which is the property the inference problem cost us.
    public init(_ value: Value?) {
        self = value.map(ProbeOutcome.observed) ?? .silent
    }
}

extension ProbeOutcome: Equatable where Value: Equatable {}
extension ProbeOutcome: Hashable where Value: Hashable {}

/// Why a bounded run stopped.
///
/// Without this, all three endings return the same dictionary and a caller cannot
/// tell them apart — and it cannot infer the answer either, because a short result
/// is ambiguous *by design*: silent probes are dropped, so "fewer results than items"
/// is the normal shape of a successful sweep across a mostly-empty network.
///
/// That gap mattered beyond ergonomics. `Outcome.deadlineExpired` and
/// `Outcome.cancelled` are load-bearing success values in the model — the CLI exits
/// zero on them and the app renders a partial-result banner from them — and core's
/// own fan-out primitive could not produce either.
public enum PoolTermination: Sendable, Hashable, CaseIterable {
    /// Every item was probed. The results are exhaustive for the items given.
    case exhausted
    /// The budget ran out with work outstanding. A success carrying partial results.
    case deadlineExpired
    /// The enclosing task was cancelled — Ctrl-C, a consumer walking away from a
    /// stream, a parent group failing. Also partial, also not an error.
    case cancelled

    /// The run outcome this termination maps to, so a stage can hand it straight to
    /// `ScanRun.outcome` without a switch at every call site.
    public var outcome: Outcome {
        switch self {
        case .exhausted: .complete
        case .deadlineExpired: .deadlineExpired
        case .cancelled: .cancelled
        }
    }
}

/// What a bounded run produced, and why it stopped.
public struct BoundedPoolRun<Item: Sendable & Hashable, Out: Sendable>: Sendable {
    /// Observations, keyed by the item that produced them. Items whose probe was
    /// silent are absent — which is why `results.count` cannot be used to infer
    /// whether the run finished.
    public var results: [Item: Out]
    /// Why the run stopped.
    public var termination: PoolTermination
    /// How many items were probed to completion, answered or not. Together with
    /// `total` this is the unambiguous progress figure that `results.count` is not.
    public var completed: Int
    /// How many items the run was given.
    public var total: Int

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(results: [Item: Out], termination: PoolTermination, completed: Int, total: Int) {
        self.results = results
        self.termination = termination
        self.completed = completed
        self.total = total
    }

    /// Items left unprobed when the run stopped.
    public var abandoned: Int { max(0, total - completed) }
}

/// Runs `work` over `items` with at most `concurrency` in flight, abandoning whatever
/// has not finished by `deadline`.
///
/// Returns results for the items that produced an observation, together with the
/// reason the run stopped. Never throws: neither an expired budget nor cancellation
/// is an error here, and both carry real partial results.
///
/// - Parameters:
///   - items: what to probe. Duplicates collapse, since the result is keyed by item.
///   - concurrency: how many probes may be in flight at once. Derive it — from the
///     descriptor limit actually granted, and from measured RTT via Little's law —
///     rather than picking a constant.
///   - deadline: when to stop and return what is in hand.
///   - onProgress: called as `(completed, total)` from arbitrary tasks, so it must be
///     safe to call concurrently.
///   - work: the probe. Returns `.observed(x)` or `.silent`.
/// - Returns: the observations and a `PoolTermination` saying why it ended.
public func boundedPool<Item: Sendable & Hashable, Out: Sendable>(
    over items: [Item],
    concurrency: Int,
    deadline: Deadline,
    onProgress: (@Sendable (Int, Int) -> Void)? = nil,
    work: @Sendable @escaping (Item) async -> ProbeOutcome<Out>
) async -> BoundedPoolRun<Item, Out> {
    let total = items.count
    guard total > 0, concurrency > 0 else {
        // Nothing to do is `.exhausted`, not a failure: a caller handed an empty
        // list and every item in it was probed.
        return BoundedPoolRun(
            results: [:],
            termination: Task.isCancelled ? .cancelled : .exhausted,
            completed: 0,
            total: total
        )
    }

    var results: [Item: Out] = [:]
    results.reserveCapacity(total)
    var completed = 0
    var termination: PoolTermination = .exhausted

    await withTaskGroup(of: (Item, ProbeOutcome<Out>)?.self) { group in
        // The timer is a sibling child that returns nil. When it fires it cancels
        // the group; when the work finishes first, we cancel it.
        group.addTask {
            try? await Task.sleep(for: deadline.remaining)
            return nil
        }

        var next = 0
        let window = min(concurrency, total)
        while next < window {
            let item = items[next]
            group.addTask { (item, await work(item)) }
            next += 1
        }

        while let finished = await group.next() {
            guard let (item, outcome) = finished else {
                // The timer child returned. Distinguish the two ways that happens:
                // an external cancellation makes `Task.sleep` throw immediately, so
                // the nil arrives at once and reading it as a deadline hit would
                // report the wrong outcome for every Ctrl-C. `Task.isCancelled` here
                // reflects the ENCLOSING task — `group.cancelAll()` cancels children,
                // not the parent — so it is true only for genuine outside pressure.
                termination = Task.isCancelled ? .cancelled : .deadlineExpired
                group.cancelAll()
                break
            }

            if let value = outcome.value { results[item] = value }
            completed += 1
            onProgress?(completed, total)

            if completed == total {
                termination = .exhausted
                // Cancel the timer so the group can retire.
                group.cancelAll()
                break
            }

            if next < total, !Task.isCancelled {
                let item = items[next]
                group.addTask { (item, await work(item)) }
                next += 1
            } else if Task.isCancelled {
                termination = .cancelled
                group.cancelAll()
                break
            }
        }
    }

    // A cancellation that lands while the last results are draining should not be
    // reported as a clean sweep.
    if Task.isCancelled, completed < total { termination = .cancelled }

    return BoundedPoolRun(
        results: results,
        termination: termination,
        completed: completed,
        total: total
    )
}

/// Unavailable overload that intercepts the ambiguous `Optional`-returning shape.
///
/// Without this, a closure returning `Out?` binds `Out` to the Optional itself and
/// the pool silently keeps every silent probe. The diagnostic is the fix: this
/// overload exists to be an error message and is never called.
@available(*, unavailable, message: """
    boundedPool's work closure must return ProbeOutcome<Out> — .observed(x) or .silent. \
    Returning an Optional binds Out to the Optional itself, so silent probes are \
    stored instead of dropped and the result count becomes probes sent, not answered.
    """)
public func boundedPool<Item: Sendable & Hashable, Out: Sendable>(
    over items: [Item],
    concurrency: Int,
    deadline: Deadline,
    onProgress: (@Sendable (Int, Int) -> Void)? = nil,
    work: @Sendable @escaping (Item) async -> Out?
) async -> BoundedPoolRun<Item, Out> {
    fatalError("unavailable")
}
