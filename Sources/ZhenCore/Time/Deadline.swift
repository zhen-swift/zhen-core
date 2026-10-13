// Deadline.swift — the budget every stage subdivides.
//
// ContinuousClock is deliberate, via MonotonicInstant. Not SuspendingClock: a laptop
// sleeping mid-scan must expire the budget, not extend it. Not Date: an NTP step
// during a long watch run would move the deadline. Engines *receive* a deadline and
// narrow it with `clamped(to:)`; no engine reads a global timeout constant, so the
// budget tree is explicit and testable rather than scattered across the codebase.
//
// A Deadline is not Codable and must never become so. It is a point on this
// machine's monotonic clock and means nothing to anyone who decodes it.

/// A point in time after which a stage must stop and return what it has.
public struct Deadline: Sendable, Hashable {
    /// When the budget runs out, on the monotonic clock.
    public let instant: MonotonicInstant

    /// Wraps an existing monotonic instant.
    public init(instant: MonotonicInstant) {
        self.instant = instant
    }

    /// A budget of `duration`, starting now unless another origin is given.
    ///
    /// The `from` parameter exists so tests can construct deadlines relative to a
    /// captured instant rather than racing the clock.
    public init(after duration: Duration, from now: MonotonicInstant = .now) {
        self.instant = now.advanced(by: duration)
    }

    /// A deadline that has already passed. Useful for asserting that a stage returns
    /// partial results immediately rather than doing any work.
    public static var expired: Deadline { Deadline(after: .zero, from: .now) }

    /// Time left, never negative, so callers can pass it straight to a sleep or a
    /// socket timeout without a `max(0, …)` at every site.
    public var remaining: Duration {
        max(.zero, instant.duration(since: .now))
    }

    /// Whether the budget is spent. Note that this is a *normal* condition: a stage
    /// that finds it expired returns what it has, and the run's outcome records that
    /// the result is partial.
    public var isExpired: Bool { remaining == .zero }

    /// A child budget may shorten a parent's, never extend it.
    ///
    /// This is the only composition rule, and having exactly one means a nested
    /// stage cannot accidentally outlive the run that spawned it.
    public func clamped(to parent: Deadline) -> Deadline {
        Deadline(instant: min(instant, parent.instant))
    }

    /// A sub-budget expressed as a fraction of what is left.
    ///
    /// Used where a stage splits internally — SSDP, for example, spends roughly 60%
    /// listening for M-SEARCH responses and 40% fetching the description documents
    /// they point at. The portion is clamped to 0…1 so a caller cannot ask for 150%
    /// of the remaining time.
    public func fraction(_ portion: Double) -> Deadline {
        let slice = remaining * max(0, min(1, portion))
        return Deadline(after: slice).clamped(to: self)
    }
}
