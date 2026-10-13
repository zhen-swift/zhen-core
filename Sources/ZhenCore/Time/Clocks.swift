// Clocks.swift — two clocks that must never be mixed, kept apart by the type system.
//
// There are exactly two notions of time in this system and they answer different
// questions:
//
//   MonotonicInstant  measurement.  Backed by ContinuousClock. Immune to NTP steps,
//                     and — unlike SuspendingClock — it keeps running while the
//                     laptop sleeps, so a scan that started before a lid close has
//                     genuinely spent its budget rather than gaining free time.
//
//   Timestamp         display.      Milliseconds since the Unix epoch. It is what a
//                     person reads, what a database stores, and what crosses the
//                     wire.
//
// The discipline is that no duration is ever computed from Timestamps and no
// MonotonicInstant is ever serialized, and it is enforced structurally rather than
// by convention:
//
//   * MonotonicInstant is deliberately NOT Codable. Its zero point is the boot of
//     this machine, so an encoded value is meaningless to anyone who decodes it. The
//     compiler refuses to let one into a Model/ type.
//   * Timestamp has no `-` operator returning a Duration and no `advanced(by:)`.
//     Subtracting two wall-clock stamps across an NTP step yields a plausible,
//     wrong number, and the whole point of Timing living in the artifact is that a
//     regression is a diff rather than a feeling.
//
// Converting between them is possible only through `Timestamp.now`, at the edges,
// which is the one place a wall-clock reading is taken.

// Foundation is used here for exactly two things: UUID, and the single wall-clock
// reading behind `Timestamp.now`. Both are available in swift-corelibs-foundation, so
// this import does not compromise the Linux requirement — and it is a plain import
// rather than a conditional, which keeps `grep -r "#if" Sources/` returning nothing.
import Foundation

/// A point on the monotonic clock: the only thing this system measures with.
///
/// Wraps `ContinuousClock.Instant` rather than aliasing it so that the absence of
/// `Codable` is a property of *our* type and cannot be added by a retroactive
/// conformance somewhere downstream.
public struct MonotonicInstant: Sendable, Hashable, Comparable {
    /// The underlying continuous-clock reading.
    public let instant: ContinuousClock.Instant

    /// Wraps an existing continuous-clock reading.
    public init(_ instant: ContinuousClock.Instant) {
        self.instant = instant
    }

    /// Reads the monotonic clock now.
    public static var now: MonotonicInstant { MonotonicInstant(.now) }

    /// How long has elapsed since `earlier`. Never negative when `earlier` really is
    /// earlier; a caller that reverses the arguments gets a negative `Duration`
    /// rather than a silently clamped zero, because that is a programming error and
    /// hiding it would make an RTT of "0 ms" look like a fast host.
    public func duration(since earlier: MonotonicInstant) -> Duration {
        instant - earlier.instant
    }

    /// The instant `duration` from this one.
    public func advanced(by duration: Duration) -> MonotonicInstant {
        MonotonicInstant(instant.advanced(by: duration))
    }

    /// Orders values by the rule documented on this type.
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.instant < rhs.instant }
}

/// Milliseconds since the Unix epoch — the wire and display representation of a
/// moment in time.
///
/// `Date` is deliberately absent from every `Model/` type: it is a `Double` of
/// seconds since 2001 and encodes with platform-dependent precision, so the same
/// scan serialized on two machines can differ in the last digits. An `Int64` of
/// milliseconds is exact, ordered, and the same on every platform.
public struct Timestamp: Sendable, Hashable, Comparable, Codable, CustomStringConvertible {
    /// Milliseconds since 1970-01-01T00:00:00Z. Negative values are permitted and
    /// mean "before the epoch"; nothing in this system produces one, but decoding
    /// must not be lossy about it.
    public let millisecondsSinceEpoch: Int64

    /// Wraps a raw epoch-millisecond count.
    public init(millisecondsSinceEpoch: Int64) {
        self.millisecondsSinceEpoch = millisecondsSinceEpoch
    }

    /// Reads the wall clock. The one place in the system a wall-clock reading is
    /// taken; everything downstream carries the value rather than re-reading.
    public static var now: Timestamp {
        Timestamp(millisecondsSinceEpoch: Int64((Date().timeIntervalSince1970 * 1000).rounded()))
    }

    /// Seconds since the epoch, for interoperating with APIs that want a `Date`.
    /// Converting at the edge is the intended use; storing the result in a model
    /// type is not.
    public var timeIntervalSince1970: Double {
        Double(millisecondsSinceEpoch) / 1000
    }

    /// Orders values by the rule documented on this type.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.millisecondsSinceEpoch < rhs.millisecondsSinceEpoch
    }

    /// Encodes as a bare JSON integer, not an object. A timestamp is a scalar and a
    /// wrapper object would cost every consumer an extra level of indirection.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.millisecondsSinceEpoch = try container.decode(Int64.self)
    }

    /// Encodes to the wire form described above.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(millisecondsSinceEpoch)
    }

    /// Debug text. Deliberately not a formatted date: rendering a stamp for a person
    /// is a locale- and timezone-aware job that belongs in a surface, not here.
    public var description: String { "\(millisecondsSinceEpoch)ms" }
}

/// Measures one span of monotonic time and reports it in the units the model uses.
///
/// Exists so that "start a timer, stop it, put the number in `StageTiming`" is one
/// obvious call rather than three places where someone could reach for `Date()`.
public struct Stopwatch: Sendable {
    private let started: MonotonicInstant

    /// Starts measuring immediately.
    public init() { self.started = .now }

    /// Elapsed time as a `Duration`, for arithmetic against a `Deadline`.
    public var elapsed: Duration { MonotonicInstant.now.duration(since: started) }

    /// Elapsed time in milliseconds, for a `Model/` type.
    public var elapsedMillis: Double { elapsed.milliseconds }
}

extension Duration {
    /// Milliseconds as a `Double`, exactly — `components` is (seconds, attoseconds)
    /// and both halves are carried, so a sub-microsecond LAN RTT survives.
    ///
    /// A fast LAN answers in hundreds of microseconds. Rounding to whole
    /// milliseconds here would collapse the entire range this scanner competes on
    /// into "0" or "1", which is the measurement mistake this project exists to
    /// avoid making.
    public var milliseconds: Double {
        let (seconds, attoseconds) = components
        return Double(seconds) * 1000 + Double(attoseconds) / 1_000_000_000_000_000
    }

    /// Builds a `Duration` from a fractional millisecond count.
    ///
    /// Deliberately not spelled `.milliseconds(_:)`: the standard library already
    /// has that name for `BinaryInteger`, and an overload taking `Double` makes
    /// every integer literal call site ambiguous.
    public static func fromMilliseconds(_ value: Double) -> Duration {
        .nanoseconds(Int64((value * 1_000_000).rounded()))
    }
}
