// ProbeStream.swift — backpressure as a decision, not an accident.
//
// `AsyncStream.makeStream()` defaults to an unbounded buffer, which will happily
// accumulate 65,000 probe events while a SwiftUI list renders thirty of them. That is
// not a slow UI; it is a memory leak with a progress bar on it.
//
// Every stream in this system therefore declares its policy, and `StreamBuffering`
// has no `.unbounded` case at all. A policy that can silently consume all available
// memory is not one this code should be able to express by forgetting to think about
// it, and if some future consumer genuinely needs unbounded buffering, adding the
// case is the moment to argue for it in review.
//
// `.bufferingNewest` is right for progress: a consumer that fell behind wants the
// current state, not a replay of history. That is only safe because results that must
// not be dropped travel in the terminal envelope — `DiscoveryResult`, `ScanReport` —
// and never in the progress stream. Keeping those two in separate channels is what
// lets the progress channel be lossy without lying.

/// The buffering policy a probe stream declares.
public enum StreamBuffering: Sendable, Hashable {
    /// Progress and liveness events: keep the newest 4,096 and drop the rest.
    ///
    /// The number is generous enough that a UI redrawing at 60 Hz never notices, and
    /// bounded enough that a consumer which stops consuming entirely costs a fixed
    /// amount of memory rather than an unbounded one.
    case progress
    /// Keep the newest `count` events.
    case newest(Int)
    /// Keep the oldest `count` events and drop later ones. For a consumer that needs
    /// the beginning of a sequence — the first hosts to answer, say — rather than the
    /// current state.
    case oldest(Int)

    /// The `AsyncStream` policy this maps to.
    var policy: AsyncStream<ProbeEvent>.Continuation.BufferingPolicy {
        switch self {
        case .progress: .bufferingNewest(4096)
        case .newest(let count): .bufferingNewest(max(1, count))
        case .oldest(let count): .bufferingOldest(max(1, count))
        }
    }
}

/// Constructors for the probe event stream.
public enum ProbeStream {
    /// Makes a stream and its continuation with an explicit buffering policy.
    ///
    /// - Parameters:
    ///   - buffering: the policy. There is no unbounded option; see the file header.
    ///   - onTermination: run when the stream ends — normally, or because the consumer
    ///     cancelled or was deallocated. This is where a socket gets closed, a
    ///     `DNSServiceRef` gets deallocated, and an `Unmanaged` context box gets
    ///     released. It fires in both cases, which is exactly the lifetime those
    ///     resources need and the reason the C bridges in the platform targets are
    ///     built on top of this rather than on a bare continuation.
    public static func make(
        buffering: StreamBuffering = .progress,
        onTermination: (@Sendable (AsyncStream<ProbeEvent>.Continuation.Termination) -> Void)? = nil
    ) -> (stream: AsyncStream<ProbeEvent>, continuation: AsyncStream<ProbeEvent>.Continuation) {
        let (stream, continuation) = AsyncStream<ProbeEvent>.makeStream(
            bufferingPolicy: buffering.policy
        )
        if let onTermination {
            continuation.onTermination = { termination in onTermination(termination) }
        }
        return (stream, continuation)
    }

    /// Makes a stream and a `ProgressSink` that feeds it.
    ///
    /// The bridge between the two halves of the engine API: an implementation emits
    /// through the sink from deep inside a probe loop without threading a continuation
    /// through every function, and the consumer sees only an `AsyncSequence`. Finish
    /// the stream by calling `finish()` on the returned closure when the stage is
    /// done — a stream nobody finishes hangs its consumer forever.
    public static func sinking(
        buffering: StreamBuffering = .progress,
        onTermination: (@Sendable (AsyncStream<ProbeEvent>.Continuation.Termination) -> Void)? = nil
    ) -> (stream: AsyncStream<ProbeEvent>, sink: ProgressSink, finish: @Sendable () -> Void) {
        let (stream, continuation) = make(buffering: buffering, onTermination: onTermination)
        let sink = ProgressSink { event in continuation.yield(event) }
        return (stream, sink, { continuation.finish() })
    }
}
