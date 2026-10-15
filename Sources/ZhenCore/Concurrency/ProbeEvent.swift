// ProbeEvent.swift — what an engine reports while it is still running.
//
// Renamed from `ProgressEvent` to match the name both consumer briefs are written
// against; it is the same idea. It is Codable because the CLI's `--ndjson` mode emits
// one of these per line as it happens, and because "all three output modes carry the
// same schema" is only true if the streaming mode's events are part of the schema
// rather than an ad-hoc rendering.
//
// The enum encodes as a tagged object — `{"event": "host_found", "host": {...}}` —
// rather than as Swift's default single-key nesting, because a consumer in another
// language switching on a discriminator field is ordinary and switching on "whichever
// key happens to be present" is not.

/// Something that happened during a scan.
public enum ProbeEvent: Sendable, Hashable, Codable {
    /// A stage began.
    case stageStarted(Stage)
    /// A stage advanced. `completed` and `total` are probe counts, and `total` can
    /// change if an engine discovers more work.
    case stageProgress(Stage, completed: Int, total: Int)
    /// A stage finished, with what it cost.
    case stageFinished(StageTiming)
    /// A host answered for the first time in this run.
    case hostFound(HostFacts)
    /// More was learned about a host already reported — a name arriving after the
    /// ICMP reply that found it, which is the common case since mDNS is slower.
    case hostUpdated(HostFacts)
    /// Something did not work. Degradations arrive here rather than as thrown errors
    /// so a stream never fails.
    case degraded(Degradation)
    /// Only addresses history expects are still being waited for: every other address
    /// has answered or had its wait. "Still listening for 2 you usually have." Emitted
    /// when the sweep enters that state and again each time the list shrinks; never
    /// emitted when nothing is expected, as on a first scan.
    case settling(expectedMissing: [IPv4Address])

    private enum CodingKeys: String, CodingKey {
        case event
        case stage
        case completed
        case total
        case timing
        case host
        case degradation
        case expectedMissing = "expected_missing"
    }

    private enum Tag: String, Codable {
        case stageStarted = "stage_started"
        case stageProgress = "stage_progress"
        case stageFinished = "stage_finished"
        case hostFound = "host_found"
        case hostUpdated = "host_updated"
        case degraded
        case settling
    }

    /// Encodes to the wire form described above.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .stageStarted(let stage):
            try container.encode(Tag.stageStarted, forKey: .event)
            try container.encode(stage, forKey: .stage)
        case .stageProgress(let stage, let completed, let total):
            try container.encode(Tag.stageProgress, forKey: .event)
            try container.encode(stage, forKey: .stage)
            try container.encode(completed, forKey: .completed)
            try container.encode(total, forKey: .total)
        case .stageFinished(let timing):
            try container.encode(Tag.stageFinished, forKey: .event)
            try container.encode(timing, forKey: .timing)
        case .hostFound(let host):
            try container.encode(Tag.hostFound, forKey: .event)
            try container.encode(host, forKey: .host)
        case .hostUpdated(let host):
            try container.encode(Tag.hostUpdated, forKey: .event)
            try container.encode(host, forKey: .host)
        case .degraded(let degradation):
            try container.encode(Tag.degraded, forKey: .event)
            try container.encode(degradation, forKey: .degradation)
        case .settling(let missing):
            try container.encode(Tag.settling, forKey: .event)
            try container.encode(missing, forKey: .expectedMissing)
        }
    }

    /// Decodes from the wire form described above.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Tag.self, forKey: .event) {
        case .stageStarted:
            self = .stageStarted(try container.decode(Stage.self, forKey: .stage))
        case .stageProgress:
            self = .stageProgress(
                try container.decode(Stage.self, forKey: .stage),
                completed: try container.decode(Int.self, forKey: .completed),
                total: try container.decode(Int.self, forKey: .total)
            )
        case .stageFinished:
            self = .stageFinished(try container.decode(StageTiming.self, forKey: .timing))
        case .hostFound:
            self = .hostFound(try container.decode(HostFacts.self, forKey: .host))
        case .hostUpdated:
            self = .hostUpdated(try container.decode(HostFacts.self, forKey: .host))
        case .degraded:
            self = .degraded(try container.decode(Degradation.self, forKey: .degradation))
        case .settling:
            self = .settling(expectedMissing: try container.decode([IPv4Address].self, forKey: .expectedMissing))
        }
    }
}

/// A Sendable closure box rather than a protocol existential, so it can be handed
/// across isolation boundaries without an actor and without an allocation per hop.
///
/// Engines emit through one of these from inside a probe loop;
/// `ProbeStream.sinking(buffering:)` is what connects it to an `AsyncStream` that a
/// main-actor view model consumes. Emission must be safe to call from arbitrary
/// tasks, because it will be.
public struct ProgressSink: Sendable {
    /// Emits one event.
    public let emit: @Sendable (ProbeEvent) -> Void

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(emit: @escaping @Sendable (ProbeEvent) -> Void) {
        self.emit = emit
    }

    /// A sink that discards everything, for a terminal-form scan with no observer.
    public static let ignore = ProgressSink { _ in }

    /// Emits one event, callable as `sink(event)`.
    public func callAsFunction(_ event: ProbeEvent) { emit(event) }
}
