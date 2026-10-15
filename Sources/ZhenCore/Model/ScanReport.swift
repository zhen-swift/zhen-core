// ScanReport.swift — the artifact.
//
// This is the product. The CLI serializes it, the app renders it, and a third
// consumer nobody has written yet reads it from a file. It is designed as a wire
// format that happens to be Swift, not as an internal convenience: explicit coding
// keys everywhere, no Date, no Duration, and optionality that means *not observed*.

// Foundation is used here for exactly two things: UUID, and the single wall-clock
// reading behind `Timestamp.now`. Both are available in swift-corelibs-foundation, so
// this import does not compromise the Linux requirement — and it is a plain import
// rather than a conditional, which keeps `grep -r "#if" Sources/` returning nothing.
import Foundation

/// How a run ended.
///
/// `deadlineExpired` is a SUCCESS value. It means the budget was spent and the
/// results are partial, which on a real network is the common case and not a
/// failure. Nothing in this API lets a consumer mistake it for an error: there is no
/// `throws` on the path that produces it, the CLI exits 0 on it, and whether a run
/// was complete is a field in the artifact rather than a status code.
public enum Outcome: String, Sendable, Hashable, CaseIterable, Codable {
    /// Every stage finished within its budget.
    case complete = "complete"
    /// The budget ran out. The results below are what was gathered; they are real,
    /// just not exhaustive.
    case deadlineExpired = "deadline_expired"
    /// The user interrupted. Also not an error, and also carries partial results —
    /// the first SIGINT commits what it has.
    case cancelled = "cancelled"

    /// Whether the results should be read as exhaustive.
    ///
    /// A surface that shows a completeness indicator reads this. A green dot over an
    /// incomplete scan is a lie of omission.
    public var isComplete: Bool { self == .complete }
}

/// Which engine produced a run, and what it was able to do.
public struct EngineDescriptor: Sendable, Hashable, Codable {
    /// A stable identifier for the implementation — "unprivileged-icmp", "bpf-arp".
    public var name: String
    /// Privileged, unprivileged, or a composition of both.
    public var kind: EngineKind
    /// What this engine can do, so a surface can say "OS fingerprint unavailable —
    /// requires the privileged engine" without knowing which engine is installed.
    public var capabilities: EngineCapabilities

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(name: String, kind: EngineKind, capabilities: EngineCapabilities) {
        self.name = name
        self.kind = kind
        self.capabilities = capabilities
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case name
        case kind
        case capabilities
    }
}

/// The metadata of one run.
public struct ScanRun: Sendable, Hashable, Codable {
    /// Identifies this run. Events derived from it carry the same value.
    public var id: UUID
    /// When the run started. Wall clock, for display — the elapsed times in `timing`
    /// are the monotonic measurements and the two are never mixed.
    public var startedAt: Timestamp
    /// When it ended. Absent while a run is in progress.
    public var finishedAt: Timestamp?
    /// What was scanned.
    public var target: IPv4Network
    /// Which interface it went out of.
    public var interface: String
    /// Which engine ran it.
    public var engine: EngineDescriptor
    /// How it ended. See `Outcome` — two of the three values are partial results and
    /// none of the three is an error.
    public var outcome: Outcome
    /// Which stages the run was asked to perform.
    ///
    /// Defaults to `.full`, which is what every document written before this field
    /// existed meant. Decoding treats it as optional for the same reason.
    public var mode: ScanMode
    /// What it cost, measured monotonically.
    public var timing: Timing
    /// What the discovery sweep's neighbour watch did — whether it was on, and what its
    /// reads of the table cost. Absent for a run whose engine has no watch, and in every
    /// document written before 0.8.0.
    public var neighborWatch: NeighborWatchReport?
    /// How the sweep decided how long to wait for each address, and which addresses
    /// history expected that the run did not find. Absent when no plan was built, and in
    /// every document written before 0.8.0.
    public var reach: ReachReport?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        id: UUID,
        startedAt: Timestamp,
        finishedAt: Timestamp? = nil,
        target: IPv4Network,
        interface: String,
        engine: EngineDescriptor,
        outcome: Outcome,
        mode: ScanMode = .full,
        timing: Timing,
        neighborWatch: NeighborWatchReport? = nil,
        reach: ReachReport? = nil
    ) {
        self.id = id
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.target = target
        self.interface = interface
        self.engine = engine
        self.outcome = outcome
        self.mode = mode
        self.timing = timing
        self.neighborWatch = neighborWatch
        self.reach = reach
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case id
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case target
        case interface
        case engine
        case outcome
        case mode
        case timing
        case neighborWatch = "neighbor_watch"
        case reach
    }

    /// Decodes, tolerating a document written before `mode` existed.
    ///
    /// Hand-written rather than synthesized for exactly one reason: the synthesized
    /// decoder requires every non-optional key to be present, so adding `mode` would
    /// have made every schema-1 document written by an earlier build fail to decode —
    /// turning an additive field into a breaking change by accident. A missing `mode`
    /// means `.full`, which is what those documents recorded.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try container.decode(UUID.self, forKey: .id),
            startedAt: try container.decode(Timestamp.self, forKey: .startedAt),
            finishedAt: try container.decodeIfPresent(Timestamp.self, forKey: .finishedAt),
            target: try container.decode(IPv4Network.self, forKey: .target),
            interface: try container.decode(String.self, forKey: .interface),
            engine: try container.decode(EngineDescriptor.self, forKey: .engine),
            outcome: try container.decode(Outcome.self, forKey: .outcome),
            mode: try container.decodeIfPresent(ScanMode.self, forKey: .mode) ?? .full,
            timing: try container.decode(Timing.self, forKey: .timing),
            neighborWatch: try container.decodeIfPresent(
                NeighborWatchReport.self, forKey: .neighborWatch
            ),
            reach: try container.decodeIfPresent(ReachReport.self, forKey: .reach)
        )
    }
}

/// Which stages a run was asked to perform.
///
/// Recorded in the artifact because two scans of the same network in different modes
/// are not comparable, and a reader holding one document should not have to work that
/// out from which stages happen to be missing. The absent stage says it structurally;
/// this says it in a field.
public enum ScanMode: String, Sendable, Hashable, Codable, CaseIterable {
    /// Discovery, naming, and the port stage if asked for. The default.
    case full
    /// Discovery only. The naming protocols are not started, so the naming stage is
    /// absent from `Timing.stages` rather than present and empty.
    case discoveryOnly = "discovery_only"
}

/// The complete output of one scan.
public struct ScanReport: Sendable, Hashable, Codable {
    /// Bumped on any breaking change to the shapes in `Model/`. Every consumer checks
    /// it before decoding and refuses a version it does not know.
    ///
    /// ── Why `ScanMode` did not bump it ──────────────────────────────────────────
    ///
    /// Discovery-only mode added `run.mode` and made the naming stage absent from
    /// `Timing.stages`. Neither is a breaking change, and the argument is worth
    /// keeping because the second half of it is not obvious.
    ///
    /// The new field is additive and optional on read: a reader of this version
    /// ignores a key it does not know, and this version reads a document without the
    /// key as `.full`, which is what such a document meant.
    ///
    /// The absent stage looks more dangerous — a consumer that iterates `stages`
    /// expecting to find a naming entry would now not find one. But such a consumer
    /// was already wrong. A stages array with no naming entry has been a valid
    /// document since before this flag existed: naming is skipped when discovery
    /// found nothing, when the outcome is not `.complete`, and when the deadline has
    /// already expired, and the port stage has only ever appeared under `--deep`.
    /// `stages` has always been a record of what ran, never a fixed-shape tuple, and
    /// this mode produces no shape a schema-1 consumer could not already receive.
    ///
    /// A bump would therefore have cost every existing consumer a refusal to decode
    /// in exchange for no new safety. If a future change makes a stage's *absence*
    /// mean something a schema-1 reader would misinterpret, that is the change that
    /// bumps it.
    /// Bumped to 2 on 2026-09-24, when `PortState` gained `open_filtered`.
    ///
    /// This is the change the paragraph above describes: a schema-1 consumer decoding
    /// a port whose state is `open_filtered` fails outright rather than misreading it,
    /// and failing is the correct outcome. The alternative — spelling UDP silence as
    /// `filtered` so old readers keep working — would have made every document quietly
    /// wrong in the direction of under-reporting.
    ///
    /// **The study's 1,580 runs were produced by a binary emitting schema 1**, which
    /// their harness records per run in `parse.schema`. That corpus is a frozen
    /// measurement and is not rewritten; a run made with this build emits schema 2, so
    /// an analysis spanning the boundary has to know the boundary is there. That is
    /// what the field is for. See `Study/REPRODUCIBILITY.md`.
    ///
    /// Bumped to 3 on 2026-09-26, when a device became a set of addresses.
    ///
    /// `Device.ip` is gone and `addresses` replaces it; `PortObservation` gained the
    /// `address` it was made on; `Device.vlan` is reserved. A schema-2 reader handed a
    /// device with no `ip` fails outright, which is correct: the alternative — keep
    /// writing `ip` beside `addresses` — keeps old readers working by showing them one
    /// address of a host that has three, and a reader that believes it has the whole
    /// device when it has a third of one is the under-reporting this project refuses.
    ///
    /// Unlike 1 → 2 this *removed* a field, so reading an older document is a
    /// migration rather than a tolerance. It lives in `Device.init(from:)`, keyed on the
    /// record's shape: the history store holds device records with no report around
    /// them, written by every build there has been, and never rewritten to upgrade them.
    ///
    /// Bumped to 4 on 2026-10-15, when `discovered_via` gained `neighbor_resolved`.
    ///
    /// By the rule above, and it is the 1 → 2 case again rather than a judgement call.
    /// `DiscoverySource` decodes strictly, so a schema-3 reader handed a device whose
    /// `discovered_via` holds the new value fails to decode the device — and with it the
    /// report — rather than misreading it. That failure is the correct outcome, and the
    /// alternative is the under-reporting this project refuses: writing a resolved-during-
    /// the-scan host as `neighbor_table` keeps old readers working by telling them the
    /// host was merely remembered, when this run saw it answer ARP.
    ///
    /// Everything else 0.8.0 adds — `run.neighbor_watch`, `run.reach`, `run.tool`, the
    /// per-host first-contact and found-after times, `attempts` and `concurrency` on a
    /// stage — is additive and optional on read, and would not have bumped it alone.
    /// `minimumReadableSchema` stays 1: nothing was removed or re-meant.
    public static let schemaVersion = 4

    /// The oldest schema this build still reads.
    ///
    /// 1. Schema 3 did remove a field, and it still stays 1: `Device` reads the removed
    /// `ip` and migrates it on the way in. Raising it is how the study's 485 archived
    /// reports and every line in a history store stop being readable, so it is a
    /// deliberate act with a cost attached.
    public static let minimumReadableSchema = 1

    /// The schema this document was written against.
    public var schema: Int
    /// Metadata about the run.
    public var run: ScanRun
    /// What was found. An empty array with `outcome == .complete` is a valid and
    /// meaningful report: it says the network is empty, which is different from
    /// saying the scan failed.
    public var devices: [Device]
    /// What did not work. Never empty because something went wrong silently — a
    /// degradation is how a failure reaches the surface at all.
    public var degradations: [Degradation]

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        schema: Int = ScanReport.schemaVersion,
        run: ScanRun,
        devices: [Device] = [],
        degradations: [Degradation] = []
    ) {
        self.schema = schema
        self.run = run
        // Canonical order, so two scans that found the same network encode to
        // byte-identical documents. Without this the claim that a regression is a
        // diff is false: devices arrive in whatever order they answered, so two
        // identical scans diff as wholly changed and a real change is invisible in
        // the noise.
        //
        // Sorted by address, which is also the order a person reads a network in. By the
        // primary address, so every v4 host keeps the position it had in schema 2 and a
        // v6-only host follows them.
        self.devices = devices.sorted { $0.primaryAddress < $1.primaryAddress }
        // Degradations are deliberately NOT sorted. Their order is the order things
        // went wrong in, which is information — "mDNS failed, then the deep scan
        // found nothing" reads differently from the reverse.
        self.degradations = degradations
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case schema
        case run
        case devices
        case degradations
    }
}

/// The one thing that can genuinely go wrong when reading a report.
///
/// Typed, because the caller's `catch` should be exhaustive and because there is
/// exactly one recoverable case in it: a document from a newer version of the tool.
public enum SchemaError: Error, Sendable, Hashable {
    /// The document declares a schema this build does not know how to read.
    case unsupportedSchema(found: Int, supported: Int)
}

extension ScanReport {
    /// Decodes, routing through the memberwise initializer so the canonical device
    /// order is established on this path too.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            schema: try container.decode(Int.self, forKey: .schema),
            run: try container.decode(ScanRun.self, forKey: .run),
            devices: try container.decodeIfPresent([Device].self, forKey: .devices) ?? [],
            degradations: try container.decodeIfPresent([Degradation].self, forKey: .degradations) ?? []
        )
    }

    /// Checks the declared schema against this build's.
    ///
    /// Called before trusting a decoded report. Decoding succeeds for a newer
    /// document whose added fields we ignore, which is precisely the dangerous case:
    /// the shapes overlap enough to decode and the meaning has moved. Checking the
    /// version explicitly is the only defence.
    public func validateSchema() throws(SchemaError) {
        // **Older is fine; newer is not, and the asymmetry is the whole point.**
        //
        // A newer document decodes here with its added fields silently ignored, which
        // is the dangerous case: the shapes overlap enough to decode and the meaning
        // has moved. That is what this refuses.
        //
        // An OLDER document is the safe direction. Schema 2 added one enum case,
        // `open_filtered`; it removed nothing and re-meant nothing, so every schema-1
        // document is exactly as readable as it was, and refusing it would strand every
        // artifact this tool has ever written.
        //
        // The study is the concrete case. Its 1,580 runs were produced by a binary
        // emitting schema 1 — `Study/data/runs.ndjson` records that per run, in
        // `parse.schema` — so a strict equality check would make a current build unable
        // to read anything that corpus refers to.
        guard schema >= Self.minimumReadableSchema, schema <= Self.schemaVersion else {
            throw SchemaError.unsupportedSchema(found: schema, supported: Self.schemaVersion)
        }
    }
}
