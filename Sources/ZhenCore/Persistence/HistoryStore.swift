// HistoryStore.swift — the persistence seam, and nothing persistent behind it.
//
// Document 03's note on SwiftData and portability raised a decision nobody had ruled on:
// SwiftData is Darwin-only and the CLI is meant to reach Linux, so "SwiftData only, not
// even as a cache" could not hold as written.
//
// **Ruled on 2026-09-09: portability wins, and this protocol is how.** There were to be
// two conformances and no more — SwiftData on Darwin, an append-only log with an index
// everywhere else — both writing the same model types, so an artifact from either is
// readable by both. Neither is a cache of the other; that is the part of the original
// rule worth keeping, and the seam is what keeps it.
//
// **Amended 2026-09-11: the SwiftData conformance is withdrawn.** The app was wired to
// the same log file `zhen scan` writes, because one shared file is the only reason
// the app and the command line agree about the network — which left the SwiftData store
// referenced by nothing but its own tests. A conformance that ships nowhere is a second
// description of an idea rather than a second implementation of it, and it drifts
// quietly because nothing runs it. Document 03 carries the reasoning and what would
// bring it back.
//
// The seam is not weakened by having one fewer conformance, and this file did not
// change for either ruling — which is the argument for a seam, made twice. There are
// still two: the log, and the session-lifetime store the app falls back to when there
// is nowhere to write a file. Both ship, and the store suite runs against both.
//
// ── Why this is in core rather than beside its first conformance ─────────────────
//
// It was in `ZhenScan`, inside the app package, where the CLI cannot reach it.
// That is fine while there is one conformance and wrong the moment there are two: a
// SwiftData store in the app and a portable log in the CLI have to satisfy the same
// protocol or they are not two implementations of one idea, they are two unrelated
// types that happen to share a name. The seam has to sit above both of them, and core
// is the only module both can see.
//
// Moving it costs nothing today and is a migration once a second conformance exists,
// which is the whole argument for doing it before the ruling rather than after.
//
// ── Why the protocol is this narrow ──────────────────────────────────────────────
//
// Structs in, structs out, and deliberately no way to hand back a live model object.
// That same note requires that a persistent model never cross an isolation boundary,
// because faulting a relationship is executor-bound: a `PersistentModel` fetched on one
// actor and read on another can fault on the wrong executor, and the failure is a data
// race in a framework nobody will think to suspect. The cheapest way to guarantee it
// cannot happen is for this protocol to be incapable of expressing it — every method
// returns a value type that has already been fully realised by the time it crosses.
//
// That is also why the store's own conformance is free to be an actor. `async` on every
// requirement is not ceremony; it is what lets the scan target write history from a
// probe task while the app target reads it from the main actor, with no lock and no
// `@unchecked Sendable` anywhere.
//
// ── Portability ──────────────────────────────────────────────────────────────────
//
// Nothing in this file may reference a Darwin type. It is checked by building
// ZhenCore alone on Linux (`Scripts/verify-linux.sh`), because inspection is not
// proof — Swift does not type-check inactive `#if` branches.

import Foundation

/// Something that changed between two runs.
public struct DerivedEvent: Identifiable, Sendable, Hashable {
    /// What kind of change.
    public enum Kind: String, Sendable, Hashable {
        /// A device answered that had not before.
        case appeared
        /// A device stopped answering.
        case disappeared
        /// A device moved address.
        case ipChanged
        /// A device's winning name changed.
        case renamed
        /// Two records were found to be the same device and joined into one.
        ///
        /// `ScanEvent.Kind` has declared `hostsMerged` since the model was written, with
        /// a comment saying it is "emitted by the identity resolver in the store, never
        /// by `deriveEvents`" — and the store could not emit it, because this enum had
        /// no case for it. The design system has had a label, a symbol and a filter
        /// category for it the whole time too. This is the case that was missing.
        case merged
    }

    /// Stable identity.
    public let id: UUID
    /// When it happened.
    public let at: Timestamp
    /// What changed.
    public let kind: Kind
    /// The device it happened to, as a person would name it.
    public let subject: String
    /// The rest of the sentence.
    public let detail: String
    /// The run that produced it.
    public let runID: UUID

    /// Creates an event. Each field is documented on the property it sets.
    public init(
        id: UUID = UUID(), at: Timestamp, kind: Kind,
        subject: String, detail: String, runID: UUID
    ) {
        self.id = id
        self.at = at
        self.kind = kind
        self.subject = subject
        self.detail = detail
        self.runID = runID
    }
}

/// A device the session has seen, whether or not the latest run found it.
public struct StoredDevice: Sendable, Hashable {
    /// The record as of the most recent run that saw it.
    public var device: Device
    /// Whether the most recent run saw it.
    ///
    /// **This is where "offline" comes from.** `Device` has no such field and should not
    /// — presence is a fact about a RUN, not about a device, and a device carries the
    /// last thing observed about it rather than a liveness flag that would be stale the
    /// moment it was written.
    public var isPresent: Bool

    /// Creates a value from its fields.
    public init(device: Device, isPresent: Bool) {
        self.device = device
        self.isPresent = isPresent
    }
}

/// Where scan history lives.
///
/// Deliberately narrow, and deliberately structs in and structs out — see the note at
/// the top of this file for why that shape is a correctness constraint rather than a
/// style preference.
public protocol HistoryStore: Sendable {
    /// Folds a finished run into history and returns what changed.
    func record(_ report: ScanReport) async -> [DerivedEvent]

    /// Sets how long the event log is kept, from now on.
    ///
    /// A requirement rather than a defaulted extension method, and the difference is the
    /// whole point: a default implementation would let a conformance inherit a retention
    /// setting it silently ignores, which is the exact defect the picker had for a
    /// release. The RULE is not here — `RetentionPolicy` and the prune belong to
    /// `HistoryLedger`, above every conformance — so what a store has to write is the
    /// one line that hands the policy on.
    ///
    /// Takes effect from the next run recorded. Pruning happens when history changes,
    /// because that is the only moment a store has anything to write, and a store that
    /// rewrote its file on being asked a question would be a surprising thing to have
    /// behind a settings picker.
    func setRetention(_ policy: RetentionPolicy) async

    /// First-seen stamps for hosts about to be recorded, by address.
    ///
    /// Asked BEFORE the devices are built, because `Device(observing:…)` needs the value
    /// at construction and defaults it to `lastSeen` otherwise — which is right on a
    /// first-ever run and silently wrong on every one after it.
    func firstSeen(for facts: [HostFacts], in network: IPv4Network) async -> [IPv4Address: Timestamp]

    /// Everything the session has seen, present and absent.
    func devices() async -> [StoredDevice]

    /// The event log, newest first.
    func events() async -> [DerivedEvent]

    /// The most recent finished run, or nil before the first one.
    func latestRun() async -> ScanRun?
}
