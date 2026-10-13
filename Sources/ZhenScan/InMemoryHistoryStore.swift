// InMemoryHistoryStore.swift — the session-lifetime conformance.
//
// The `HistoryStore` protocol, `DerivedEvent` and `StoredDevice` used to be declared at
// the top of this file. They now live in `ZhenCore/Persistence/HistoryStore.swift`,
// because the CLI cannot reach anything in this package and the SwiftData ruling
// produced a second conformance that has to satisfy the same protocol as this one. The
// seam sits above both; this is one implementation of it.
//
// The rules for folding a run into history moved out too, into `HistoryLedger`. What is
// left here is genuinely all this type ever was: an actor, and a place to keep the
// ledger between calls. That is the point of the split — a store should contribute
// nothing to what recording a run MEANS, and the shortest way to guarantee it is to
// leave it nothing to contribute.
//
// The conformance stayed in this package deliberately. It is an actor over in-memory
// state with no portability claim to make, and moving it would have put a session cache
// in the module whose whole job is to be the thing everyone else agrees on.
//
// What an in-memory store buys is not nothing. First-seen, last-seen and the event log
// are all *within-session* facts, and within a session they are correct: a device that
// appeared during the second scan really did appear, and the timeline says so. What is
// lost is everything across a relaunch, which is exactly the part a real store adds.

import Foundation
import ZhenCore

/// The session-lifetime store.
///
/// An actor, so the scan target can write it from a probe task while the app target
/// reads it from the main actor, with no lock and no `@unchecked Sendable` anywhere.
public actor InMemoryHistoryStore: HistoryStore {
    private var ledger = HistoryLedger()

    /// Creates an empty store.
    public init() {}

    public func latestRun() async -> ScanRun? { ledger.latestRun }

    public func events() async -> [DerivedEvent] { ledger.events() }

    public func devices() async -> [StoredDevice] { ledger.devices() }

    public func firstSeen(
        for facts: [HostFacts], in network: IPv4Network
    ) async -> [IPv4Address: Timestamp] {
        ledger.firstSeen(for: facts, in: network)
    }

    public func record(_ report: ScanReport) async -> [DerivedEvent] {
        ledger.record(report)
    }

    public func recordPorts(
        _ result: PortScanResult, targeted targets: [IPAddress], at: Timestamp
    ) async -> [DerivedEvent] {
        ledger.foldPorts(result, targeted: targets, at: at).events
    }

    /// Sets how long events are kept, from the next recorded run onward.
    ///
    /// One line, which is the shape a store's share of retention is supposed to be: the
    /// rule is `HistoryLedger`'s and this hands the policy to the one it holds. A store
    /// that decided anything here would be the second copy of a rule.
    ///
    /// It applies to a session store for the same reason it applies to a file. Without a
    /// home directory to write to, this is the app's history — the whole of it — and a
    /// person who asks for thirty days is not asking about the file system.
    public func setRetention(_ policy: RetentionPolicy) async {
        ledger.retention = policy
    }
}
