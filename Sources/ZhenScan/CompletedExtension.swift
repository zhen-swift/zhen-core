// CompletedExtension.swift — what a look-longer sweep produced.
//
// Guarded like every file in this target; see `ScanRunner.swift`.
#if canImport(Darwin)
import Foundation
import ZhenCore

/// What `ScanRunner.lookLonger` found, and what it changed in history.
public struct CompletedExtension: Sendable {
    /// The run that was extended, or nil when there was none to extend.
    public var runID: UUID?
    /// The devices the sweep found among the addresses it was given, as recorded.
    public var found: [Device]
    /// The addresses it was given that still showed no evidence.
    public var missing: [IPv4Address]
    /// What history derived: an `appeared` for each found device the run had not seen.
    public var events: [DerivedEvent]
    /// The sweep's own result: timing, degradations, outcome.
    public var discovery: DiscoveryResult

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        runID: UUID?, found: [Device], missing: [IPv4Address],
        events: [DerivedEvent], discovery: DiscoveryResult
    ) {
        self.runID = runID
        self.found = found
        self.missing = missing
        self.events = events
        self.discovery = discovery
    }
}

#endif
