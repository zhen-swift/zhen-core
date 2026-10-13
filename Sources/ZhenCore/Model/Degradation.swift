// Degradation.swift — failures are values.
//
// A silent `catch {}` destroys the product's main feature. Explaining *why* a device
// is unidentified is the reason this tool exists, so every probe failure travels back
// to the surface as data rather than a log line. The app renders these on the live
// scan screen and keeps them visible after the run ends; the CLI puts them in the
// report. Nothing swallows one.

/// The stages of a run, in the order they execute.
///
/// A network-controller stage used to be a case here. The integration is dropped
/// from the project, so it is dropped from the schema — a stage that can never run
/// has no business in a wire format that consumers switch over exhaustively.
public enum Stage: String, Sendable, Hashable, CaseIterable, Codable {
    /// Interface enumeration, descriptor limits, permission checks. Most likely
    /// place for the Local Network denial to first show itself.
    case setup = "setup"
    /// Host discovery: the ICMP sweep and the neighbour cache.
    case discovery = "discovery"
    /// Naming: mDNS, SSDP, NetBIOS, reverse DNS.
    case naming = "naming"
    /// Port scanning and banner grabbing.
    case deepScan = "deep_scan"

    /// A stable human label, for a renderer that would otherwise have to build one
    /// from the raw value and get "deepScan" wrong.
    public var label: String {
        switch self {
        case .setup: "Setup"
        case .discovery: "Discovery"
        case .naming: "Naming"
        case .deepScan: "Deep scan"
        }
    }
}

/// Something that did not work, expressed so a person can read it.
public struct Degradation: Sendable, Hashable, Codable {
    /// Which stage was affected.
    public let stage: Stage
    /// User-facing. This string reaches the scan view verbatim, so write it for a
    /// person: what stopped working, and what it costs them.
    ///
    /// Where the cause is inferred rather than known — the Local Network permission
    /// cannot be queried, only guessed at from a silent sweep over a populated
    /// neighbour cache — the text must say so. Claiming certainty about something
    /// we deduced is the kind of small lie that erodes trust in everything else the
    /// tool reports.
    public let reason: String
    /// Whether a retry could plausibly succeed without the user changing something.
    /// A busy BPF node is recoverable; a denied permission is not.
    public let recoverable: Bool

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(stage: Stage, reason: String, recoverable: Bool) {
        self.stage = stage
        self.reason = reason
        self.recoverable = recoverable
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case stage
        case reason
        case recoverable
    }
}
