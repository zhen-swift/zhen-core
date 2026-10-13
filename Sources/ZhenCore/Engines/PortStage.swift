// PortStage.swift — which hosts a run probes for ports.
//
// The port stage was one switch: on, and every host that answered was probed; off, and
// none was. The app's Settings had a toggle written as "Deep-scan new devices", which is a
// different thing — a person asking to learn what a device is the first time it appears,
// not to re-probe a printer they have owned for years on every scan — and with one switch
// to offer, the app relabelled the toggle to say what the switch did instead.
//
// This is the third answer. It lives in core rather than in the runner because "new" is
// a question about history, and the answer has to be the same one the ledger gives.

/// Which of the hosts that answered a run probes for ports.
public enum PortStage: String, Sendable, Hashable, CaseIterable {
    /// No port stage.
    case off
    /// Every host that answered.
    case everyHost
    /// Only hosts history has no record of: devices seen for the first time.
    ///
    /// "New" is decided by `HistoryStore.firstSeen(for:in:)` — the ledger's own identity
    /// resolution, the one that follows a device across a MAC rotation — so a phone that
    /// rotated its address is not new, and is not re-probed for having done so. On a first
    /// run every host is new, which is what a first run is.
    case newHosts

    /// The hosts this stage probes, in address order.
    ///
    /// - Parameters:
    ///   - hosts: the hosts that answered.
    ///   - known: first-seen stamps from history, by address. A host with none is new.
    public func targets(
        among hosts: [IPv4Address], known: [IPv4Address: Timestamp]
    ) -> [IPv4Address] {
        switch self {
        case .off: []
        case .everyHost: hosts.sorted()
        case .newHosts: hosts.filter { known[$0] == nil }.sorted()
        }
    }
}
