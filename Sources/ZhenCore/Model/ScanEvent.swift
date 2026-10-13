// ScanEvent.swift — what changed between two runs, derived purely.
//
// ── Closing the gap in the original specification ────────────────────────────────
//
// SPEC specified the diff as:
//
//     public func deriveEvents(previous: [HostFacts], current: [HostFacts],
//                              at: Date, run: ScanRunID) -> [ScanEvent]
//
// described as a pure free function, "testable with zero I/O and zero database" —
// and that is the right instinct, because this is the logic most likely to be subtly
// wrong. But as written it cannot be one. `ScanEvent` there is a SwiftData `@Model`
// entity, and a `PersistentModel` cannot be constructed outside a `ModelContext`; a
// "pure function" returning one needs a database to run. `Date` violates the model's
// own no-Date rule, and `ScanRunID` is a store type core must not know.
//
// The gap is closed by inverting the dependency rather than by weakening the
// function. `ScanEvent` is a core value type — Sendable, Hashable, Codable, no
// context, no reference semantics. `deriveEvents` returns those, and it really is
// pure. The store's `@Model` entity becomes a PROJECTION of this value type: the
// store maps events into rows, and nothing in the diff logic knows a store exists.
// That inversion is also what lets the CLI derive events on Linux with no SwiftData
// at all, which the original shape made impossible.
//
// Two further consequences worth stating, because they are deliberate:
//
//   * `ScanEvent` has no `id`. A pure function cannot mint a UUID without becoming
//     non-deterministic, and a non-deterministic function is not testable against
//     handcrafted before/after sets — which was the entire justification for
//     extracting it. Persistent identity is the store's to assign.
//   * `at` is a `Timestamp` passed in, not read from a clock. Same reason: a
//     function that reads the clock cannot be asserted against.
//
// `hostsMerged` is defined in the enum but never produced here. A merge is decided
// by the identity resolver against the accumulated identifier table, which is
// store-resident by nature; the diff between two runs cannot see it. It is in the
// enum because the timeline renders it and the store emits it.

// Foundation is used here for exactly two things: UUID, and the single wall-clock
// reading behind `Timestamp.now`. Both are available in swift-corelibs-foundation, so
// this import does not compromise the Linux requirement — and it is a plain import
// rather than a conditional, which keeps `grep -r "#if" Sources/` returning nothing.
import Foundation

/// What kind of change an event records.
public enum ScanEventKind: String, Sendable, Hashable, CaseIterable, Codable {
    /// A device present now that was not present in the previous run.
    case hostAppeared = "host_appeared"
    /// A device present in the previous run and absent now.
    case hostDisappeared = "host_disappeared"
    /// The same device, at a different address.
    case ipMoved = "ip_moved"
    /// A port that was not open is open.
    case portOpened = "port_opened"
    /// A port that was open no longer is.
    case portClosed = "port_closed"
    /// The winning name changed.
    case nameChanged = "name_changed"
    /// The OUI-derived vendor changed — usually the signature of a MAC rotation
    /// being resolved to the same device, and worth surfacing for exactly that
    /// reason.
    case vendorChanged = "vendor_changed"
    /// Two records were found to be the same device and joined. Emitted by the
    /// identity resolver in the store, never by `deriveEvents`.
    case hostsMerged = "hosts_merged"
}

/// How much attention an event deserves.
public enum EventSeverity: String, Sendable, Hashable, CaseIterable, Codable {
    /// Routine. A device came back after a reboot.
    case info = "info"
    /// Worth a look. A new device appeared; a port opened.
    case notable = "notable"
    /// Worth acting on. A device's identity changed under it.
    case warning = "warning"
}

/// One change, as a value.
public struct ScanEvent: Sendable, Hashable, Codable {
    /// When it was observed. Wall clock, supplied by the caller — see the file
    /// header for why this is not read from a clock here.
    public var at: Timestamp
    /// The run this was derived from.
    public var run: UUID
    /// What changed.
    public var kind: ScanEventKind
    /// How much it matters.
    public var severity: EventSeverity
    /// The address involved — for `ipMoved`, the new one.
    public var ip: IPAddress
    /// The join key the two observations were matched under, so a reader can see
    /// *why* these were considered the same device. This is the field that makes a
    /// wrong match explicable instead of mysterious.
    public var identity: HostIdentifier?
    /// One line, written for a person.
    public var summary: String
    /// Structured specifics — `{"from": "...", "to": "..."}` and similar. A
    /// dictionary rather than a per-kind payload type because consumers render it
    /// generically and a closed payload union would need a schema bump for every
    /// new detail.
    public var details: [String: String]

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        at: Timestamp,
        run: UUID,
        kind: ScanEventKind,
        severity: EventSeverity,
        ip: IPAddress,
        identity: HostIdentifier? = nil,
        summary: String,
        details: [String: String] = [:]
    ) {
        self.at = at
        self.run = run
        self.kind = kind
        self.severity = severity
        self.ip = ip
        self.identity = identity
        self.summary = summary
        self.details = details
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case at
        case run
        case kind
        case severity
        case ip
        case identity
        case summary
        case details
    }
}

/// Derives the events between two runs.
///
/// Pure, deterministic, and free of I/O: the same inputs always produce the same
/// events in the same order. That is what makes it testable against handcrafted
/// before/after sets, which is the point of it being a free function.
///
/// Devices are matched across runs by their strongest join key that is not an
/// address — a universal MAC, then an mDNS instance, then a DHCP hostname, then a
/// randomized MAC. Address keys are excluded from matching deliberately: two devices
/// swapping DHCP leases between runs would otherwise each appear to have changed
/// into the other. When a device offers no non-address key at all, it falls back to
/// matching on the address itself, which is the best available answer and is recorded
/// in the event's `identity` so a reader can see how weak the match was.
///
/// - Parameters:
///   - previous: devices from the prior run.
///   - current: devices from this run.
///   - at: the wall-clock stamp to put on every derived event.
///   - run: the current run's identifier.
///   - network: the scanned network, used only to build fallback address keys.
/// - Returns: events in a deterministic order — by address, then by kind.
public func deriveEvents(
    previous: [Device],
    current: [Device],
    at: Timestamp,
    run: UUID,
    network: IPv4Network
) -> [ScanEvent] {
    func joinKey(_ device: Device) -> HostIdentifier {
        let keys = HostIdentifier.candidates(for: device, in: network)
        return keys.first { $0.kind != .ipLease } ?? HostIdentifier(kind: .ipLease, value: "\(network)@\(device.primaryAddress)")
    }

    // Grouped, not last-write-wins. `before[joinKey(d)] = d` looks right and quietly
    // drops devices: a dual-homed host appears twice under one key — same MAC, two
    // addresses — and the second assignment discards the first, so one of its two
    // interfaces vanishes from the diff entirely. Worse, which one survives depends on
    // array order, so the pair that got compared could be ip1-versus-ip2 and the diff
    // would report a spurious ipMoved for a host that had not moved.
    var before: [HostIdentifier: [Device]] = [:]
    for device in previous { before[joinKey(device), default: []].append(device) }
    var after: [HostIdentifier: [Device]] = [:]
    for device in current { after[joinKey(device), default: []].append(device) }

    var events: [ScanEvent] = []

    /// Appends one event. A local function rather than six near-identical
    /// initializer calls, so the shared fields cannot drift between kinds.
    func emit(
        _ kind: ScanEventKind,
        _ severity: EventSeverity,
        _ key: HostIdentifier,
        _ ip: IPAddress,
        _ summary: String,
        _ details: [String: String] = [:]
    ) {
        events.append(
            ScanEvent(
                at: at, run: run, kind: kind, severity: severity,
                ip: ip, identity: key, summary: summary, details: details
            )
        )
    }

    /// Diffs the fields of one matched pair. Address changes are handled by the
    /// caller, which knows whether the two were matched on address or paired up.
    func diffFields(_ key: HostIdentifier, _ then: Device, _ now: Device) {
        let wasNamed = then.displayName
        let isNamed = now.displayName
        if wasNamed != isNamed {
            // A name arriving where there was none is routine — mDNS is slower than
            // ICMP and the second run often names what the first only found. A name
            // *changing* is worth a warning: either the device was renamed or the
            // identity join is wrong, and the second is the expensive possibility.
            let severity: EventSeverity = (wasNamed == nil || isNamed == nil) ? .info : .warning
            emit(.nameChanged, severity, key, now.primaryAddress,
                 "\(then.primaryAddress) is now known as \(isNamed ?? "an unnamed device")",
                 ["from": wasNamed ?? "", "to": isNamed ?? ""])
        }

        if then.vendor != now.vendor {
            emit(.vendorChanged, .warning, key, now.primaryAddress,
                 "Vendor for \(now.displayName ?? now.primaryAddress.description) changed",
                 ["from": then.vendor ?? "", "to": now.vendor ?? ""])
        }

        // Only `.open` transitions are events. A port moving between `.closed` and
        // `.filtered` means the host stopped answering, not that anything about the
        // service changed, and reporting it would bury the real signal.
        let openBefore = Set(then.openPorts.map(\.port))
        let openNow = Set(now.openPorts.map(\.port))
        for port in openNow.subtracting(openBefore).sorted() {
            emit(.portOpened, .notable, key, now.primaryAddress,
                 "Port \(port) opened on \(now.displayName ?? now.primaryAddress.description)",
                 ["port": String(port)])
        }
        for port in openBefore.subtracting(openNow).sorted() {
            emit(.portClosed, .info, key, now.primaryAddress,
                 "Port \(port) closed on \(now.displayName ?? now.primaryAddress.description)",
                 ["port": String(port)])
        }
    }

    for key in Set(before.keys).union(after.keys).sorted() {
        // Within one join key, match on address first. Everything left over on each
        // side is then paired in address order: one unmatched on each side is a move,
        // a surplus before is a disappearance, a surplus after is an appearance. That
        // reduces to the obvious answer for a single-homed host and stays correct for
        // a dual-homed one, where the interfaces that did not change must not be
        // dragged into the diff by the one that did.
        let thens = before[key] ?? []
        let nows = after[key] ?? []
        let thenByIP = Dictionary(thens.map { ($0.primaryAddress, $0) }, uniquingKeysWith: { first, _ in first })
        let nowByIP = Dictionary(nows.map { ($0.primaryAddress, $0) }, uniquingKeysWith: { first, _ in first })

        for ip in Set(thenByIP.keys).intersection(nowByIP.keys).sorted() {
            diffFields(key, thenByIP[ip]!, nowByIP[ip]!)
        }

        let strandedThen = thens.filter { nowByIP[$0.primaryAddress] == nil }.sorted { $0.primaryAddress < $1.primaryAddress }
        let strandedNow = nows.filter { thenByIP[$0.primaryAddress] == nil }.sorted { $0.primaryAddress < $1.primaryAddress }

        for index in 0..<Swift.min(strandedThen.count, strandedNow.count) {
            let then = strandedThen[index]
            let now = strandedNow[index]
            emit(.ipMoved, .notable, key, now.primaryAddress,
                 "\(now.displayName ?? now.primaryAddress.description) moved from \(then.primaryAddress) to \(now.primaryAddress)",
                 ["from": then.primaryAddress.description, "to": now.primaryAddress.description])
            diffFields(key, then, now)
        }
        for then in strandedThen.dropFirst(strandedNow.count) {
            emit(.hostDisappeared, .info, key, then.primaryAddress,
                 "\(then.displayName ?? then.primaryAddress.description) is no longer answering")
        }
        for now in strandedNow.dropFirst(strandedThen.count) {
            emit(.hostAppeared, .notable, key, now.primaryAddress,
                 "\(now.displayName ?? now.primaryAddress.description) appeared")
        }
    }

    // Deterministic order. Dictionary iteration above is unordered, and a report
    // whose event list reshuffles between identical runs cannot be diffed.
    return events.sorted {
        ($0.ip, $0.kind.rawValue, $0.summary) < ($1.ip, $1.kind.rawValue, $1.summary)
    }
}
