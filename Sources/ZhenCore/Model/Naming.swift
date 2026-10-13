// Naming.swift — the name cascade as a total order.
//
// Resolving a device's name is `candidates.min()`, not a procedure. Encoding the
// cascade as Comparable means there is exactly one place the priority lives, and
// adding a source cannot introduce an ordering bug at a call site.
//
// Naming change from the original: the highest-priority source used to be `.omada`,
// after the TP-Link controller that supplied it. That integration is dropped from
// the project entirely, but the *slot* it occupied is not an accident — it is "a
// name a person deliberately assigned", which must beat anything a device says about
// itself. The case is now `.administrative` and the JSON value changed with it.
// Freezing a dead vendor's name into schema 1 would have been the worse outcome.

/// Where a name came from, in priority order. Lower priority wins.
public enum NameSource: String, Sendable, Hashable, CaseIterable, Codable, Comparable {
    /// A name a person set deliberately — a DHCP reservation label, a controller
    /// entry, a user override in the app. Beats self-advertised names because it
    /// reflects intent rather than a factory default.
    case administrative = "administrative"
    /// Bonjour. The best on-wire source on a home LAN by a wide margin, and the
    /// reason this project treats mDNS as primary rather than as a fallback.
    case mdns = "mdns"
    /// SSDP/UPnP `friendlyName`. Catches TVs, printers, consoles and NAS boxes that
    /// ignore Bonjour entirely.
    case ssdp = "ssdp"
    /// A NBSTAT node-status reply on UDP/137.
    case netbios = "netbios"
    /// Reverse DNS. Last because it so often returns a name derived from the address
    /// itself, which explains nothing.
    case dns = "dns"

    /// Lower wins. Written as a switch rather than derived from the raw value so
    /// that the JSON spelling and the ordering can change independently — the raw
    /// value is a wire contract, the priority is a product decision.
    public var priority: Int {
        switch self {
        case .administrative: 0
        case .mdns: 1
        case .ssdp: 2
        case .netbios: 3
        case .dns: 4
        }
    }

    /// Whether a name from this source stands on its own as an identification.
    ///
    /// Reverse DNS and NetBIOS routinely yield a name mechanically derived from the
    /// address or the MAC — `10-10-20-8.lan`, `WORKGROUP` — which looks like a name
    /// and identifies nothing. A name from one of those sources needs corroboration
    /// before the device counts as identified; see `Identification`.
    public var isSelfSufficient: Bool {
        switch self {
        case .administrative, .mdns, .ssdp: true
        case .netbios, .dns: false
        }
    }

    /// What to call this source when telling a person what did or did not answer.
    ///
    /// The protocol name, not the enum case: a user reads "Bonjour", not "mdns", and a
    /// degradation that names the wrong thing is worse than one that names nothing.
    public var label: String {
        switch self {
        case .administrative: "an assigned name"
        case .mdns: "Bonjour"
        case .ssdp: "UPnP"
        case .netbios: "NetBIOS"
        case .dns: "reverse DNS"
        }
    }

    /// Orders values by the rule documented on this type.
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.priority < rhs.priority }
}

/// One name offered by one source, kept whether it wins or loses.
public struct NameCandidate: Sendable, Hashable, Comparable, Codable {
    /// The name as the source gave it, after cleaning.
    public let value: String
    /// Which source offered it.
    public let source: NameSource
    /// Quality rank within a source — mDNS service types differ in how clean a name
    /// they carry. Zero for sources where the distinction does not apply. Lower is
    /// better, matching the priority ordering.
    public let rank: Int
    /// A model string the same record carried, if any. A source can supply a model
    /// without winning the name, which is why this travels on the candidate rather
    /// than on the device.
    public let model: String?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(value: String, source: NameSource, rank: Int = 0, model: String? = nil) {
        self.value = value
        self.source = source
        self.rank = rank
        self.model = model
    }

    /// Lexicographic on (source priority, rank, value), which makes the entire
    /// cascade `candidates.min()`.
    ///
    /// `value` is the final tiebreak and it is not decoration. Ordering on
    /// (priority, rank) alone is a strict weak ordering but not a *total* one: two
    /// mDNS candidates from service types of equal rank compare as neither less than
    /// the other, so `min()` returns whichever the sort encountered first — which is
    /// mDNS arrival order, which is a race. `displayName` would then flip between
    /// runs for a device that had not changed, and `deriveEvents` would emit a
    /// `nameChanged` at `.warning` severity, the severity reserved for "the identity
    /// join may be wrong". Tying on value costs a string compare and makes the winner
    /// a function of the data alone.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.source.priority, lhs.rank, lhs.value) < (rhs.source.priority, rhs.rank, rhs.value)
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case value
        case source
        case rank
        case model
    }
}

extension Collection where Element == NameCandidate {
    /// The winning name, or nil when nothing named this host.
    public var best: NameCandidate? { self.min() }

    /// Losing candidates, in cascade order. These are the explanation for why a
    /// device is named what it is, and the device detail view renders them under
    /// "also known as". Discarding them destroys the product's main feature.
    public var alternates: [NameCandidate] {
        guard let winner = best else { return [] }
        return sorted().filter { $0 != winner }
    }

    /// How many distinct sources offered a name.
    ///
    /// This is the "how many independent sources agree" input to `Identification`.
    /// Two sources agreeing on a device is materially stronger evidence than one,
    /// and it is the difference between trusting a reverse-DNS name and not.
    public var independentSourceCount: Int {
        Set(map(\.source)).count
    }
}
