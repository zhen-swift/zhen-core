// HostIdentifier.swift — the weighted join keys identity is resolved through.
//
// MAC is never the primary key. Private Wi-Fi addresses rotate, and on a modern home
// network that is the common case rather than the edge case: keying on MAC would
// mint a new device on every rotation and make the history worthless.
//
// So identity is a weighted set of keys, and the strongest one that matches wins.
// The weights are the whole design. `mdnsInstance` (60) deliberately outranks
// `randomizedMAC` (30): an iPhone using private addressing but advertising a stable
// Bonjour name has to stay ONE device across rotations, and that requires the name to
// beat the MAC.
//
// Shape note: SPEC modelled this as an enum with associated values. It is a struct
// here — `kind` plus a normalized `value` string — for one reason: this is a wire
// format. An enum with associated values has no natural JSON encoding, and every
// scheme for giving it one (a discriminator object, an array pair) is something a
// consumer in another language has to special-case. `{"kind": "...", "value": "..."}`
// is not.
//
// The resolution algorithm that consumes these — first hit wins, differing hits
// merge, and the anti-collapse guard on `ipLease` — lives in the store, not here.
// Core defines what a key *is* and how strong it is.

/// What kind of thing an identity key is derived from. Ordered strongest first.
public enum HostIdentifierKind: String, Sendable, Hashable, CaseIterable, Codable, Comparable {
    /// A globally administered MAC: burned in, genuinely stable, the best key there
    /// is. Absent for every device using private Wi-Fi addressing.
    case universalMAC = "universal_mac"
    /// A normalized Bonjour instance name. Stable across MAC rotation, which is what
    /// makes randomized-MAC devices trackable at all.
    case mdnsInstance = "mdns_instance"
    /// A hostname from a DHCP lease. Stable while the lease is, and it is often a
    /// name the device never advertises on the wire.
    case dhcpHostname = "dhcp_hostname"
    /// A locally administered MAC. Rotates on a schedule the device chooses, so it
    /// identifies a device only until it does not.
    case randomizedMAC = "randomized_mac"
    /// An address within a network. Last resort, and the reason the store needs an
    /// anti-collapse guard: two devices swapping leases must not merge into one.
    case ipLease = "ip_lease"

    /// How much this kind is trusted as a join key, 0–100.
    ///
    /// These numbers are compared, not summed. Their absolute values do not mean
    /// anything; the gaps between them do, and `mdnsInstance` sitting above
    /// `randomizedMAC` is the single most consequential gap in the system.
    public var weight: Int {
        switch self {
        case .universalMAC: 100
        case .mdnsInstance: 60
        case .dhcpHostname: 40
        case .randomizedMAC: 30
        case .ipLease: 10
        }
    }

    /// Higher weight sorts first, so `candidates.sorted()` is strongest-first and
    /// "first hit wins" is a `for` loop.
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.weight > rhs.weight }
}

/// One identity key: a kind and the normalized value it matches on.
public struct HostIdentifier: Sendable, Hashable, Codable, Comparable {
    /// Which kind of key this is.
    public var kind: HostIdentifierKind
    /// The normalized value. Normalization is the caller's job and the constructors
    /// below do it: MACs go through `MACAddress.description`, names are lowercased
    /// and trimmed. Two spellings of the same thing must produce the same key or the
    /// join silently fails.
    public var value: String

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(kind: HostIdentifierKind, value: String) {
        self.kind = kind
        self.value = value
    }

    /// Convenience for the weight of this key's kind.
    public var weight: Int { kind.weight }

    /// Strongest first, then by value so the ordering is total and deterministic —
    /// a report has to diff cleanly against the previous one.
    ///
    /// Note the inversion on weight: a *higher* weight sorts *earlier*, so
    /// `candidates.sorted()` is strongest-first and "first hit wins" is a plain `for`
    /// loop over it rather than a search.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.kind.weight != rhs.kind.weight { return lhs.kind.weight > rhs.kind.weight }
        return lhs.value < rhs.value
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case kind
        case value
    }
}

extension HostIdentifier {
    /// A key from a MAC, choosing the kind from the locally-administered bit.
    ///
    /// The caller does not get to decide whether a MAC is stable — the address says
    /// so itself, and reading bit 1 of the first octet is the entire test. Making
    /// this one function means no call site can get it backwards.
    public static func fromMAC(_ mac: MACAddress) -> HostIdentifier {
        HostIdentifier(
            kind: mac.isLocallyAdministered ? .randomizedMAC : .universalMAC,
            value: mac.description
        )
    }

    /// A key from a Bonjour instance name.
    public static func mdnsInstance(_ instance: String) -> HostIdentifier {
        HostIdentifier(kind: .mdnsInstance, value: normalized(instance))
    }

    /// A key from a DHCP lease hostname.
    public static func dhcpHostname(_ hostname: String) -> HostIdentifier {
        HostIdentifier(kind: .dhcpHostname, value: normalized(hostname))
    }

    /// A key from an address within a network.
    ///
    /// Scoped by network on purpose: `192.168.1.10` on one LAN and on another are
    /// different devices, and an unscoped address key would merge them the first time
    /// a laptop moved between two networks with the same numbering.
    public static func ipLease(_ address: IPv4Address, in network: IPv4Network) -> HostIdentifier {
        HostIdentifier(kind: .ipLease, value: "\(network)@\(address)")
    }

    /// Lowercased and trimmed of surrounding whitespace. Bonjour instance names
    /// arrive with inconsistent case from different service types on the same
    /// device, and a case-sensitive key would split it.
    static func normalized(_ text: String) -> String {
        text.trimmingCharacters(in: [" ", "\t", "\n", "\r"]).lowercased()
    }
}

extension HostIdentifier {
    /// The single derivation of candidate keys, used by every overload below.
    ///
    /// One function rather than one per input type, and that is a correctness
    /// requirement rather than tidiness. There used to be two — one over `HostFacts`,
    /// one over `Device` — and they disagreed: the `Device` overload had no DHCP
    /// hostname to read, so it silently omitted a weight-40 key the other produced.
    /// The consequences were not cosmetic. `identityStability` in a report could not
    /// be recomputed from that report, and `deriveEvents` could never reach the
    /// DHCP-hostname clause its own documentation promised — so a randomized-MAC
    /// device whose only stable key was its lease name emitted hostDisappeared plus
    /// hostAppeared on every MAC rotation, which is precisely the failure the whole
    /// identity model exists to prevent.
    ///
    /// Two derivations of one thing will drift. This one cannot.
    static func candidates(
        leases: [IPv4Address],
        mac: MACAddress?,
        names: [NameCandidate],
        dhcpHostname: String?,
        network: IPv4Network
    ) -> [HostIdentifier] {
        var keys: [HostIdentifier] = []
        if let mac { keys.append(.fromMAC(mac)) }
        for candidate in names where candidate.source == .mdns && !candidate.value.isEmpty {
            keys.append(.mdnsInstance(candidate.value))
        }
        if let dhcpHostname, !dhcpHostname.isEmpty {
            keys.append(.dhcpHostname(dhcpHostname))
        }
        for lease in leases { keys.append(.ipLease(lease, in: network)) }
        // Deduplicate while keeping the strongest-first order: two mDNS service
        // types on the same device routinely offer the same instance name.
        var seen: Set<HostIdentifier> = []
        return keys.sorted().filter { seen.insert($0).inserted }
    }

    /// Every candidate key an observation supports, strongest first.
    ///
    /// This is step one of the store's resolution algorithm, extracted so it is a
    /// pure function testable with no database. The store then looks each up in
    /// order and takes the first hit.
    ///
    /// - Parameters:
    ///   - facts: what one scan saw.
    ///   - network: the network the scan ran over, needed to scope the `ipLease` key.
    public static func candidates(for facts: HostFacts, in network: IPv4Network) -> [HostIdentifier] {
        candidates(
            leases: [facts.ip],
            mac: facts.mac,
            names: facts.allNames,
            dhcpHostname: facts.dhcpHostname,
            network: network
        )
    }

    /// Every candidate key a fused device record supports, strongest first.
    ///
    /// Produces exactly the same set as the `HostFacts` overload for the same host —
    /// which is why `Device` carries `dhcpHostname` at all. A report has to be able
    /// to reproduce its own identity keys, or `identityStability` is a number nobody
    /// downstream can check.
    public static func candidates(for device: Device, in network: IPv4Network) -> [HostIdentifier] {
        // One lease key per v4 address. A v6 address is not a lease: a link-local one is
        // self-assigned and a global one is scoped by a prefix this key has no room for,
        // and neither is scoped by the v4 network the store keys leases by.
        candidates(
            leases: device.ipv4Addresses,
            mac: device.mac,
            names: device.names,
            dhcpHostname: device.dhcpHostname,
            network: network
        )
    }
}

/// How stable the join key behind a device record is — how likely that record is to
/// fragment across runs, or to merge with the wrong thing.
///
/// This is not a measure of how well we know *what* the device is; that is
/// `Identification`, and the two answer different questions from different inputs.
/// See `Device` for why keeping them apart matters.
public enum Stability: String, Sendable, Hashable, CaseIterable, Codable, Comparable {
    /// A burned-in MAC. This record will still be this record in a year.
    case strong = "strong"
    /// A stable name — a Bonjour instance, or a DHCP lease hostname. Survives MAC
    /// rotation; does not survive the user renaming the device or the lease expiring.
    case moderate = "moderate"
    /// A rotating MAC and nothing better. The record will fragment when the address
    /// next rolls over, unless something stronger arrives first.
    case weak = "weak"
    /// An address lease and nothing else. Identity here is a guess that holds only
    /// while the lease does.
    case ephemeral = "ephemeral"

    /// Ordered strongest first.
    public var rank: Int {
        switch self {
        case .strong: 0
        case .moderate: 1
        case .weak: 2
        case .ephemeral: 3
        }
    }

    /// Orders values by the rule documented on this type.
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }

    /// Maps the weight of the strongest available key onto a stability band.
    ///
    /// Bands rather than the raw weight because the weight is an implementation
    /// detail of the join and the band is what a surface renders.
    ///
    /// Every threshold sits strictly between two defined weights, so no key kind
    /// lands on a boundary and adding one later falls into a band by construction:
    ///
    ///     universalMAC   100  ┐ strong      (≥ 80)
    ///                         ├─ 80
    ///     mdnsInstance    60  ┐
    ///     dhcpHostname    40  ┘ moderate    (35 ..< 80)
    ///                         ├─ 35
    ///     randomizedMAC   30    weak        (20 ..< 35)
    ///                         ├─ 20
    ///     ipLease         10    ephemeral   (< 20)
    ///
    /// The earlier bands had `moderate` starting at 50, which put `dhcpHostname` (40)
    /// into `weak` — a band whose own documentation says "a rotating MAC and nothing
    /// better", so a host with no MAC at all was described as having a rotating one,
    /// while `moderate` named the DHCP hostname as its example case. The code and the
    /// prose now agree.
    public init(strongestWeight: Int) {
        switch strongestWeight {
        case 80...: self = .strong
        case 35..<80: self = .moderate
        case 20..<35: self = .weak
        default: self = .ephemeral
        }
    }

    /// Stability of a set of candidate keys, taken from the strongest one.
    ///
    /// An empty set is `.ephemeral` rather than a failure: a device with no keys at
    /// all is a device we cannot track, which is a legitimate state to report.
    public init(strongestOf identifiers: some Collection<HostIdentifier>) {
        self.init(strongestWeight: identifiers.map(\.weight).max() ?? 0)
    }
}
