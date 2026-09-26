// Device.swift — the fused record, and the two confidences that must stay apart.
//
// There are two layers of host type in this system and they are not redundant:
//
//   HostFacts   what ONE scan observed at one moment. Produced by engines, carried
//               in ProbeEvent, thrown away once folded in.
//   Device      the fused record across observations: first seen, last seen, the
//               accumulated name candidates, and the two confidences. This is what
//               ScanReport carries and what a UI renders.
//
// ── The two confidences ──────────────────────────────────────────────────────────
//
// `identification` answers: how well do we know WHAT this thing is? Do we have a
// name, a model, a vendor, an OS hint, and do independent sources agree? It is what
// every row of the device list shows and the only one a non-technical user ever
// sees.
//
// `identityStability` answers a different question entirely: how likely is this
// RECORD to fragment or to merge wrongly? It comes from the weight of the strongest
// join key — universal MAC, then mDNS instance, then randomized MAC, then IP lease.
// It explains why the identity history looks the way it does, and it belongs one
// level in: the detail view's identity card, and the CLI's JSON. Never the list.
//
// They are computed from different inputs and they routinely disagree, which is the
// proof they are not the same number:
//
//   A MacBook advertising a clean Bonjour name over a randomized MAC:
//       identification = .identified     (we know exactly what it is)
//       identityStability = .moderate    (the name is the only thing holding the
//                                         record together across MAC rotations)
//
//   A gateway with a burned-in MAC and no friendly name anywhere:
//       identification = .partial        (a vendor and a model string, no name)
//       identityStability = .strong      (that MAC will never change)
//
// Collapsing them into one field loses one of those two facts every time. This
// project has made that mistake once already; the comment is here so it is not made
// a second time.

// Foundation is used here for exactly two things: UUID, and the single wall-clock
// reading behind `Timestamp.now`. Both are available in swift-corelibs-foundation, so
// this import does not compromise the Linux requirement — and it is a plain import
// rather than a conditional, which keeps `grep -r "#if" Sources/` returning nothing.
import Foundation

/// How well we know what a device is. The user-facing confidence.
public enum Identification: String, Sendable, Hashable, CaseIterable, Codable, Comparable {
    /// A real name, from a source that stands on its own or corroborated by a second
    /// source. The device list shows this without qualification.
    case identified = "identified"
    /// Something, but not a name: a model, a vendor, an OS hint — or a name from a
    /// source too weak to trust alone. Enough to say roughly what it is.
    case partial = "partial"
    /// An address, and possibly a MAC that tells us nothing. The unidentified device
    /// is the normal case on a network full of private Wi-Fi addresses, and it is
    /// rendered as an ordinary row, never as an error.
    case minimal = "minimal"

    /// Ordered most-known first.
    public var rank: Int {
        switch self {
        case .identified: 0
        case .partial: 1
        case .minimal: 2
        }
    }

    /// Orders values by the rule documented on this type.
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

/// The inputs `Identification` is fused from, kept as a value so the conclusion can
/// be explained rather than asserted.
///
/// Carried separately rather than folded into the enum because the detail view wants
/// to show *why* a device reads as partial, and because a consumer that disagrees
/// with our thresholds can recompute from the same evidence.
public struct IdentificationEvidence: Sendable, Hashable, Codable {
    /// A name exists that is not merely a restatement of the model string.
    public var hasDistinctName: Bool
    /// The winning name came from a source that stands on its own — administrative,
    /// mDNS or SSDP rather than NetBIOS or reverse DNS.
    public var nameSourceIsSelfSufficient: Bool
    /// A model string is known.
    public var hasModel: Bool
    /// A vendor is known. Absent for a randomized MAC, by construction.
    public var hasVendor: Bool
    /// A TTL-derived OS family hint is available.
    public var hasOSHint: Bool
    /// How many distinct sources offered a name.
    public var independentSources: Int

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        hasDistinctName: Bool,
        nameSourceIsSelfSufficient: Bool,
        hasModel: Bool,
        hasVendor: Bool,
        hasOSHint: Bool,
        independentSources: Int
    ) {
        self.hasDistinctName = hasDistinctName
        self.nameSourceIsSelfSufficient = nameSourceIsSelfSufficient
        self.hasModel = hasModel
        self.hasVendor = hasVendor
        self.hasOSHint = hasOSHint
        self.independentSources = independentSources
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case hasDistinctName = "has_distinct_name"
        case nameSourceIsSelfSufficient = "name_source_is_self_sufficient"
        case hasModel = "has_model"
        case hasVendor = "has_vendor"
        case hasOSHint = "has_os_hint"
        case independentSources = "independent_sources"
    }
}

extension Identification {
    /// Fuses evidence into a level.
    ///
    /// The rule, and the reasoning behind each clause:
    ///
    /// `.identified` needs a name that is genuinely a name — not the model string
    /// echoed back — from a source that stands on its own, OR corroborated by a
    /// second independent source. That second clause is what "how many independent
    /// sources agree" buys: a reverse-DNS name alone is `10-10-20-8.lan`, which
    /// looks like a name and identifies nothing, but the same name confirmed by
    /// NetBIOS is real.
    ///
    /// `.partial` is everything with some substance: a model, a vendor, an OS hint,
    /// or a name we do not yet trust alone.
    ///
    /// `.minimal` is an address. It is a normal outcome, not a failure.
    public init(evidence: IdentificationEvidence) {
        if evidence.hasDistinctName,
           evidence.nameSourceIsSelfSufficient || evidence.independentSources >= 2 {
            self = .identified
        } else if evidence.hasDistinctName || evidence.hasModel || evidence.hasVendor
                    || evidence.hasOSHint {
            self = .partial
        } else {
            self = .minimal
        }
    }
}

/// A coarse OS family, hinted at by the TTL on an echo reply.
///
/// This is free information. Every ICMP echo reply carries a TTL, the initial values
/// vendors ship are distinct, and reading it costs nothing on top of a probe we were
/// sending anyway. It is a *hint* and named as one: a hop count subtracts from the
/// TTL, so the value seen is the initial value minus the distance, and on a LAN that
/// distance is zero or one.
///
/// Fused identity beats this every time — `AppleTV5,3` from a Bonjour TXT record is
/// more precise than any fingerprint guess — so the OS hint is supplementary
/// evidence for `Identification`, never the basis of a claim on its own.
public enum OSHint: String, Sendable, Hashable, CaseIterable, Codable {
    /// TTL near 64: Linux, macOS, iOS, Android, most embedded stacks.
    case unixLike = "unix_like"
    /// TTL near 128: Windows.
    case windows = "windows"
    /// TTL near 255: routers, switches, printers and other network gear.
    case networkDevice = "network_device"

    /// Derives a hint from an observed TTL, allowing for up to 32 hops of decrement.
    ///
    /// Returns nil rather than guessing when the value falls in no band. A TTL of 100
    /// is either a Windows host 28 hops away or something unusual, and on a LAN it is
    /// far more likely to be something unusual — reporting nothing is honest, and
    /// `nil` here means *not observed*, which is what optionality means everywhere in
    /// this model.
    public init?(ttl: UInt8) {
        switch ttl {
        case 32...64: self = .unixLike
        case 96...128: self = .windows
        case 224...255: self = .networkDevice
        default: return nil
        }
    }
}

/// One device, fused across everything a run learned about it.
public struct Device: Sendable, Hashable, Codable {
    /// The address it was last seen at.
    public var ip: IPv4Address
    /// Its hardware address, where one was observed. Absent when the neighbour cache
    /// had no entry — not zero.
    public var mac: MACAddress?
    /// Every name candidate, winners and losers.
    ///
    /// The losers are kept deliberately. Explaining *why* a device is named what it
    /// is, is the feature; discarding the alternatives destroys it, and the device
    /// detail view renders them directly.
    public var names: [NameCandidate]
    /// OUI-derived vendor. Necessarily nil for a randomized MAC, since the OUI of a
    /// locally administered address is meaningless.
    public var vendor: String?
    /// The PTR name, where one resolved. Carried rather than folded away because it
    /// is evidence a reader may want to see disagreeing with the winning name.
    public var reverseDNS: String?
    /// A hostname from a DHCP lease.
    ///
    /// Carried on the fused record, not only on the observation, because it is a
    /// weight-40 identity key: without it `HostIdentifier.candidates(for:)` would
    /// produce a different key set for a `Device` than for the `HostFacts` it came
    /// from, `identityStability` could not be recomputed from a report, and a
    /// randomized-MAC device whose only stable key is its lease name would appear to
    /// vanish and return on every MAC rotation.
    public var dhcpHostname: String?
    /// How well we know what this is. See the file header.
    public var identification: Identification
    /// The evidence `identification` was fused from, so the conclusion can be shown
    /// rather than asserted.
    public var identificationEvidence: IdentificationEvidence
    /// How stable the join key behind this record is. See the file header — this is
    /// a different question with different inputs, and not a duplicate of the above.
    public var identityStability: Stability
    /// TTL from an echo reply. 64 unix-like, 128 Windows, 255 network gear.
    public var ttl: UInt8?
    /// Round trip to this host.
    public var rtt: RTTSample?
    /// Ports observed on it.
    public var ports: [PortObservation]
    /// What the host's TCP stack disclosed, if a fingerprint probe ran. Supplementary
    /// evidence for `identification` and never the basis of a claim on its own — on a
    /// consumer LAN a Bonjour model string beats any fingerprint.
    public var osFingerprint: OSFingerprint?
    /// How this device was found, strongest evidence first.
    ///
    /// Stored as an already-canonical array rather than a set, because at this level it
    /// is reported and never merged — `HostFacts` is where two engines' findings are
    /// unioned, and by the time one becomes a `Device` that question is settled. An
    /// array also keeps the synthesized encoder honest: a `Set` would emit in hash
    /// order and make two identical scans differ.
    ///
    /// Empty means the engine did not say, which is what an artifact written before
    /// this field existed decodes to.
    public var discoveredVia: [DiscoverySource]
    /// When this device was first ever seen. Wall clock, for display.
    public var firstSeen: Timestamp
    /// When it was last seen. Wall clock, for display.
    public var lastSeen: Timestamp

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        ip: IPv4Address,
        mac: MACAddress? = nil,
        names: [NameCandidate] = [],
        vendor: String? = nil,
        reverseDNS: String? = nil,
        dhcpHostname: String? = nil,
        identification: Identification,
        identificationEvidence: IdentificationEvidence,
        identityStability: Stability,
        ttl: UInt8? = nil,
        rtt: RTTSample? = nil,
        ports: [PortObservation] = [],
        osFingerprint: OSFingerprint? = nil,
        discoveredVia: [DiscoverySource] = [],
        firstSeen: Timestamp,
        lastSeen: Timestamp
    ) {
        self.ip = ip
        self.mac = mac
        // Canonical order on construction. `names` decides `displayName`, and
        // `NameCandidate`'s ordering is total, so the winner cannot depend on the
        // order mDNS happened to answer in.
        self.names = names.sorted()
        self.vendor = vendor
        self.reverseDNS = reverseDNS
        self.dhcpHostname = dhcpHostname
        self.identification = identification
        self.identificationEvidence = identificationEvidence
        self.identityStability = identityStability
        self.ttl = ttl
        self.rtt = rtt
        // Canonical order, so two scans that found the same ports encode to the same
        // bytes and a real change is what a diff shows.
        self.ports = ports.sorted { ($0.port, $0.proto.rawValue) < ($1.port, $1.proto.rawValue) }
        self.osFingerprint = osFingerprint
        self.discoveredVia = discoveredVia.sorted()
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ip
        case mac
        case names
        case vendor
        case reverseDNS = "reverse_dns"
        case dhcpHostname = "dhcp_hostname"
        case identification
        case identificationEvidence = "identification_evidence"
        case identityStability = "identity_stability"
        case ttl
        case rtt
        case ports
        case osFingerprint = "os_fingerprint"
        case discoveredVia = "discovered_via"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
    }
}

extension Device {
    /// Decodes, routing through the memberwise initializer.
    ///
    /// Not the synthesized conformance, because the synthesized one assigns stored
    /// properties directly and would let a hand-edited document reintroduce an
    /// unsorted `names` or `ports` array. Both entry points into a `Device` — this
    /// and the memberwise init — establish the same canonical order, so the ordering
    /// invariant holds for every value that exists.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            ip: try container.decode(IPv4Address.self, forKey: .ip),
            mac: try container.decodeIfPresent(MACAddress.self, forKey: .mac),
            names: try container.decodeIfPresent([NameCandidate].self, forKey: .names) ?? [],
            vendor: try container.decodeIfPresent(String.self, forKey: .vendor),
            reverseDNS: try container.decodeIfPresent(String.self, forKey: .reverseDNS),
            dhcpHostname: try container.decodeIfPresent(String.self, forKey: .dhcpHostname),
            identification: try container.decode(Identification.self, forKey: .identification),
            identificationEvidence: try container.decode(
                IdentificationEvidence.self, forKey: .identificationEvidence
            ),
            identityStability: try container.decode(Stability.self, forKey: .identityStability),
            ttl: try container.decodeIfPresent(UInt8.self, forKey: .ttl),
            rtt: try container.decodeIfPresent(RTTSample.self, forKey: .rtt),
            ports: try container.decodeIfPresent([PortObservation].self, forKey: .ports) ?? [],
            osFingerprint: try container.decodeIfPresent(OSFingerprint.self, forKey: .osFingerprint),
            discoveredVia: try container.decodeIfPresent([DiscoverySource].self, forKey: .discoveredVia) ?? [],
            firstSeen: try container.decode(Timestamp.self, forKey: .firstSeen),
            lastSeen: try container.decode(Timestamp.self, forKey: .lastSeen)
        )
    }

    /// Projects one scan's observation into a device record, computing both
    /// confidences.
    ///
    /// This is the path a consumer without a store takes — the CLI, running one scan
    /// and emitting one report. A consumer with a store folds `HostFacts` into an
    /// existing record instead and recomputes the same two numbers from the
    /// accumulated evidence.
    ///
    /// - Parameters:
    ///   - facts: what the scan observed.
    ///   - network: the network scanned, needed to scope the `ipLease` join key.
    ///   - firstSeen: when this device was first ever seen. Defaults to `lastSeen`,
    ///     which is correct for a first-ever run and wrong afterwards — a caller with
    ///     history must pass the real value.
    ///   - lastSeen: when this observation was made.
    public init(
        observing facts: HostFacts,
        in network: IPv4Network,
        firstSeen: Timestamp? = nil,
        lastSeen: Timestamp = .now
    ) {
        let evidence = IdentificationEvidence(facts: facts)
        let keys = HostIdentifier.candidates(for: facts, in: network)
        self.init(
            ip: facts.ip,
            mac: facts.mac,
            names: facts.allNames,
            vendor: facts.vendor,
            reverseDNS: facts.reverseDNS,
            dhcpHostname: facts.dhcpHostname,
            identification: Identification(evidence: evidence),
            identificationEvidence: evidence,
            identityStability: Stability(strongestOf: keys),
            ttl: facts.ttl,
            rtt: facts.rtt,
            ports: facts.ports,
            osFingerprint: facts.osFingerprint,
            discoveredVia: facts.discoveredVia.canonical,
            firstSeen: firstSeen ?? lastSeen,
            lastSeen: lastSeen
        )
    }

    /// The name shown to a person, or nil when nothing named this device.
    public var displayName: String? { names.best?.value }

    /// The model string, preferring the winning candidate's but falling back to any
    /// candidate that carried one. A source can supply a model without winning the
    /// name, and dropping the model in that case loses real information.
    public var displayModel: String? {
        names.best?.model ?? names.sorted().lazy.compactMap(\.model).first
    }

    /// The TTL-derived OS family hint, if the TTL falls in a recognized band.
    public var osHint: OSHint? { ttl.flatMap(OSHint.init(ttl:)) }

    /// Ports that answered.
    public var openPorts: [PortObservation] { ports.filter { $0.state == .open } }

    /// Whether any port observation proves this host is reachable — `.open` or
    /// `.closed`. All-`.filtered` proves nothing, which is the distinction the
    /// three-valued `PortState` exists to preserve.
    public var portScanProvesAlive: Bool { ports.contains { $0.state.provesHostAlive } }
}

extension IdentificationEvidence {
    /// Extracts identification evidence from one observation.
    ///
    /// "Distinct name" means a name that is not just the model echoed back. A router
    /// we could only name from its model string has a name field populated and is
    /// still only `.partial`, because knowing a device calls itself `ER7206` is
    /// knowing the model, not the device.
    public init(facts: HostFacts) {
        let model = facts.allNames.best?.model
            ?? facts.allNames.sorted().lazy.compactMap(\.model).first
        let winner = facts.allNames.best
        let name = winner?.value
        let nameIsJustTheModel: Bool = {
            guard let name, let model else { return false }
            return HostIdentifier.normalized(name) == HostIdentifier.normalized(model)
        }()
        self.init(
            hasDistinctName: (name?.isEmpty == false) && !nameIsJustTheModel,
            nameSourceIsSelfSufficient: winner?.source.isSelfSufficient ?? false,
            hasModel: model?.isEmpty == false,
            hasVendor: facts.vendor?.isEmpty == false,
            hasOSHint: facts.ttl.flatMap(OSHint.init(ttl:)) != nil,
            independentSources: facts.allNames.independentSourceCount
        )
    }
}
