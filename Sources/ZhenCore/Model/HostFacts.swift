// HostFacts.swift — what one scan observed about one host.
//
// A frozen value type. This is what crosses every isolation boundary in the
// pipeline; nothing holding a file descriptor and no persistent model ever does.
//
// HostFacts is the OBSERVATION. `Device` is the fused RECORD built from one or more
// of them, and it is the thing that carries first-seen, last-seen and the two
// confidences. Engines produce HostFacts and know nothing about Device; the fusion
// step goes one way and never back. Keeping them separate is what lets a scan run
// with no history at all — the CLI's default — and still produce a valid report.
//
// Two changes from the original shape, both to remove a duplicate:
//   * `ports` is `[PortObservation]`, the type the report already had to carry.
//     `PortFacts` was the same idea with loose String fields where ServiceIdentity
//     belongs, and two spellings of one concept is exactly what a definition package
//     exists to prevent.
//   * `rttMillis: Double?` became `rtt: RTTSample?`. A bare Double cannot say how
//     many samples it rests on or what the smoothed estimate is, and the adaptive
//     per-host timeout needs both.

/// Everything one scan learned about one host.
public struct HostFacts: Sendable, Hashable, Codable {
    /// The address probed.
    public var ip: IPv4Address
    /// The hardware address, from the neighbour cache or a layer-2 sweep. Absent
    /// means the cache had no entry for it, not that the host has no MAC.
    public var mac: MACAddress?
    /// Every candidate, winners and losers. The pipeline must not discard the
    /// losers — they are what the detail view explains the chosen name with.
    public var allNames: [NameCandidate]
    /// From the OUI, and therefore absent for a randomized MAC. A device can have a
    /// model and no vendor; that is a normal state, not missing data.
    public var vendor: String?
    /// The PTR name, where one resolved.
    public var reverseDNS: String?
    /// A hostname from a DHCP lease — often a name the device never advertises on
    /// the wire, which makes it the best available input for identifying a host
    /// behind a randomized MAC.
    public var dhcpHostname: String?
    /// TTL from the echo reply. 64 hints Linux/macOS/iOS, 128 Windows, 255 network
    /// gear. Free OS hinting from a probe we were sending anyway.
    public var ttl: UInt8?
    /// Round trip, measured monotonically. This is what the adaptive per-host
    /// timeout is derived from, which is why it carries the estimator state and not
    /// just a number.
    public var rtt: RTTSample?
    /// Port observations, if a deep scan ran.
    public var ports: [PortObservation]
    /// What the host's TCP stack disclosed about itself, if a fingerprint probe ran.
    ///
    /// Distinct from `osHint`, which is one TTL band and ships on every ICMP reply.
    /// This is a match against `StackSignatures` and carries the features it matched
    /// on, so a reader can disagree with the table.
    public var osFingerprint: OSFingerprint?
    /// How this host came to be reported: answered a probe, answered ARP, was in the
    /// neighbour table, or is this machine itself.
    ///
    /// A set, because these are not alternatives — a host can be reached two ways, and
    /// when the composite engine unions a privileged and an unprivileged result that
    /// agreement is the most informative thing it produces. Empty means an engine did
    /// not say, which is the honest reading of an older artifact rather than a claim
    /// that the host was found by nothing.
    public var discoveredVia: Set<DiscoverySource>

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        ip: IPv4Address,
        mac: MACAddress? = nil,
        allNames: [NameCandidate] = [],
        vendor: String? = nil,
        reverseDNS: String? = nil,
        dhcpHostname: String? = nil,
        ttl: UInt8? = nil,
        rtt: RTTSample? = nil,
        ports: [PortObservation] = [],
        osFingerprint: OSFingerprint? = nil,
        discoveredVia: Set<DiscoverySource> = []
    ) {
        self.ip = ip
        self.mac = mac
        // Canonical order here too, not only on `Device`. A HostFacts is encoded — it
        // is the payload of a `hostFound` event, and the CLI's --ndjson mode writes one
        // per line — so an unsorted array makes the streaming artifact unstable in
        // exactly the way the report artifact was.
        self.allNames = allNames.sorted()
        self.vendor = vendor
        self.reverseDNS = reverseDNS
        self.dhcpHostname = dhcpHostname
        self.ttl = ttl
        self.rtt = rtt
        self.ports = ports.sorted { ($0.port, $0.proto.rawValue) < ($1.port, $1.proto.rawValue) }
        self.osFingerprint = osFingerprint
        self.discoveredVia = discoveredVia
    }

    /// Decodes, routing through the memberwise initializer so the canonical order is
    /// established on this path too.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            ip: try container.decode(IPv4Address.self, forKey: .ip),
            mac: try container.decodeIfPresent(MACAddress.self, forKey: .mac),
            allNames: try container.decodeIfPresent([NameCandidate].self, forKey: .allNames) ?? [],
            vendor: try container.decodeIfPresent(String.self, forKey: .vendor),
            reverseDNS: try container.decodeIfPresent(String.self, forKey: .reverseDNS),
            dhcpHostname: try container.decodeIfPresent(String.self, forKey: .dhcpHostname),
            ttl: try container.decodeIfPresent(UInt8.self, forKey: .ttl),
            rtt: try container.decodeIfPresent(RTTSample.self, forKey: .rtt),
            ports: try container.decodeIfPresent([PortObservation].self, forKey: .ports) ?? [],
            osFingerprint: try container.decodeIfPresent(OSFingerprint.self, forKey: .osFingerprint),
            discoveredVia: Set(
                try container.decodeIfPresent([DiscoverySource].self, forKey: .discoveredVia) ?? []
            )
        )
    }

    /// The winning name, or nil when nothing named this host.
    public var displayName: String? { allNames.best?.value }

    /// The model string, preferring the winner's but accepting one from a losing
    /// candidate rather than dropping it.
    public var displayModel: String? {
        allNames.best?.model ?? allNames.sorted().lazy.compactMap(\.model).first
    }

    /// True when nothing named this host. The device list renders it as an ordinary
    /// row, never as an error — an unnamed device with a randomized MAC is the
    /// normal case on this network and the acceptance case for the whole product.
    public var isUnidentified: Bool { allNames.isEmpty }

    /// Ports that answered.
    public var openPorts: [PortObservation] { ports.filter { $0.state == .open } }

    /// TTL-derived OS family hint, where the TTL falls in a recognized band.
    public var osHint: OSHint? { ttl.flatMap(OSHint.init(ttl:)) }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ip
        case mac
        case allNames = "all_names"
        case vendor
        case reverseDNS = "reverse_dns"
        case dhcpHostname = "dhcp_hostname"
        case ttl
        case rtt
        case ports
        case osFingerprint = "os_fingerprint"
        case discoveredVia = "discovered_via"
    }

    /// Encodes, writing `discovered_via` in its canonical order.
    ///
    /// Hand-written because a `Set` has no order of its own and the synthesized
    /// encoder would emit whatever the hash seed produced that run — which makes two
    /// identical scans differ byte for byte, the exact instability `allNames` and
    /// `ports` are sorted to avoid.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ip, forKey: .ip)
        try container.encodeIfPresent(mac, forKey: .mac)
        try container.encode(allNames, forKey: .allNames)
        try container.encodeIfPresent(vendor, forKey: .vendor)
        try container.encodeIfPresent(reverseDNS, forKey: .reverseDNS)
        try container.encodeIfPresent(dhcpHostname, forKey: .dhcpHostname)
        try container.encodeIfPresent(ttl, forKey: .ttl)
        try container.encodeIfPresent(rtt, forKey: .rtt)
        try container.encode(ports, forKey: .ports)
        try container.encodeIfPresent(osFingerprint, forKey: .osFingerprint)
        try container.encode(discoveredVia.canonical, forKey: .discoveredVia)
    }
}

/// One IPv4 interface on this machine.
public struct NetworkInterface: Sendable, Hashable, Codable {
    /// BSD interface name — `en0`, `eth0`.
    public var name: String
    /// This machine's address on it.
    public var address: IPv4Address
    /// The network it is attached to, which is what gets scanned by default.
    public var network: IPv4Network
    /// This machine's hardware address on it, where one is readable.
    public var hardwareAddress: MACAddress?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        name: String,
        address: IPv4Address,
        network: IPv4Network,
        hardwareAddress: MACAddress? = nil
    ) {
        self.name = name
        self.address = address
        self.network = network
        self.hardwareAddress = hardwareAddress
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case name
        case address
        case network
        case hardwareAddress = "hardware_address"
    }
}
