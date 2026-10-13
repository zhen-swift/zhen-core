// PlatformSeam.swift — what only a platform can do, declared where everyone can see it.
//
// The portability rule constrains this package more than anything else in it: the
// public API of core must compile on Linux. Darwin-only machinery — `dns_sd`, kqueue,
// BPF, the route socket — is reachable only through the protocols declared here and
// implemented in platform targets. A `#if canImport(Darwin)` inside a public type's
// body is a design failure; a protocol with two conformances is not.
//
// There is no `#if` in this file, and there must never be one. `#if os(...)` belongs
// only in the platform targets that conform to these protocols. The moment a
// conditional leaks into a command, a renderer or a model type, the portability claim
// is gone and nobody notices for six months.
//
// Every one of these is async or synchronous by deliberate choice rather than habit.
// Interface enumeration is a `sysctl` and returns immediately; a neighbour-table walk
// is a larger `sysctl` and still returns immediately, but is async because the Linux
// implementation reads `/proc` or talks netlink and should not be forced to lie about
// that. Browsing and reverse resolution are `AsyncSequence` and `async` because they
// are genuinely long-running and must be cancellable.

/// What can go wrong reaching the platform.
///
/// Typed, and used with `throws(PlatformError)`, so the top-level mapping from a
/// failure to an exit code or a `Degradation` is a switch the compiler checks for
/// exhaustiveness. Note that these are *setup* failures. Once probing starts, nothing
/// throws: a probe that gets no answer is a value and a denied capability is a
/// `Degradation`.
public enum PlatformError: Error, Sendable, Hashable {
    /// The platform has no implementation of this at all — Bonjour browsing on a
    /// Linux box with no Avahi. A missing capability is a `Degradation`, never a
    /// build failure: that machine scans fine and reports that names were
    /// unavailable, exactly as macOS does when the permission is denied.
    case unavailable(String)
    /// The platform refused. Note that the most important denial in this system —
    /// the macOS Local Network permission — does NOT arrive here: it returns zero
    /// results rather than an error, and has to be inferred. See
    /// `LocalNetworkDenialHeuristic`.
    case denied(String)
    /// Asked for something that is not there — an interface name that does not exist.
    case notFound(String)
    /// A syscall failed. `code` is `errno`, `api` names the call, so a bug report
    /// carries something actionable rather than "it didn't work".
    case systemError(code: Int32, api: String)
}

/// Enumerates this machine's network interfaces.
///
/// `getifaddrs` on both Darwin and Linux; `GetAdaptersAddresses` on Windows later.
public protocol InterfaceProvider: Sendable {
    /// Every IPv4 interface that is up and has an address.
    func interfaces() throws(PlatformError) -> [NetworkInterface]

    /// The interface the default route goes out of — what a scan targets when the
    /// user names none.
    func primaryInterface() throws(PlatformError) -> NetworkInterface
}

/// One entry in the kernel's neighbour table.
///
/// Free layer-2 truth: the ARP cache knows the MAC of everything this machine has
/// recently talked to, at no probe cost, unprivileged, on both platforms. It is also
/// the control in the Local Network denial heuristic — a populated cache alongside a
/// silent sweep is the signature.
public struct NeighborEntry: Sendable, Hashable, Codable {
    /// The address.
    public var ip: IPv4Address
    /// The hardware address the kernel has for it.
    public var mac: MACAddress
    /// Whether the entry is complete. An incomplete entry is an ARP request that got
    /// no answer, which is evidence of absence rather than presence.
    public var isComplete: Bool
    /// Whether the entry is a static or permanent one rather than a learned lease.
    public var isPermanent: Bool

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(ip: IPv4Address, mac: MACAddress, isComplete: Bool = true, isPermanent: Bool = false) {
        self.ip = ip
        self.mac = mac
        self.isComplete = isComplete
        self.isPermanent = isPermanent
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ip
        case mac
        case isComplete = "is_complete"
        case isPermanent = "is_permanent"
    }
}

/// Reads the kernel's neighbour table.
///
/// Darwin: `sysctl(CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO)`, whose
/// reply contains variable-length `sockaddr_dl` structures that must be parsed by byte
/// offset — see `WireDecodable` and the note there about alignment. Linux:
/// `/proc/net/arp` or netlink.
public protocol NeighborCache: Sendable {
    /// Every entry the kernel currently holds.
    func entries() async throws(PlatformError) -> [NeighborEntry]
}

/// One entry in the IPv6 neighbour cache — NDP's counterpart of an ARP entry.
public struct IPv6NeighborEntry: Sendable, Hashable {
    /// The neighbour's address, with the zone of the interface it was learned on.
    public var address: IPv6Address
    /// Its link-layer address.
    public var mac: MACAddress
    /// A permanent entry is one of this machine's own addresses, not a neighbour.
    public var isPermanent: Bool

    public init(address: IPv6Address, mac: MACAddress, isPermanent: Bool) {
        self.address = address
        self.mac = mac
        self.isPermanent = isPermanent
    }
}

/// The IPv6 neighbour cache. Read, never written; needs no privilege on any platform
/// this project targets.
public protocol IPv6NeighborCache: Sendable {
    func ipv6Entries() async throws(PlatformError) -> [IPv6NeighborEntry]
}

/// One ICMPv6 echo to the all-nodes group, and the unicast echo that lets the neighbour
/// cache learn a responder's hardware address. Unprivileged on macOS (D1).
///
/// A **complement** to the v4 sweep, not a replacement (Q2): on the network it was
/// measured on, one packet reached 6–7 of 10 hosts, and once a host the sweep never found.
/// Its value is that second kind of host, for the price of one packet.
public protocol IPv6MulticastEcho: Sendable {
    /// Sends one echo request to `ff02::1` on `interface` and collects who answers
    /// within `window`. Each responder once, with its zone.
    func solicitAllNodes(on interface: String, within window: Duration) async -> IPv6Solicitation

    /// One unicast echo. True if it answered. Sent only to a responder the cache has no
    /// hardware address for: the exchange makes the kernel resolve it, and without a MAC
    /// the responder cannot be joined to its v4 device.
    func echo(_ address: IPv6Address, on interface: String, within budget: Duration) async -> Bool
}

/// What one all-nodes solicitation found.
public struct IPv6Solicitation: Sendable, Hashable {
    /// Every address that answered, once each.
    public var responders: [IPv6Address]
    /// Packets sent: 1, or 0 when the socket could not be opened.
    public var sent: Int
    /// Why nothing could be sent, when nothing was.
    public var failure: String?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(responders: [IPv6Address] = [], sent: Int = 0, failure: String? = nil) {
        self.responders = responders
        self.sent = sent
        self.failure = failure
    }
}

/// No IPv6 multicast: sends nothing, finds nothing. The default wherever there is no
/// engine for it, and in every fixture — so an artifact baseline is unchanged by it.
public struct NoIPv6MulticastEcho: IPv6MulticastEcho {
    public init() {}
    public func solicitAllNodes(on interface: String, within window: Duration) async -> IPv6Solicitation {
        IPv6Solicitation()
    }
    public func echo(_ address: IPv6Address, on interface: String, within budget: Duration) async -> Bool {
        false
    }
}

/// One sighting of one service instance on one host.
public struct ServiceSighting: Sendable, Hashable, Codable {
    /// The address it resolved to.
    public var ip: IPv4Address
    /// The service type — `_googlecast._tcp`.
    public var serviceType: String
    /// The instance name as advertised, after cleaning.
    public var instanceName: String
    /// The hostname from the resolve step, if there was one.
    public var hostname: String?
    /// The TXT record, parsed into key/value pairs.
    ///
    /// Model strings live under `am`, `model`, `rpMd`, `ty` or `device`, first
    /// non-empty winning. NEVER under `md`: on `_raop` that key holds the
    /// supported-metadata list — the literal string "0,1,2" — and reading it as a
    /// model silently fills the report with nonsense that looks plausible enough to
    /// survive review. This comment is the containment.
    public var txt: [String: String]
    /// Quality rank of the service type this came from. Lower is cleaner, and it
    /// becomes `NameCandidate.rank`.
    public var rank: Int

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        ip: IPv4Address,
        serviceType: String,
        instanceName: String,
        hostname: String? = nil,
        txt: [String: String] = [:],
        rank: Int = 0
    ) {
        self.ip = ip
        self.serviceType = serviceType
        self.instanceName = instanceName
        self.hostname = hostname
        self.txt = txt
        self.rank = rank
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ip
        case serviceType = "service_type"
        case instanceName = "instance_name"
        case hostname
        case txt
        case rank
    }
}

/// Browses for service instances.
///
/// The Darwin conformance is `dns_sd` — one shared connection with
/// `kDNSServiceFlagsShareConnection`, browse then resolve then `GetAddrInfo`, bridged
/// to an `AsyncStream` whose `onTermination` deallocates the ref and releases the
/// `Unmanaged` context box. That whole apparatus is invisible from here, which is the
/// point of the protocol existing.
public protocol ServiceBrowser: Sendable {
    /// The service types this browser looks for, in rank order.
    var browsedTypes: [String] { get }

    /// Sightings as they arrive, until the deadline.
    ///
    /// Never fails. A platform with no mDNS at all returns an empty stream, and the
    /// caller records a `Degradation` — that is what "a missing capability is a
    /// degradation, never a build failure" means in practice.
    func browse(deadline: Deadline) -> AsyncStream<ServiceSighting>
}

/// One SSDP responder's description of itself.
///
/// SSDP answers a different question from Bonjour and catches a different population:
/// televisions, printers, games consoles and NAS boxes routinely speak UPnP and ignore
/// Bonjour completely. On a network where every Apple device is already named by mDNS,
/// SSDP is what names the rest.
public struct SSDPSighting: Sendable, Hashable, Codable {
    /// The address the response came from. Note that this is the source address of the
    /// datagram, not anything the device claimed — a device cannot lie about it without
    /// also not receiving the reply.
    public var ip: IPv4Address
    /// `<friendlyName>` from the description document, which is the name the owner set
    /// or the manufacturer's default.
    public var friendlyName: String?
    /// `<modelName>` from the same document.
    public var modelName: String?
    /// The `SERVER:` header from the M-SEARCH response — an OS and UPnP-stack string,
    /// kept because it is the only identifying thing available when the description
    /// document could not be fetched.
    public var server: String?
    /// The `LOCATION:` URL the description was fetched from, or would have been.
    public var location: String?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        ip: IPv4Address,
        friendlyName: String? = nil,
        modelName: String? = nil,
        server: String? = nil,
        location: String? = nil
    ) {
        self.ip = ip
        self.friendlyName = friendlyName
        self.modelName = modelName
        self.server = server
        self.location = location
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ip
        case friendlyName = "friendly_name"
        case modelName = "model_name"
        case server
        case location
    }
}

/// Discovers UPnP devices by multicast search.
///
/// The Darwin conformance sends an M-SEARCH to 239.255.255.250:1900 and then fetches
/// each responder's description document. Two things about it are not optional and both
/// are invisible from here: the socket binds to the SELECTED INTERFACE'S ADDRESS and
/// sets `IP_MULTICAST_IF`, because a multicast send from `INADDR_ANY` on a multi-homed
/// machine leaves through whichever interface the kernel's multicast route happens to
/// name — routinely a VPN tunnel, which means the search describes somebody else's
/// network. And the budget splits internally, roughly 60% listening and 40% fetching,
/// because a responder that is never asked for its description contributes only a
/// `SERVER:` string.
public protocol SSDPDiscovery: Sendable {
    /// Responders as they are described, until the deadline.
    ///
    /// Never fails. A platform with no multicast returns an empty stream and the caller
    /// records a `Degradation`.
    func search(from interface: NetworkInterface, deadline: Deadline) -> AsyncStream<SSDPSighting>
}

/// One NBSTAT node-status reply.
public struct NetBIOSSighting: Sendable, Hashable, Codable {
    /// The address that answered.
    public var ip: IPv4Address
    /// The workstation name — the unique entry with suffix `0x00`.
    public var name: String
    /// The workgroup or domain — the group entry with suffix `0x00`. Kept because it is
    /// occasionally the only thing that distinguishes two otherwise identical hosts,
    /// and never used as a name: `WORKGROUP` identifies nothing.
    public var workgroup: String?
    /// The adapter's hardware address, which an NBSTAT reply carries in its statistics
    /// block. Free layer-2 truth from a host the ARP cache may not have.
    public var mac: MACAddress?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(ip: IPv4Address, name: String, workgroup: String? = nil, mac: MACAddress? = nil) {
        self.ip = ip
        self.name = name
        self.workgroup = workgroup
        self.mac = mac
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case ip
        case name
        case workgroup
        case mac
    }
}

/// Asks specific hosts for their NetBIOS node status.
///
/// The weakest of the three name sources and the cheapest to skip, which is why it
/// takes an address list rather than a network: it is asked only about hosts that mDNS
/// and SSDP both failed to name. The whole protocol is one 50-byte datagram to UDP/137
/// and one reply, so it needs no library and no session.
public protocol NetBIOSQuerying: Sendable {
    /// Node-status replies from the addresses given, until the deadline.
    ///
    /// Never fails. Hosts that do not answer are simply absent, which is the normal
    /// case for anything that is not Windows or Samba.
    func nodeStatus(
        of addresses: [IPv4Address], from interface: NetworkInterface, deadline: Deadline
    ) -> AsyncStream<NetBIOSSighting>
}

/// Resolves PTR names.
///
/// Deliberately not `getnameinfo`. That call and `gethostbyaddr` have no cancellation
/// and no timeout: a task blocked in one ignores its deadline completely, and since
/// the cooperative pool is sized to the core count, a handful of them deadlocks the
/// scanner rather than slowing it. The Darwin conformance uses
/// `DNSServiceQueryRecord`, which is fd-driven and cancellable by
/// `DNSServiceRefDeallocate`.
public protocol ReverseNameResolver: Sendable {
    /// The PTR name for an address, or nil if there is none or the budget expired.
    /// Silence and absence are the same answer here, and neither is an error.
    func reverseName(for address: IPv4Address, deadline: Deadline) async -> String?
}

/// Whether this process has the privileges the layer-2 engines need.
///
/// The mechanism — run under `sudo`, open BPF at startup, then `setuid` irrevocably,
/// keeping the descriptors that survive the drop — lives in the platform target. Core
/// only needs to know whether the privileged engines can be constructed.
public protocol PrivilegeBroker: Sendable {
    /// Whether privileged operations are available.
    var isPrivileged: Bool { get }
}

/// Reads and raises process resource limits.
public protocol ResourceLimits: Sendable {
    /// Raises the descriptor soft limit toward the hard limit and returns what was
    /// actually granted.
    ///
    /// Returns the granted value rather than a success flag because the value is what
    /// the caller needs: concurrency is derived from it through
    /// `ConcurrencyBudget.fromDescriptorLimit(_:)`, never from a constant.
    func raiseDescriptorLimit() -> Int
}

/// Owns a file descriptor, with exactly one owner, enforced by the compiler.
///
/// A descriptor is a resource with one owner and `~Copyable` makes that a type-level
/// fact: double-close and use-after-close become compile errors rather than production
/// mysteries. That matters disproportionately here — when the in-flight count is in the
/// thousands, a leaked descriptor exhausts the process limit and the scan fails, where
/// a leaked allocation would merely waste memory.
///
/// The close syscall is supplied by a static-only `DescriptorPolicy` rather than by a
/// stored closure. A stored closure would mean a heap allocation per descriptor, which
/// across 25,000 probes is 25,000 allocations to avoid one `import Darwin` — and this
/// type has to compile on Linux, so the syscall cannot be named here at all.
public protocol DescriptorPolicy: Sendable {
    /// Closes a raw descriptor. The platform target supplies `Darwin.close` or
    /// `Glibc.close`.
    static func close(_ raw: Int32)
}

/// A uniquely owned file descriptor.
public struct OwnedDescriptor<Policy: DescriptorPolicy>: ~Copyable {
    /// The raw descriptor. Borrow it for a syscall; do not store it anywhere, since
    /// a stored copy is exactly the aliasing this type exists to prevent.
    public let raw: Int32

    /// Takes ownership of a descriptor the caller has just opened.
    public init(raw: Int32) {
        self.raw = raw
    }

    /// Closes it now.
    ///
    /// `consuming`, so the value is gone afterwards and a second call does not
    /// compile. `discard self` suppresses the deinit that would otherwise close it a
    /// second time — a double close is not harmless: between the two, another thread
    /// can open a socket and receive the same number, and the second close then shuts
    /// down an unrelated connection.
    public consuming func close() {
        Policy.close(raw)
        discard self
    }

    deinit {
        Policy.close(raw)
    }
}
