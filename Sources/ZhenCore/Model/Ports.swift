// Ports.swift — what one port on one host looked like.
//
// The three-valued port state is the load-bearing idea in this file and it is worth
// being blunt about why. A naive scanner reports open or not-open. That collapse
// throws away the only signal that separates a live host behind a firewall from an
// address with nothing on it:
//
//   .open      something answered and accepted.
//   .closed    a RST came back. Positive information: a host is *there* and told us
//              so. Strictly more informative than silence.
//   .filtered  nothing came back. Indistinguishable, on its own, from a dead
//              address — which is exactly why it must not be conflated with .closed.
//
// A host whose ports are all .closed is definitely up. A host whose ports are all
// .filtered may not exist. Merging those two states makes that question unanswerable
// from the artifact, and the answer is what the user wants.

/// Transport protocol a port observation was made over.
public enum TransportProtocol: String, Sendable, Hashable, CaseIterable, Codable {
    case tcp = "tcp"
    case udp = "udp"
}

/// What a port probe learned. See the file header — these three are not two.
public enum PortState: String, Sendable, Hashable, CaseIterable, Codable {
    /// The connection was accepted, or the service answered.
    case open = "open"
    /// Actively refused — a TCP RST or an ICMP port-unreachable. A positive result:
    /// the host exists and is reachable, and it has nothing listening here.
    case closed = "closed"
    /// Silence within the budget. Carries no information about whether the host
    /// exists; it says only that nothing came back in time.
    case filtered = "filtered"
    /// Silence from a UDP port, which means open OR filtered and cannot be resolved.
    ///
    /// **The fourth state exists because UDP cannot be made to fit the other three.**
    /// On TCP, silence is `filtered`: a listening port completes a handshake whether
    /// it wants to or not, so nothing coming back means nothing got there. On UDP
    /// there is no handshake. An open port usually answers only if the payload meant
    /// something to it, and a closed one answers with an ICMP port-unreachable that
    /// firewalls routinely drop. So silence is genuinely ambiguous, and the two
    /// honest-looking alternatives are both wrong:
    ///
    /// - Reporting it `filtered` under-reports, which is the failure this file's
    ///   header warns about — it would hide every open UDP port that did not feel
    ///   like answering.
    /// - Reporting it `open` over-reports, and an over-reported open port is how a
    ///   scanner earns a reputation for crying wolf.
    ///
    /// So it is named. A reader who wants a boolean must decide which way to round it
    /// and can see that they are deciding. **This is what bumped the artifact to
    /// schema 2**: a schema-1 consumer decoding `open_filtered` fails outright, which
    /// is the correct outcome and the reason the version is checked.
    case openFiltered = "open_filtered"

    /// Whether this observation proves the host is reachable at all.
    ///
    /// True for `.open` and `.closed`, false for `.filtered`. This is the property
    /// discovery actually needs from a port scan, and having it here rather than at
    /// each call site is what stops someone reintroducing the collapse.
    public var provesHostAlive: Bool {
        switch self {
        case .open, .closed: true
        // Silence proves nothing on either transport. `openFiltered` is the ambiguity
        // itself, so it cannot be evidence of reachability — which is the whole reason
        // it is not folded into `.open`.
        case .filtered, .openFiltered: false
        }
    }
}

/// How a service was identified. There is deliberately no case for "the port number
/// said so".
///
/// A port-number table is a guess dressed as a fact: 8080 is a proxy, or a dev
/// server, or a printer, or a Plex box. This project claims a service only when
/// something on the wire said what it was, and making the alternative
/// unrepresentable is cheaper than a code review that has to catch it every time.
public enum ServiceEvidence: String, Sendable, Hashable, CaseIterable, Codable {
    /// A banner the service sent unprompted or in response to a probe — an SSH
    /// version string, an HTTP `Server:` header.
    case banner = "banner"
    /// A TLS certificate's subject or SAN.
    case tlsCertificate = "tls_certificate"
    /// A protocol handshake that only one service could have completed.
    case protocolHandshake = "protocol_handshake"
}

/// A service identified from evidence on the wire.
public struct ServiceIdentity: Sendable, Hashable, Codable {
    /// Short service name, lowercased — "ssh", "http", "smb".
    public var name: String
    /// Product, where the evidence named one — "OpenSSH", "nginx".
    public var product: String?
    /// Version, where the evidence carried one.
    public var version: String?
    /// The raw banner text, truncated by the probe. Kept because it is the evidence,
    /// and a user who disagrees with our parse should be able to see what we parsed.
    public var banner: String?
    /// Certificate subject or SAN, for a TLS service.
    public var tlsSubject: String?
    /// What justified this identification.
    public var evidence: ServiceEvidence

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        name: String,
        product: String? = nil,
        version: String? = nil,
        banner: String? = nil,
        tlsSubject: String? = nil,
        evidence: ServiceEvidence
    ) {
        self.name = name
        self.product = product
        self.version = version
        self.banner = banner
        self.tlsSubject = tlsSubject
        self.evidence = evidence
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case name
        case product
        case version
        case banner
        case tlsSubject = "tls_subject"
        case evidence
    }
}

/// One port, on one host, at one moment.
public struct PortObservation: Sendable, Hashable, Codable {
    /// The port number.
    public var port: UInt16
    /// Which transport it was probed over.
    public var proto: TransportProtocol
    /// Open, closed or filtered — never collapsed to a boolean.
    public var state: PortState
    /// The service, if something on the wire identified one. Absent means *not
    /// observed*: either nothing answered, or what answered said nothing useful.
    /// It never means "we assumed from the port number".
    public var service: ServiceIdentity?
    /// Round trip for this specific probe, where one was measured. A per-port RTT
    /// is what shows a host that is fast on 443 and slow on 22.
    public var rtt: RTTSample?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        port: UInt16,
        proto: TransportProtocol = .tcp,
        state: PortState,
        service: ServiceIdentity? = nil,
        rtt: RTTSample? = nil
    ) {
        self.port = port
        self.proto = proto
        self.state = state
        self.service = service
        self.rtt = rtt
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case port
        case proto
        case state
        case service
        case rtt
    }
}
