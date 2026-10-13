// BannerProbe.swift — asking an open port what it is, and believing only the answer.
//
// `EngineCapabilities.bannerProbe` was declared with nothing constructing it, and
// `ServiceIdentity` was built in the tests and nowhere else — so every open port in
// every artifact this tool has ever produced carried `service: null`. `--deep` answered
// "something is listening on 8080" and stopped there, which is the least useful true
// thing it could say.
//
// ── The rule this file exists to hold ───────────────────────────────────────────
//
// **A service is never inferred from a port number.** Port 8080 is a web server on most
// networks and a Sonos device, a print spooler or somebody's dev build on plenty of
// others, and a scanner that prints "http" because the number is 8080 has told the user
// something it does not know. `ServiceIdentity` exists precisely to carry the evidence
// alongside the claim, and `ServiceEvidence` says which kind it was.
//
// So the port number decides only **which probe to try**, never what to report. A port
// that answers nothing gets no identity, and that is the correct outcome rather than a
// gap to be filled with a guess.
//
// ── Three ways a service identifies itself, in the order they are cheap ─────────
//
//   1. It speaks first. SSH, SMTP, FTP and POP3 all send a banner on connect, so the
//      probe is to connect and listen. No bytes are sent at all, which also means
//      nothing is written to a service that might log it.
//   2. It answers a request. HTTP says nothing until asked, so the probe sends a
//      minimal `HEAD` and reads the `Server:` header back.
//   3. It presents a certificate. TLS names itself in the subject and the SANs before
//      any application data is exchanged, and that is often the most specific evidence
//      on the whole network — a printer's self-signed certificate carries its model.
//
// ── Why this is not the connect scan ────────────────────────────────────────────
//
// It reuses the connect machinery and it is a different question. The scan asks whether
// a port is open; this asks what is on it, on the ports the scan already found open. It
// is also the one thing the half-open scan cannot do — a banner needs a completed
// handshake, which is exactly what half-open declines to perform — so under root the
// two run in sequence: SYN decides the verdicts, and this connects to the winners.
#if canImport(Darwin)

import Darwin
import Foundation
import Network
import ZhenCore
import Security

/// Identifies what is listening on a port, from what it says.
public struct BannerProbe: Sendable {
    /// How long one port gets, end to end.
    ///
    /// A ceiling rather than a wait. Most services answer in a millisecond on a LAN;
    /// this bounds the ones that never will.
    public var budget: Duration
    /// How many bytes of a banner to keep.
    ///
    /// Enough for an SSH identification string and an HTTP status line with headers,
    /// and bounded because the far side chooses this number and a scanner that let it
    /// choose without limit would have a memory bug waiting on the network.
    public var maximumBytes: Int

    /// Creates the probe.
    public init(budget: Duration = .milliseconds(1200), maximumBytes: Int = 2048) {
        self.budget = budget
        self.maximumBytes = maximumBytes
    }

    /// Ports where TLS is worth trying before plaintext.
    ///
    /// A hint about which probe to run first, never about what to report. A port not in
    /// this set still gets the TLS probe if plaintext says nothing, because a service
    /// on a non-standard port is exactly the case a port-number table gets wrong.
    static let likelyTLS: Set<UInt16> = [443, 465, 636, 853, 993, 995, 8443, 9443, 8883]

    /// Asks one port what it is.
    ///
    /// - Returns: what the port said, or nil when it said nothing usable. Nil is a real
    ///   answer and the common one: plenty of services are silent until spoken to in a
    ///   protocol this probe does not speak, and reporting nothing is correct.
    public func identify(
        _ ip: ZhenCore.IPv4Address, port: UInt16, deadline: Deadline
    ) async -> ServiceIdentity? {
        let slice = min(budget, deadline.remaining)
        guard slice > .zero else { return nil }

        if Self.likelyTLS.contains(port) {
            if let tls = await tlsIdentity(ip, port: port, budget: slice) { return tls }
            return await plaintextIdentity(ip, port: port, budget: slice)
        }
        if let plain = await plaintextIdentity(ip, port: port, budget: slice) { return plain }
        // A service on a non-standard port that turned out to be TLS. Tried second
        // because the handshake costs more than a read that returns nothing.
        return await tlsIdentity(ip, port: port, budget: slice)
    }

    // MARK: - Plaintext

    /// Connects, listens, and asks only if listening produced nothing.
    ///
    /// Listening first is not only cheaper. A service that speaks first has told us what
    /// it is without being sent a single byte, which is the least intrusive probe
    /// available and the one least likely to appear in somebody's log as a request.
    private func plaintextIdentity(
        _ ip: ZhenCore.IPv4Address, port: UInt16, budget: Duration
    ) async -> ServiceIdentity? {
        guard let connection = await TCPStream.connect(to: ip, port: port, within: budget) else {
            return nil
        }
        defer { connection.close() }

        let greeting = await connection.read(upTo: maximumBytes, within: budget / 3)
        if let identity = Self.parseGreeting(greeting, port: port) { return identity }

        // Nothing volunteered. Ask the way a web server expects to be asked. HEAD
        // rather than GET so nothing downloads a body we would only discard, and
        // HTTP/1.0 so the far side closes rather than holding the connection open.
        let request = "HEAD / HTTP/1.0\r\nHost: \(ip)\r\nUser-Agent: zhen\r\n\r\n"
        guard connection.write(Array(request.utf8)) else { return nil }
        let response = await connection.read(upTo: maximumBytes, within: budget / 2)
        return Self.parseHTTP(response)
    }

    /// Reads a banner a service volunteered.
    ///
    /// Only protocols whose greeting is unambiguous are named. "Something sent bytes"
    /// is not an identification, and a scanner that reported the port's conventional
    /// name because *anything* arrived would be guessing with extra steps.
    static func parseGreeting(_ bytes: [UInt8], port: UInt16) -> ServiceIdentity? {
        guard !bytes.isEmpty else { return nil }
        let text = String(decoding: bytes, as: UTF8.self)
        let firstLine = text.split(separator: "\r\n", omittingEmptySubsequences: false)
            .first.map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !firstLine.isEmpty else { return nil }

        // RFC 4253: "SSH-protoversion-softwareversion SP comments CR LF". The software
        // version is the part worth having — "OpenSSH_9.6" names the product and the
        // version in one field.
        if firstLine.hasPrefix("SSH-") {
            let parts = firstLine.split(separator: "-", maxSplits: 2).map(String.init)
            let software = parts.count >= 3 ? parts[2].split(separator: " ").first.map(String.init) : nil
            let (product, version) = Self.splitProduct(software)
            return ServiceIdentity(
                name: "ssh", product: product, version: version,
                banner: firstLine, evidence: .banner
            )
        }
        // RFC 5321: a 220 greeting, with the product usually after the hostname.
        if firstLine.hasPrefix("220 ") || firstLine.hasPrefix("220-") {
            let name = port == 21 ? "ftp" : "smtp"
            return ServiceIdentity(name: name, banner: firstLine, evidence: .banner)
        }
        if firstLine.hasPrefix("+OK") {
            return ServiceIdentity(name: "pop3", banner: firstLine, evidence: .banner)
        }
        if firstLine.hasPrefix("* OK") {
            return ServiceIdentity(name: "imap", banner: firstLine, evidence: .banner)
        }
        if firstLine.hasPrefix("RFB ") {
            return ServiceIdentity(name: "vnc", banner: firstLine, evidence: .banner)
        }
        // Something answered and we cannot say what it is. Reported as an unnamed
        // service carrying its own evidence rather than discarded: "this port speaks
        // something" is a real observation, and the banner is there for a person to
        // read when the parse was not good enough.
        return ServiceIdentity(name: "unknown", banner: firstLine, evidence: .banner)
    }

    /// Reads an HTTP response, whose `Server:` header is the identification.
    static func parseHTTP(_ bytes: [UInt8]) -> ServiceIdentity? {
        guard !bytes.isEmpty else { return nil }
        let text = String(decoding: bytes, as: UTF8.self)
        guard text.hasPrefix("HTTP/") else { return nil }

        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false).map(String.init)
        let status = lines.first?.trimmingCharacters(in: .whitespacesAndNewlines)
        let server = lines.first { $0.lowercased().hasPrefix("server:") }?
            .dropFirst("server:".count)
            .trimmingCharacters(in: .whitespaces)

        let (product, version) = Self.splitProduct(server)
        return ServiceIdentity(
            name: "http", product: product, version: version,
            // The status line when there is no Server header, because a server that
            // declines to name itself has still proved it speaks HTTP.
            banner: server ?? status,
            evidence: .banner
        )
    }

    /// Splits "OpenSSH_9.6" or "nginx/1.24.0" into a product and a version.
    ///
    /// Conservative: anything that does not look like `name<separator>version` is kept
    /// whole as the product, because inventing a split is worse than not splitting.
    static func splitProduct(_ raw: String?) -> (String?, String?) {
        guard let raw = raw?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
            return (nil, nil)
        }
        for separator in ["/", "_"] where raw.contains(separator) {
            let parts = raw.split(separator: Character(separator), maxSplits: 1).map(String.init)
            if parts.count == 2, parts[1].first?.isNumber == true {
                return (parts[0], parts[1])
            }
        }
        return (raw, nil)
    }

    // MARK: - TLS

    /// Completes a TLS handshake and reads the certificate's subject.
    ///
    /// `NWConnection` rather than the socket path, because a TLS handshake by hand is a
    /// protocol implementation and this is a scanner. The verify block is where the
    /// certificate is read; it **always accepts**, and that is deliberate — the question
    /// is what this endpoint calls itself, not whether a chain validates. A self-signed
    /// certificate on a printer is exactly the evidence worth having, and rejecting it
    /// would discard the most specific identification on most home networks.
    private func tlsIdentity(
        _ ip: ZhenCore.IPv4Address, port: UInt16, budget: Duration
    ) async -> ServiceIdentity? {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let host = NWEndpoint.Host.ipv4(ZhenCore.IPv4Address.networkAddress(ip))
        let subject = CertificateBox()

        let options = NWProtocolTLS.Options()
        // SAFETY: the verify block is a C-level callback taking retained security
        // objects. It runs on the queue named here, records the leaf certificate's
        // subject and then unconditionally completes with `true`.
        unsafe sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, trust, complete in
                let certificateTrust = unsafe sec_trust_copy_ref(trust).takeRetainedValue()
                if let leaf = unsafe SecTrustGetCertificateAtIndex(certificateTrust, 0),
                   let summary = unsafe SecCertificateCopySubjectSummary(leaf) as String? {
                    subject.record(summary)
                }
                complete(true)
            },
            TLSQueue.shared
        )
        // TLS 1.0 as the floor. A printer or a camera with an ancient stack is precisely
        // the device worth identifying, and refusing to speak to it would lose exactly
        // the hosts this is most useful on.
        unsafe sec_protocol_options_set_min_tls_protocol_version(
            options.securityProtocolOptions, .TLSv10
        )

        let connection = NWConnection(
            host: host, port: endpointPort,
            using: NWParameters(tls: options, tcp: NWProtocolTCP.Options())
        )
        let settled = await TLSHandshake.run(connection, within: budget)
        connection.cancel()
        guard settled else { return nil }

        guard let name = subject.value else {
            // The handshake completed and no subject could be read. Still an
            // identification: this port speaks TLS, which the port number alone could
            // not have established.
            return ServiceIdentity(name: "tls", evidence: .protocolHandshake)
        }
        return ServiceIdentity(
            name: port == 443 || port == 8443 ? "https" : "tls",
            tlsSubject: name,
            evidence: .tlsCertificate
        )
    }
}

/// The queue TLS verify blocks are delivered on.
enum TLSQueue {
    static let shared = DispatchQueue(label: "com.jctec.zhen.tls", qos: .userInitiated)
}

/// Holds a certificate subject across the verify block's callback boundary.
final class CertificateBox: @unchecked Sendable {
    private let lock = NSLock()
    private var subject: String?
    func record(_ value: String) { lock.withLock { if subject == nil { subject = value } } }
    var value: String? { lock.withLock { subject } }
}

/// Runs an `NWConnection` to its first terminal state, or to a deadline.
enum TLSHandshake {
    /// - Returns: true when the connection reached `.ready`, meaning the handshake
    ///   completed and the verify block has already run.
    static func run(_ connection: NWConnection, within budget: Duration) async -> Bool {
        let claim = ResumeOnce()
        return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            let finish: @Sendable (Bool) -> Void = { ready in
                guard claim.claim() else { return }
                continuation.resume(returning: ready)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                // `.waiting` is a connection the system will keep retrying — a filtered
                // port looks exactly like this and would otherwise sit until the budget
                // expires, which it is allowed to do, but there is nothing to wait for.
                case .waiting: finish(false)
                default: break
                }
            }
            connection.start(queue: TLSQueue.shared)
            TLSQueue.shared.asyncAfter(
                deadline: .now() + .nanoseconds(budget.wholeNanoseconds)
            ) { finish(false) }
        }
    }
}

extension ZhenCore.IPv4Address {
    /// Bridges to Network.framework's address type.
    ///
    /// Both modules declare an `IPv4Address` and this file imports both, so every
    /// mention in it is qualified. Going through the textual form rather than the raw
    /// integer because Network's initialiser is the one that knows its own byte order,
    /// and a scanner that guessed it would probe the address backwards.
    static func networkAddress(_ address: ZhenCore.IPv4Address) -> Network.IPv4Address {
        Network.IPv4Address("\(address)") ?? .loopback
    }
}

#endif
