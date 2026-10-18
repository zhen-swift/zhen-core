// NetBIOSProbe.swift — the last resort, and the cheapest one.
//
// NBSTAT is the whole protocol: one 50-byte datagram to UDP/137, one reply listing the
// names the adapter has registered. No library, no session, no handshake. That is why
// it is worth having at all — it costs one packet per host and it names the population
// the other two sources cannot see: Windows machines with Bonjour not installed, NAS
// boxes running Samba, and anything on the network old enough that its vendor never
// implemented either mDNS or UPnP.
//
// It is also the WEAKEST source, and it is asked LAST and about the FEWEST hosts. A
// NetBIOS name is uppercase, fifteen characters, and frequently something like
// `DESKTOP-7Q3M8X2` that a manufacturer generated rather than a person chose — which is
// exactly why `NameSource.netbios` is not self-sufficient in the cascade and why this
// probe is only pointed at hosts that mDNS and SSDP both failed to name. Asking every
// host would spend packets to add a worse name to devices that already have a good one.
//
// One socket for every target, like the ICMP sweep and for the same reason: the reply
// carries its source address, so there is nothing to demultiplex per host, and one
// descriptor means the descriptor limit is irrelevant to this stage.
#if canImport(Darwin)

import Darwin
import Dispatch
import Foundation
import ZhenCore

/// Asks specific hosts for their NetBIOS node status.
public struct DarwinNetBIOSQuery: NetBIOSQuerying {
    /// Where setup failures are recorded, shared with the other name sources.
    public var failures: DegradationLog
    /// Raised when the query could not run at all, so the denial heuristic knows this
    /// source's silence is already explained.
    public var failed: FailureFlag

    /// How long to wait between the two query rounds.
    ///
    /// Sized for a LAN round trip with room for an ARP resolution in front of it, not
    /// for a network path.
    public static let roundGap = Duration.milliseconds(250)

    /// How long to keep listening after the last query goes out.
    ///
    /// One wait covering every host simultaneously, the same shape as the sweep's tail:
    /// the hosts that will never answer cost nothing extra because they are waiting in
    /// parallel with the one that might.
    public static let tail = Duration.milliseconds(500)

    /// Creates the prober.
    public init(failures: DegradationLog = DegradationLog(), failed: FailureFlag = FailureFlag()) {
        self.failures = failures
        self.failed = failed
    }

    /// Node-status replies, until the deadline.
    public func nodeStatus(
        of addresses: [IPv4Address], from interface: NetworkInterface, deadline: Deadline
    ) -> AsyncStream<NetBIOSSighting> {
        let (stream, continuation) = AsyncStream<NetBIOSSighting>.makeStream(
            bufferingPolicy: .bufferingNewest(512)
        )
        guard !addresses.isEmpty else {
            continuation.finish()
            return stream
        }
        let log = failures
        let failureFlag = failed

        let work = Task {
            let socket: UDPProbe
            do {
                // Bound to the interface on an ephemeral port, not 137: binding the well-known
                // port would collide with anything already running a NetBIOS name service —
                // Samba, a Windows VM's bridged adapter — and a node-status reply is unicast
                // back to the source port.
                socket = try UDPProbe(
                    interface: interface,
                    queue: DispatchQueue(label: "com.jctec.zhen.netbios", qos: .userInitiated)
                )
            } catch {
                failureFlag.raise()
                log.record(Degradation(
                    stage: .naming,
                    reason: """
                        A UDP socket for NetBIOS could not be opened on \(interface.name) \
                        (\(error)), so NetBIOS names cannot be read this scan. Windows and Samba \
                        hosts that publish no Bonjour or UPnP name may appear unnamed.
                        """,
                    recoverable: true
                ))
                continuation.finish()
                return
            }

            // Who has answered, so the probe can stop when there is nobody left to hear
            // from. Shared between the reader and the send loop, hence the lock.
            let answered = AnsweredSet()

            // ── One transaction ID per address, decided before anything goes out ──
            //
            // NBSTAT has no authentication, no sequence number beyond this, and no
            // handshake — so without matching, ANY datagram arriving on port 137 is
            // accepted as an answer from whatever address it claims. That is not a
            // theoretical problem on a segment this tool is pointed at: a host can send
            // one forged reply and attach a name of its choosing to a real device, and
            // because the sighting also marks that address answered, the genuine reply
            // is then discarded and the lie is the only version anyone sees.
            //
            // Two checks, the same pair the ICMP path already makes: the datagram must
            // come from an address we actually asked, and it must carry the transaction
            // ID we asked it with. The ID is per address and stable across both rounds,
            // so a retransmission is still matchable.
            var assigning: [IPv4Address: UInt16] = [:]
            for address in addresses {
                assigning[address] = UInt16.random(in: 1...UInt16.max)
            }
            let transactions = assigning

            let replies = socket.events()
            let reader = Task {
                for await event in replies {
                    guard case .datagram(let datagram) = event else { continue }
                    // Not an address this scan asked about. Nothing it says is an answer.
                    guard let source = datagram.source.v4,
                          let expected = transactions[source] else { continue }
                    guard let sighting = NBSTAT.decode(
                        datagram.payload[datagram.payload.indices].span, from: source, expecting: expected
                    ) else { continue }
                    answered.insert(sighting.ip)
                    continuation.yield(sighting)
                }
            }

            // ── The budget is a CEILING, not a wait ──────────────────────────────
            //
            // NBSTAT is one datagram out and one back on the same segment: a LAN round
            // trip, which is under a millisecond wired and a few milliseconds over
            // Wi-Fi. Sitting on the full stage slice waiting for it is precisely the
            // fixed-interval mistake this project rejects in the ICMP sweep — and it was
            // measurable, adding about a second and a half of wall clock to every scan
            // of a network with no NetBIOS host on it, which is most networks.
            //
            // So: two rounds spaced by a short gap, then a short tail, then stop —
            // and stop the instant every host asked has answered.
            for round in 0..<2 {
                guard !Task.isCancelled, !deadline.isExpired else { break }
                for address in addresses where !answered.contains(address) {
                    guard !Task.isCancelled, !deadline.isExpired else { break }
                    guard let transaction = transactions[address] else { continue }
                    socket.send(NBSTAT.query(transaction: transaction), to: address, port: NBSTAT.port)
                }
                guard round == 0, !answered.covers(addresses) else { break }
                // A gap before asking again, so a reply to the first round is not
                // mistaken for silence — and short, because the thing being waited for
                // is one LAN round trip.
                try? await Task.sleep(for: min(deadline.remaining, Self.roundGap))
            }

            // One tail wait, covering every host at once, ended early by everybody
            // answering. The remaining budget bounds it; it does not define it.
            let tailEnd = MonotonicInstant.now.advanced(by: Self.tail)
            while !Task.isCancelled, !deadline.isExpired, MonotonicInstant.now < tailEnd {
                if answered.covers(addresses) { break }
                try? await Task.sleep(for: .milliseconds(20))
            }

            // Stop the socket FIRST, then wait for the reader to finish on its own.
            //
            // The other way round — which this did — cancels the reader while datagrams
            // are still sitting in the stream's buffer, and every one of them is thrown
            // away. Those are replies that arrived inside the budget, from hosts that
            // answered, discarded at the last moment for no reason. `stop()` cancels the
            // read source, whose cancel handler finishes the datagram stream, so the
            // reader's `for await` ends by itself with everything drained. SSDP already
            // does it this way; this is the same fix, and now the two agree.
            socket.stop()
            await reader.value
            continuation.finish()
        }

        continuation.onTermination = { _ in work.cancel() }
        return stream
    }
}

/// The NBSTAT wire format: one query shape and one reply shape.
///
/// Kept as pure functions over bytes so the decoder can be tested against a captured
/// reply rather than against a live Windows machine — which is the only way this parser
/// gets exercised at all on a network that may not have one.
enum NBSTAT {
    /// The NetBIOS name service port.
    static let port: UInt16 = 137
    /// Query type: node status.
    static let typeNBSTAT: UInt16 = 0x0021
    /// Query class: internet.
    static let classIN: UInt16 = 0x0001
    /// A first-level-encoded NetBIOS name is 32 bytes plus its length byte and
    /// terminator.
    static let encodedNameLength = 32

    /// Builds the node-status query.
    ///
    /// The name asked about is the wildcard `*`: sixteen bytes, an asterisk followed by
    /// fifteen nulls, first-level encoded. "First-level encoding" is NetBIOS's own
    /// scheme and is the one thing about this protocol that surprises people — each
    /// byte is split into two nibbles and each nibble is added to `'A'`, so the sixteen
    /// bytes become thirty-two letters and `*` becomes `CK` followed by thirty `A`s.
    static func query(transaction: UInt16 = UInt16.random(in: 1...UInt16.max)) -> [UInt8] {
        var packet: [UInt8] = []
        packet.reserveCapacity(50)
        packet.append(contentsOf: bigEndian(transaction))
        packet.append(contentsOf: bigEndian(UInt16(0x0000)))   // flags: a plain query
        packet.append(contentsOf: bigEndian(UInt16(1)))        // qdcount
        packet.append(contentsOf: bigEndian(UInt16(0)))        // ancount
        packet.append(contentsOf: bigEndian(UInt16(0)))        // nscount
        packet.append(contentsOf: bigEndian(UInt16(0)))        // arcount
        packet.append(UInt8(encodedNameLength))
        packet.append(contentsOf: encode(name: "*"))
        packet.append(0x00)                                    // root label
        packet.append(contentsOf: bigEndian(typeNBSTAT))
        packet.append(contentsOf: bigEndian(classIN))
        return packet
    }

    /// First-level encodes a NetBIOS name: pad to 16 bytes, split each into nibbles,
    /// add `'A'`.
    static func encode(name: String) -> [UInt8] {
        var raw = Array(name.utf8.prefix(16))
        // The wildcard pads with NULs; an ordinary name pads with spaces. Only the
        // wildcard is ever sent from here, and it is the one case where the difference
        // matters — a space-padded `*` asks about a name no host has registered.
        raw.append(contentsOf: [UInt8](repeating: 0x00, count: 16 - raw.count))
        var encoded: [UInt8] = []
        encoded.reserveCapacity(32)
        for byte in raw {
            encoded.append(0x41 + (byte >> 4))
            encoded.append(0x41 + (byte & 0x0F))
        }
        return encoded
    }

    /// Decodes a node-status reply.
    ///
    /// Returns nil for anything that is not a well-formed NBSTAT answer, carrying the
    /// transaction ID we asked with, and holding a usable workstation name. Silence, a
    /// malformed reply and an unmatched one are the same answer here: this host is not
    /// named by NetBIOS.
    ///
    /// - Parameter transaction: the ID sent to this address. REQUIRED, and not
    ///   defaultable — a convenience overload that skipped the check would be an
    ///   invitation to accept forged replies, which is the defect this parameter exists
    ///   to close. Sixteen bits is all the protocol offers, so this is not a
    ///   cryptographic guarantee; paired with the source-address check it is the same
    ///   strength as the ICMP path's sequence-and-source matching, and no more.
    static func decode(
        _ bytes: Span<UInt8>, from source: IPv4Address, expecting transaction: UInt16
    ) -> NetBIOSSighting? {
        // Header (12) + the echoed question name (1 + 32 + 1) + type (2) + class (2)
        // + ttl (4) + rdlength (2) + name count (1).
        let namesOffset = 12 + 1 + encodedNameLength + 1 + 2 + 2 + 4 + 2
        guard bytes.count > namesOffset else { return nil }
        // The transaction ID, first, before anything in this datagram is believed.
        guard UInt16(bytes[0]) << 8 | UInt16(bytes[1]) == transaction else { return nil }
        // Response bit set and no error in the low nibble of the flags. A reply with a
        // non-zero rcode is a host declining to answer, not a host with no name.
        let flags = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        guard flags & 0x8000 != 0, flags & 0x000F == 0 else { return nil }
        // At least one answer, and it must be an NBSTAT answer rather than something
        // else that happened to arrive on port 137.
        let answerType = UInt16(bytes[12 + 1 + encodedNameLength + 1]) << 8
            | UInt16(bytes[12 + 1 + encodedNameLength + 2])
        guard answerType == typeNBSTAT else { return nil }

        let count = Int(bytes[namesOffset])
        guard count > 0 else { return nil }
        var offset = namesOffset + 1
        var workstation: String?
        var workgroup: String?

        for _ in 0..<count {
            // 15 bytes of name, 1 byte of suffix, 2 bytes of flags.
            guard offset + 18 <= bytes.count else { break }
            var text = ""
            for index in 0..<15 {
                let byte = bytes[offset + index]
                // Printable ASCII only. The padding is spaces, and a control byte in a
                // name means the reply is not what it claims to be.
                guard byte >= 0x20, byte < 0x7F else { break }
                text.append(Character(UnicodeScalar(byte)))
            }
            let suffix = bytes[offset + 15]
            let entryFlags = UInt16(bytes[offset + 16]) << 8 | UInt16(bytes[offset + 17])
            // Bit 15 of the flags marks a GROUP name. The distinction is the whole
            // reason both fields exist: suffix 0x00 on a unique name is the machine,
            // suffix 0x00 on a group name is the workgroup or domain. Confusing them
            // names every machine in an office `WORKGROUP`.
            let isGroup = entryFlags & 0x8000 != 0
            let name = text.trimmed
            if suffix == 0x00, !name.isEmpty {
                if isGroup {
                    if workgroup == nil { workgroup = name }
                } else if workstation == nil {
                    workstation = name
                }
            }
            offset += 18
        }

        guard let workstation, !workstation.isEmpty else { return nil }
        return NetBIOSSighting(
            ip: source,
            name: workstation,
            workgroup: workgroup,
            mac: adapterAddress(bytes, at: offset)
        )
    }

    /// The adapter's hardware address, from the head of the statistics block.
    ///
    /// The six bytes immediately after the name list are the unit ID. Samba reports all
    /// zeroes there and a real Windows adapter reports its MAC, so an all-zero value is
    /// read as absent rather than as the address 00:00:00:00:00:00 — which would be a
    /// fabricated identifier, and identifiers are what the whole identity system joins
    /// on.
    static func adapterAddress(_ bytes: Span<UInt8>, at offset: Int) -> MACAddress? {
        guard offset + 6 <= bytes.count else { return nil }
        var raw: UInt64 = 0
        var allZero = true
        for index in 0..<6 {
            let byte = bytes[offset + index]
            if byte != 0 { allZero = false }
            raw = raw << 8 | UInt64(byte)
        }
        guard !allZero else { return nil }
        return MACAddress(raw: raw)
    }

    /// Big-endian bytes of a 16-bit field.
    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }
}

/// The addresses that have answered.
///
/// A lock over a set rather than an actor: it is written from the reader loop and read
/// from the send loop on every iteration, and an actor hop per check would cost more
/// than the wait it is trying to shorten.
final class AnsweredSet: @unchecked Sendable {
    private let lock = NSLock()
    private var addresses: Set<IPv4Address> = []

    /// Notes an answer.
    func insert(_ address: IPv4Address) { lock.withLock { _ = addresses.insert(address) } }

    /// Whether this address has answered.
    func contains(_ address: IPv4Address) -> Bool { lock.withLock { addresses.contains(address) } }

    /// Whether every address asked has answered, which is when there is nothing left to
    /// wait for.
    func covers(_ wanted: [IPv4Address]) -> Bool {
        lock.withLock { wanted.allSatisfy { addresses.contains($0) } }
    }
}

#endif
