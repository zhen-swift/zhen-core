// ICMPPacket.swift — building and reading echo messages.
//
// macOS grants an unprivileged process `SOCK_DGRAM`/`IPPROTO_ICMP`, which is the entire
// reason host discovery here needs no password. The kernel rewrites the identifier
// field on the way out — that is how it demultiplexes replies back to the right socket
// — but it does not compute the checksum. The application does, with core's
// `InternetChecksum`.
//
// Because the kernel owns the identifier, **replies cannot be matched on it.** The
// sequence number and the source address are what identify a reply, and every probe
// therefore carries a sequence unique within the sweep.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// An ICMP echo request, ready to hand to `sendto`.
enum ICMPEcho {
    /// ICMP type 8.
    static let requestType: UInt8 = 8
    /// ICMP type 0.
    static let replyType: UInt8 = 0
    /// Header length: type, code, checksum, identifier, sequence.
    static let headerLength = 8
    /// Magic at the head of every payload, so a reply whose data did not come from us
    /// is visibly wrong rather than silently accepted.
    static let magic: [UInt8] = Array("NSTY".utf8)
    /// Total payload length: magic, token, then filler.
    static let payloadLength = 16

    /// Builds an echo request.
    ///
    /// **The token, not the sequence number, is what identifies a probe.** The sequence
    /// field is sixteen bits, which wraps at 65,536 — comfortably inside a single /16
    /// sweep with retransmissions, at which point a wrapped sequence overwrites an
    /// earlier probe's entry and a live host that answers the older one is looked up
    /// against the newer one, fails the source check, and is reported absent. The
    /// token is 32 bits and rides in the payload, which RFC 792 requires an echo reply
    /// to return unchanged, so it survives the round trip and does not run out.
    ///
    /// The sequence number is still set, because a well-formed echo request has one and
    /// middleboxes look at it.
    ///
    /// - Parameters:
    ///   - sequence: the wire sequence field. Not used for matching.
    ///   - token: the identifier this probe is matched on.
    static func request(sequence: UInt16, token: UInt32) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: headerLength + payloadLength)
        packet[0] = requestType
        packet[1] = 0                       // code
        packet[2] = 0                       // checksum, computed below over the zeroed field
        packet[3] = 0
        packet[4] = 0                       // identifier, rewritten by the kernel
        packet[5] = 0
        packet[6] = UInt8(sequence >> 8)
        packet[7] = UInt8(sequence & 0xFF)
        for (index, byte) in magic.enumerated() { packet[headerLength + index] = byte }
        packet[headerLength + 4] = UInt8(truncatingIfNeeded: token >> 24)
        packet[headerLength + 5] = UInt8(truncatingIfNeeded: token >> 16)
        packet[headerLength + 6] = UInt8(truncatingIfNeeded: token >> 8)
        packet[headerLength + 7] = UInt8(truncatingIfNeeded: token)

        let checksum = InternetChecksum.compute(packet)
        packet[2] = UInt8(checksum >> 8)
        packet[3] = UInt8(checksum & 0xFF)
        return packet
    }
}

/// What one echo reply told us.
struct ICMPReply: Sendable, Hashable {
    /// Which host answered.
    var source: IPv4Address
    /// The sequence number it echoed back. Informational; matching uses `token`.
    var sequence: UInt16
    /// The probe token echoed back in the payload. This is what identifies which
    /// transmission the reply answers.
    var token: UInt32
    /// When the datagram was pulled off the socket.
    ///
    /// Stamped inside the readiness handler, before any actor hop, because a timestamp
    /// taken later measures our own scheduling as though it were the network's latency.
    /// The first version of this sweep timestamped after two hops and reported a LAN
    /// host answering in 0.4 ms as answering in 207 ms — which then fed the adaptive
    /// timeout and made the whole sweep slow, so the error compounded rather than just
    /// misreporting.
    var receivedAt: MonotonicInstant
    /// The IP TTL the reply arrived with, when it could be read.
    ///
    /// Free OS hinting: 64 for Linux/macOS/iOS, 128 for Windows, 255 for network gear,
    /// minus the hop count — which on a LAN is zero or one. It costs nothing on top of
    /// a probe we were sending anyway, so there is no reason not to take it.
    var ttl: UInt8?
}

/// Decodes what `recvmsg` returned on an ICMP datagram socket.
enum ICMPReplyDecoder {
    /// Parses a received buffer into a reply.
    ///
    /// Handles both shapes deliberately. Documentation for `SOCK_DGRAM`/`IPPROTO_ICMP`
    /// says the IP header is stripped, and on this machine it is — but the behaviour
    /// has differed between Darwin releases and between this and `SOCK_RAW`, and a
    /// scanner that reads the wrong eight bytes reports every host as unreachable with
    /// no indication why. Sniffing the version nibble costs one comparison and removes
    /// a whole class of silent failure.
    ///
    /// - Parameters:
    ///   - bytes: the received datagram.
    ///   - source: the peer address `recvmsg` reported.
    ///   - controlTTL: the TTL from an `IP_RECVTTL` control message, if one arrived.
    static func decode(
        _ bytes: Span<UInt8>,
        source: IPv4Address,
        controlTTL: UInt8?,
        receivedAt: MonotonicInstant = .now
    ) -> ICMPReply? {
        var offset = 0
        var ttl = controlTTL

        // An IPv4 header begins with version 4 in the high nibble and an IHL of at
        // least 5 words in the low one.
        if bytes.count >= 20, bytes[0] >> 4 == 4 {
            let headerWords = Int(bytes[0] & 0x0F)
            if headerWords >= 5, bytes.count >= headerWords * 4 + ICMPEcho.headerLength {
                ttl = bytes[8]
                offset = headerWords * 4
            }
        }

        guard bytes.count >= offset + ICMPEcho.headerLength else { return nil }
        guard bytes[offset] == ICMPEcho.replyType, bytes[offset + 1] == 0 else {
            // Not an echo reply. Destination-unreachable and time-exceeded messages
            // also land on this socket; they are ignored rather than misread as a host
            // answering, because the host they name is precisely the one that did not.
            return nil
        }

        // Verify the checksum over the ICMP message. The file header claims the
        // application owns the checksum, and owning it means checking it on the way in
        // as well as computing it on the way out — a corrupted reply is otherwise
        // accepted as a live host. Measured on the target platform: the ICMP portion of
        // a received echo reply sums to zero, so this is a real check and not a
        // formality. (The whole datagram does not, because it still carries the IP
        // header, which is not covered by the ICMP checksum.)
        let message = bytes.extracting(offset..<bytes.count)
        guard InternetChecksum.verifies(message) else { return nil }

        // And verify the payload is one of ours. The magic makes a reply to somebody
        // else's probe — or a stale reply from a previous run of this tool — visibly
        // wrong instead of silently attributed to a host we are measuring.
        let payloadStart = offset + ICMPEcho.headerLength
        guard bytes.count >= payloadStart + 8 else { return nil }
        for (index, byte) in ICMPEcho.magic.enumerated() where bytes[payloadStart + index] != byte {
            return nil
        }
        let token = UInt32(bytes[payloadStart + 4]) << 24
            | UInt32(bytes[payloadStart + 5]) << 16
            | UInt32(bytes[payloadStart + 6]) << 8
            | UInt32(bytes[payloadStart + 7])
        let sequence = UInt16(bytes[offset + 6]) << 8 | UInt16(bytes[offset + 7])
        return ICMPReply(source: source, sequence: sequence, token: token,
                         receivedAt: receivedAt, ttl: ttl)
    }
}

#endif
