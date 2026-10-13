// ICMPv6Echo.swift — echo request and reply, and the checksum that is not ICMPv4's.
//
// ICMPv4's checksum covers the ICMP message. ICMPv6's also covers a pseudo-header
// (RFC 8200 §8.1): source address, destination address, upper-layer length and next
// header 58. The same bytes checksummed the v4 way give a different, wrong answer — and
// a receiver drops a message with a bad checksum without a word, so the failure is a host
// that never answers.
//
// ── What was measured, and what it means for this file ──────────────────────────
//
// On macOS the kernel **rewrites the checksum of every message sent on an ICMPv6
// datagram socket**: a request carrying a zero checksum, and one carrying 0xBEEF, were
// both answered by a link-local neighbour exactly like a correct one (D1, in the ledger).
// So on this platform the send path cannot get it wrong. The computation here still
// matters, for two reasons:
//
//   - Replies are verified with it. That is where the pseudo-header is checked against
//     bytes another stack produced — the captured reply in the test fixtures.
//   - A raw socket on another platform, or a frame written through BPF for stage 6's
//     SYN-over-v6, gets no such help.
//
// Pure functions over bytes: this file compiles on Linux and has no `unsafe` in it.

/// The ICMPv6 echo messages this project sends and recognizes.
public enum ICMPv6Echo {
    public static let requestType: UInt8 = 128
    public static let replyType: UInt8 = 129
    /// The ICMPv6 next-header value, as it appears in the pseudo-header.
    public static let nextHeader: UInt8 = 58
    public static let headerLength = 8
    /// Marks a reply as an answer to this program rather than to anybody's `ping6`.
    public static let magic: [UInt8] = Array("ZHN6".utf8)
    public static let payloadLength = 8

    /// An echo request carrying `token` after the magic.
    ///
    /// The checksum is computed over the pseudo-header when the source is known, and
    /// left zero when it is not — which the kernel fills in on a datagram socket. The
    /// identifier is zero because a datagram socket assigns its own.
    public static func request(
        sequence: UInt16, token: UInt32, source: IPv6Address?, destination: IPv6Address
    ) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: headerLength + payloadLength)
        packet[0] = requestType
        packet[6] = UInt8(sequence >> 8)
        packet[7] = UInt8(sequence & 0xFF)
        for (index, byte) in magic.enumerated() { packet[headerLength + index] = byte }
        packet[headerLength + 4] = UInt8(truncatingIfNeeded: token >> 24)
        packet[headerLength + 5] = UInt8(truncatingIfNeeded: token >> 16)
        packet[headerLength + 6] = UInt8(truncatingIfNeeded: token >> 8)
        packet[headerLength + 7] = UInt8(truncatingIfNeeded: token)
        if let source {
            let sum = checksum(packet, source: source, destination: destination)
            packet[2] = UInt8(sum >> 8)
            packet[3] = UInt8(sum & 0xFF)
        }
        return packet
    }

    /// The RFC 8200 §8.1 pseudo-header for an ICMPv6 message of `length` bytes.
    public static func pseudoHeader(source: IPv6Address, destination: IPv6Address, length: Int) -> [UInt8] {
        let upper = UInt32(length)
        return source.bytes + destination.bytes + [
            UInt8(upper >> 24), UInt8((upper >> 16) & 0xFF), UInt8((upper >> 8) & 0xFF), UInt8(upper & 0xFF),
            0, 0, 0, nextHeader,
        ]
    }

    /// The checksum to write into `message`, whose checksum field must be zero.
    public static func checksum(_ message: [UInt8], source: IPv6Address, destination: IPv6Address) -> UInt16 {
        InternetChecksum.compute(pseudoHeader(source: source, destination: destination,
                                              length: message.count) + message)
    }

    /// Whether a received message's checksum is right, for the addresses it travelled
    /// between. Summing a correct message together with its checksum gives zero.
    public static func verifies(_ message: [UInt8], source: IPv6Address, destination: IPv6Address) -> Bool {
        InternetChecksum.compute(pseudoHeader(source: source, destination: destination,
                                              length: message.count) + message) == 0
    }

    /// The sequence and token of one of our echo replies, or nil for anything else —
    /// another program's reply, a router advertisement, a neighbour solicitation. A
    /// datagram ICMPv6 socket hands over every ICMPv6 message the host receives, so this
    /// filter is not optional.
    public static func decodeReply(_ message: [UInt8]) -> (sequence: UInt16, token: UInt32)? {
        guard message.count >= headerLength + payloadLength,
              message[0] == replyType, message[1] == 0
        else { return nil }
        for (index, byte) in magic.enumerated() where message[headerLength + index] != byte {
            return nil
        }
        let token = UInt32(message[headerLength + 4]) << 24
            | UInt32(message[headerLength + 5]) << 16
            | UInt32(message[headerLength + 6]) << 8
            | UInt32(message[headerLength + 7])
        return (UInt16(message[6]) << 8 | UInt16(message[7]), token)
    }
}
