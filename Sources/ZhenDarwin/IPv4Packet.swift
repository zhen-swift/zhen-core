// IPv4Packet.swift — building and reading the TCP segments a half-open scan sends.
//
// ── What half-open means, and what it costs ─────────────────────────────────────
//
// A connect scan completes the handshake: SYN, SYN-ACK, ACK — and the application on
// the far side sees an accepted connection, logs it, and often sends a banner before we
// close. A half-open scan sends the SYN itself and stops at the answer:
//
//   SYN-ACK  → the port is open.   We never ACK.
//   RST      → the port is closed. The host is there and said no.
//   nothing  → filtered. Says only that nothing came back in time.
//
// The advantage is not stealth — every modern stack logs a half-open probe if it is
// looking — it is that the far-side application is never involved, so the scan costs
// the target one packet instead of an accept, a read timeout and a close.
//
// **The kernel sends a RST we did not ask it to.** Our SYN-ACK arrives addressed to a
// source port with no socket bound to it, so this machine's TCP stack answers with a
// RST and tears the half-open connection down. That is what closes it, we do not, and
// it is why the scan is half-open from our side rather than from the network's. Binding
// a socket to that port to suppress it would be worse: the kernel would then *complete*
// the handshake on our behalf and the scan would silently become a connect scan.
//
// ── Matching replies without keeping state ──────────────────────────────────────
//
// A SYN carries a 32-bit sequence number and the answer echoes it back in the
// acknowledgement field, plus one. So the sequence is not random here: it is a cookie
// over the destination address, the port, and a salt drawn once per scan — which means
// a reply identifies its own probe and the scan holds no per-probe table at all.
//
// The salt is not decoration. Without it the cookie is a pure function of the target
// and port, and a capture of two runs minutes apart showed them sending byte-identical
// sequence numbers to every port; a reply that arrived late from the first would then
// match a probe in the second and decide a port that had not answered.
//
// `seq` is 32 bits over a space of at most 254 × 65,535, so this is a hash and
// collisions are possible; the source address and port on the reply are checked as
// well, which is what makes the match unambiguous.
//
// ── Offsets, and why they are written out ───────────────────────────────────────
//
//     Ethernet II (14)   dst@0  src@6  ethertype@12
//     IPv4 (20, no opts) v/IHL@0  TOS@1  total@2  id@4  flags/frag@6
//                        TTL@8  proto@9  checksum@10  src@12  dst@16
//     TCP (20, no opts)  sport@0  dport@2  seq@4  ack@8  offset/flags@12
//                        window@14  checksum@16  urgent@18
//
// Same discipline as `ARPFrame`: written by index into an `[UInt8]`, read out of a
// `Span<UInt8>` by combining bytes big-endian. No `unsafe`, no alignment assumed, and
// the byte order is written out rather than inherited from the machine — this is wire
// data, unlike the `bpf_hdr` fields next door, which are the kernel's own integers.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// IPv4 and TCP, enough of each to send a SYN and read the answer.
enum IPv4Packet {
    /// Ethernet header length.
    static let ethernetHeaderLength = 14
    /// IPv4 header length with no options, which is all this engine emits.
    static let ipHeaderLength = 20
    /// TCP header length with no options, which is all this engine emits.
    static let tcpHeaderLength = 20
    /// A complete SYN frame before the driver pads it.
    static let synFrameLength = ethernetHeaderLength + ipHeaderLength + tcpHeaderLength

    /// `ETHERTYPE_IP`.
    static let ethertype: UInt16 = 0x0800
    /// IP protocol number for TCP.
    static let protocolTCP: UInt8 = 6

    /// TCP flag bits, as they sit in the low six bits of the byte at offset 13.
    struct Flags: OptionSet, Sendable, Hashable {
        let rawValue: UInt8
        init(rawValue: UInt8) { self.rawValue = rawValue }
        static let fin = Flags(rawValue: 1 << 0)
        static let syn = Flags(rawValue: 1 << 1)
        static let rst = Flags(rawValue: 1 << 2)
        static let push = Flags(rawValue: 1 << 3)
        static let ack = Flags(rawValue: 1 << 4)
        static let urgent = Flags(rawValue: 1 << 5)
    }

    /// Builds one SYN, complete from the Ethernet header down.
    ///
    /// - Parameters:
    ///   - target: the address being probed, and the layer-3 destination.
    ///   - targetMAC: the layer-2 destination. On a local segment this is the host's
    ///     own hardware address, which is why this engine needs the neighbour table —
    ///     see `SYNScan.swift` on why reading it for next-hop is not the same thing as
    ///     claiming `neighborTable` as a discovery capability.
    ///   - port: the destination port.
    ///   - senderMAC: this machine's hardware address on the sending interface.
    ///   - senderIP: this machine's address, and where the answer will come back to.
    ///   - sourcePort: the local port every probe in a scan is sent from, and the one
    ///     the BPF filter matches on.
    ///   - identifier: the IPv4 identification field. Varied per probe so a middlebox
    ///     cannot mistake two probes for fragments of one datagram.
    ///   - salt: the per-scan value mixed into the sequence cookie. See `cookie`.
    static func syn(
        target: IPv4Address,
        targetMAC: MACAddress,
        port: UInt16,
        senderMAC: MACAddress,
        senderIP: IPv4Address,
        sourcePort: UInt16,
        identifier: UInt16,
        salt: UInt32 = 0,
        options: [UInt8] = []
    ) -> [UInt8] {
        // Options are padded to a four-byte boundary, because the data-offset field
        // counts words and cannot express anything else.
        var options = options
        while options.count % 4 != 0 { options.append(Option.endOfList) }
        let tcpLength = tcpHeaderLength + options.count
        var frame = [UInt8](repeating: 0, count: ethernetHeaderLength + ipHeaderLength + tcpLength)

        write(&frame, at: 0, mac: targetMAC)
        write(&frame, at: 6, mac: senderMAC)
        write(&frame, at: 12, u16: ethertype)

        let ip = ethernetHeaderLength
        frame[ip] = 0x45                                    // version 4, 5 words of header
        frame[ip + 1] = 0                                   // DSCP/ECN
        write(&frame, at: ip + 2, u16: UInt16(ipHeaderLength + tcpLength))
        write(&frame, at: ip + 4, u16: identifier)
        // Don't Fragment. A 40-byte datagram cannot need fragmenting, and setting it
        // means a path that would have fragmented answers instead of silently splitting
        // a probe into something the far side reassembles differently.
        write(&frame, at: ip + 6, u16: 0x4000)
        frame[ip + 8] = 64                                  // TTL
        frame[ip + 9] = protocolTCP
        write(&frame, at: ip + 10, u16: 0)                  // checksum, computed below
        write(&frame, at: ip + 12, ip: senderIP)
        write(&frame, at: ip + 16, ip: target)
        let headerChecksum = InternetChecksum.compute(Array(frame[ip..<(ip + ipHeaderLength)]))
        write(&frame, at: ip + 10, u16: headerChecksum)

        let tcp = ip + ipHeaderLength
        write(&frame, at: tcp, u16: sourcePort)
        write(&frame, at: tcp + 2, u16: port)
        write(&frame, at: tcp + 4, u32: cookie(target: target, port: port, salt: salt))
        write(&frame, at: tcp + 8, u32: 0)                  // acknowledgement
        frame[tcp + 12] = UInt8((tcpLength / 4) << 4)       // data offset, in words
        frame[tcp + 13] = Flags.syn.rawValue
        write(&frame, at: tcp + 14, u16: 65_535)            // window
        write(&frame, at: tcp + 16, u16: 0)                 // checksum, computed below
        write(&frame, at: tcp + 18, u16: 0)                 // urgent pointer
        for (index, byte) in options.enumerated() { frame[tcp + tcpHeaderLength + index] = byte }
        let segmentChecksum = tcpChecksum(
            frame: frame, tcpOffset: tcp, tcpLength: tcpLength,
            source: senderIP, destination: target
        )
        write(&frame, at: tcp + 16, u16: segmentChecksum)

        return frame
    }

    /// The sequence number a probe carries, and the thing its reply is matched by.
    ///
    /// Deterministic in `target` and `port` so that a reply names its own probe and the
    /// scan holds no per-probe table at all — that is the whole mechanism.
    ///
    /// **`salt` is what keeps it from being deterministic across scans**, and it was
    /// added because a packet capture showed the first version was not: two runs
    /// against the same network minutes apart sent byte-identical sequence numbers to
    /// every port. A reply that arrived late from the earlier scan would then match a
    /// probe in the later one and decide a port that had not answered. The salt is
    /// drawn once per scan and held for its duration, so matching stays stateless
    /// within a run and cannot reach across two.
    ///
    /// The constants are the usual 32-bit avalanche. Nothing here is a security
    /// property — it only has to scatter.
    static func cookie(target: IPv4Address, port: UInt16, salt: UInt32 = 0) -> UInt32 {
        var value = target.raw ^ (UInt32(port) &* 0x9E37_79B9) ^ salt
        value ^= value >> 16
        value = value &* 0x85EB_CA6B
        value ^= value >> 13
        value = value &* 0xC2B2_AE35
        value ^= value >> 16
        // Never zero: a zero sequence would make `ack == 1` on the reply, which is also
        // what a stack answering a probe we did not send would produce.
        return value == 0 ? 0x5EED_5EED : value
    }

    // MARK: - Options
    //
    // A SYN-ACK's options are the most discriminating thing a stack emits, and most of
    // them are *negotiated*: a peer includes SACK-permitted, window scale and timestamps
    // only if the SYN offered them first. So a fingerprint probe has to offer the lot,
    // and the ordinary scan deliberately does not — its SYN is twenty bytes because
    // nine thousand of them go out and the verdict does not depend on options.

    /// The canonical option block a fingerprint probe offers.
    ///
    /// MSS, SACK-permitted, timestamps, NOP padding and window scale, in the order
    /// Linux emits them. The order matters less than the offer: what is being measured
    /// is which of these the *peer* echoes and in which order **it** places them.
    ///
    ///     02 04 05 b4   MSS 1460
    ///     04 02         SACK permitted
    ///     08 0a ...     timestamps, value then echo
    ///     01            NOP
    ///     03 03 07      window scale 7
    static func fingerprintOptions(timestamp: UInt32) -> [UInt8] {
        var options: [UInt8] = [0x02, 0x04, 0x05, 0xB4, 0x04, 0x02, 0x08, 0x0A]
        for index in 0..<4 { options.append(UInt8(truncatingIfNeeded: timestamp >> (24 - 8 * index))) }
        options.append(contentsOf: [0, 0, 0, 0])   // echo reply, zero in a SYN
        options.append(contentsOf: [0x01, 0x03, 0x03, 0x07])
        return options
    }

    /// One TCP option as it appeared on the wire.
    struct Option: Sendable, Hashable {
        /// The option kind byte.
        var kind: UInt8
        /// Its value bytes, excluding kind and length.
        var value: [UInt8]

        static let endOfList: UInt8 = 0
        static let noOperation: UInt8 = 1
        static let maximumSegmentSize: UInt8 = 2
        static let windowScale: UInt8 = 3
        static let sackPermitted: UInt8 = 4
        static let timestamps: UInt8 = 8
    }

    /// Reads the option block of a TCP segment.
    ///
    /// **The data-offset field is what says where the options end**, and a malformed
    /// length inside them is the thing that turns this walk into an infinite loop or a
    /// read past the segment. Both are guarded: a zero-or-one length on a multi-byte
    /// option ends the walk, and so does a length that runs past the header.
    ///
    /// Returns the options in the order the peer placed them, which is itself part of
    /// the signature — the same set in a different order is a different stack.
    static func options(_ bytes: Span<UInt8>) -> [Option] {
        guard bytes.count >= ethernetHeaderLength + ipHeaderLength else { return [] }
        let ip = ethernetHeaderLength
        let ipWords = Int(bytes[ip] & 0x0F)
        guard ipWords >= 5 else { return [] }
        let tcp = ip + ipWords * 4
        guard bytes.count >= tcp + tcpHeaderLength else { return [] }

        let dataWords = Int(bytes[tcp + 12] >> 4)
        guard dataWords > 5 else { return [] }
        let end = tcp + dataWords * 4
        guard bytes.count >= end else { return [] }

        var found: [Option] = []
        var cursor = tcp + tcpHeaderLength
        while cursor < end {
            let kind = bytes[cursor]
            if kind == Option.endOfList { break }
            if kind == Option.noOperation {
                found.append(Option(kind: kind, value: []))
                cursor += 1
                continue
            }
            guard cursor + 1 < end else { break }
            let length = Int(bytes[cursor + 1])
            // A length below two cannot include its own kind and length bytes, and
            // would not advance the cursor.
            guard length >= 2, cursor + length <= end else { break }
            var value: [UInt8] = []
            for index in (cursor + 2)..<(cursor + length) { value.append(bytes[index]) }
            found.append(Option(kind: kind, value: value))
            cursor += length
        }
        return found
    }

    /// The IPv4 header fields a fingerprint reads.
    struct Header: Sendable, Hashable {
        /// The TTL as it arrived, already decremented by every hop.
        var ttl: UInt8
        /// Whether Don't Fragment was set.
        var dontFragment: Bool
        /// The advertised receive window.
        var window: UInt16
    }

    /// Reads the IPv4 and TCP header fields a fingerprint reads.
    static func header(_ bytes: Span<UInt8>) -> Header? {
        guard bytes.count >= ethernetHeaderLength + ipHeaderLength else { return nil }
        let ip = ethernetHeaderLength
        let ipWords = Int(bytes[ip] & 0x0F)
        guard ipWords >= 5 else { return nil }
        let tcp = ip + ipWords * 4
        guard bytes.count >= tcp + tcpHeaderLength else { return nil }
        return Header(
            ttl: bytes[ip + 8],
            dontFragment: bytes[ip + 6] & 0x40 != 0,
            window: u16(bytes, tcp + 14)
        )
    }

    /// What one TCP segment off the wire said.
    struct Segment: Sendable, Hashable {
        /// Who sent it.
        var source: IPv4Address
        /// The port it came from, which is the port that was probed.
        var sourcePort: UInt16
        /// The port it was addressed to, which is ours.
        var destinationPort: UInt16
        /// The acknowledgement field. For an answer to a SYN this is our sequence plus
        /// one, which is how the probe is recovered.
        var acknowledgement: UInt32
        /// Which flags were set.
        var flags: Flags

        /// A SYN-ACK: the port is open.
        var isSynAck: Bool { flags.contains(.syn) && flags.contains(.ack) }
        /// A RST: the port is closed, and the host is there to say so.
        var isReset: Bool { flags.contains(.rst) }
    }

    /// Reads an Ethernet frame, returning its TCP segment when it has one.
    ///
    /// Returns nil for anything that is not IPv4-over-Ethernet carrying TCP. The kernel
    /// filter has already rejected those, so this is the second of two checks — and it
    /// is still worth making, because a filter that failed to install must not turn
    /// every frame on the segment into a port verdict.
    ///
    /// **The IPv4 header length is read, not assumed.** A header carrying options is
    /// longer than twenty bytes and the TCP fields move with it; reading them at a
    /// fixed offset would produce a port number out of the middle of an option.
    static func parse(_ bytes: Span<UInt8>) -> Segment? {
        guard bytes.count >= ethernetHeaderLength + ipHeaderLength else { return nil }
        guard u16(bytes, 12) == ethertype else { return nil }

        let ip = ethernetHeaderLength
        guard bytes[ip] >> 4 == 4 else { return nil }
        let headerWords = Int(bytes[ip] & 0x0F)
        guard headerWords >= 5 else { return nil }
        let headerLength = headerWords * 4
        guard bytes[ip + 9] == protocolTCP else { return nil }

        let tcp = ip + headerLength
        guard bytes.count >= tcp + tcpHeaderLength else { return nil }

        return Segment(
            source: ipAddress(bytes, ip + 12),
            sourcePort: u16(bytes, tcp),
            destinationPort: u16(bytes, tcp + 2),
            acknowledgement: u32(bytes, tcp + 8),
            flags: Flags(rawValue: bytes[tcp + 13] & 0x3F)
        )
    }

    /// The TCP checksum, which covers a pseudo-header as well as the segment.
    ///
    /// The pseudo-header — source, destination, a zero byte, the protocol number and
    /// the TCP length — is not transmitted; it exists so a segment delivered to the
    /// wrong host or the wrong protocol fails its checksum instead of being accepted.
    /// Omitting it produces a segment every stack silently discards, which presents as
    /// a scan where every port is filtered.
    static func tcpChecksum(
        frame: [UInt8], tcpOffset: Int, tcpLength: Int,
        source: IPv4Address, destination: IPv4Address
    ) -> UInt16 {
        var buffer = [UInt8]()
        buffer.reserveCapacity(12 + tcpLength)
        var pseudo = [UInt8](repeating: 0, count: 12)
        write(&pseudo, at: 0, ip: source)
        write(&pseudo, at: 4, ip: destination)
        pseudo[8] = 0
        pseudo[9] = protocolTCP
        write(&pseudo, at: 10, u16: UInt16(tcpLength))
        buffer.append(contentsOf: pseudo)
        buffer.append(contentsOf: frame[tcpOffset..<(tcpOffset + tcpLength)])
        return InternetChecksum.compute(buffer)
    }

    // MARK: - Scalars, big-endian because this is wire data

    private static func write(_ frame: inout [UInt8], at offset: Int, u16 value: UInt16) {
        frame[offset] = UInt8(truncatingIfNeeded: value >> 8)
        frame[offset + 1] = UInt8(truncatingIfNeeded: value)
    }

    private static func write(_ frame: inout [UInt8], at offset: Int, u32 value: UInt32) {
        for index in 0..<4 {
            frame[offset + index] = UInt8(truncatingIfNeeded: value >> (24 - 8 * index))
        }
    }

    private static func write(_ frame: inout [UInt8], at offset: Int, mac: MACAddress) {
        for (index, byte) in mac.bytes.enumerated() { frame[offset + index] = byte }
    }

    private static func write(_ frame: inout [UInt8], at offset: Int, ip: IPv4Address) {
        for index in 0..<4 {
            frame[offset + index] = UInt8(truncatingIfNeeded: ip.raw >> (24 - 8 * index))
        }
    }

    private static func u16(_ bytes: Span<UInt8>, _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func u32(_ bytes: Span<UInt8>, _ offset: Int) -> UInt32 {
        var value: UInt32 = 0
        for index in 0..<4 { value = (value << 8) | UInt32(bytes[offset + index]) }
        return value
    }

    private static func ipAddress(_ bytes: Span<UInt8>, _ offset: Int) -> IPv4Address {
        IPv4Address(raw: u32(bytes, offset))
    }
}

#endif
