// ARPFrame.swift — building and reading ARP over Ethernet, byte by byte.
//
// ── Why ARP is the capability worth having root for ──────────────────────────────
//
// Every host on a segment must answer an ARP request for its own address, whatever its
// ICMP policy, whatever its firewall, however slowly it answers anything else — because
// without answering it cannot receive a frame at all. That is a stronger obligation
// than any other probe can appeal to, and it is why `nmap -sn` under root reaches hosts
// that no unprivileged sweep does.
//
// Reading the kernel's neighbour table is NOT this. The table holds what the kernel
// happens to have learned; putting a request on the wire asks. The two were the same
// `EngineCapabilities` member until a packet capture taken on 2026-09-12 showed the
// unprivileged engine claiming `arpSweep` while emitting no ARP of its own — the frames
// in that capture were the kernel resolving next-hop for the ICMP datagrams, which is a
// side-effect of a probe rather than a probe. This file is the thing that claim was
// wrong about.
//
// ── The layout, measured against RFC 826 and a capture ───────────────────────────
//
//     Ethernet II (14 bytes)
//       0..6    destination hardware address
//       6..12   source hardware address
//       12..14  ethertype, 0x0806 big-endian
//     ARP payload (28 bytes)
//       14..16  hardware type, 0x0001 Ethernet
//       16..18  protocol type, 0x0800 IPv4
//       18      hardware address length, 6
//       19      protocol address length, 4
//       20..22  operation, 1 request / 2 reply
//       22..28  sender hardware address
//       28..32  sender protocol address
//       32..38  target hardware address
//       38..42  target protocol address
//
// Forty-two bytes. Ethernet's minimum payload is 46, so the driver pads on the way out
// and a capture shows either 42 or 60 depending on where it tapped; both are this
// frame. Nothing here pads, because padding an ARP request is the driver's job and
// doing it twice would put four bytes of ours where the FCS is expected.
//
// ── Why no `unsafe` appears below ────────────────────────────────────────────────
//
// Building writes into an `[UInt8]` by index. Reading takes a `Span<UInt8>` and
// combines bytes explicitly rather than loading a `UInt16`, for the reason
// `InternetChecksum.swift` sets out at length: `RawSpan`'s only load is
// `unsafeLoadUnaligned`, and wire data is both unaligned and big-endian, so writing the
// combination out is simultaneously the safe version and the correct one. A parser
// copied from this file starts right.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// ARP over Ethernet: the frame this engine sends, and the reply it reads.
enum ARPFrame {
    /// Ethernet header length.
    static let ethernetHeaderLength = 14
    /// ARP payload length for IPv4 over Ethernet.
    static let payloadLength = 28
    /// A complete request, before the driver pads it.
    static let totalLength = ethernetHeaderLength + payloadLength

    /// `ETHERTYPE_ARP`.
    static let ethertype: UInt16 = 0x0806
    /// Hardware type 1: Ethernet.
    static let hardwareTypeEthernet: UInt16 = 0x0001
    /// Protocol type 0x0800: IPv4.
    static let protocolTypeIPv4: UInt16 = 0x0800
    /// Operation 1.
    static let operationRequest: UInt16 = 1
    /// Operation 2.
    static let operationReply: UInt16 = 2

    /// The all-ones hardware address a request is broadcast to.
    static let broadcast = MACAddress(raw: 0xFFFF_FFFF_FFFF)

    /// Builds an ARP request asking who holds `target`.
    ///
    /// - Parameters:
    ///   - target: the address being asked about. Goes in the target protocol field;
    ///     the target hardware field stays zero, which is what makes it a question.
    ///   - senderMAC: this machine's hardware address on the sending interface. The
    ///     reply comes back to it, so a wrong value here produces a sweep that sends
    ///     perfectly and hears nothing.
    ///   - senderIP: this machine's address on the segment. A host that answers will
    ///     also cache this pairing, which is a side-effect worth knowing about: an ARP
    ///     sweep is not passive.
    static func request(
        target: IPv4Address, senderMAC: MACAddress, senderIP: IPv4Address
    ) -> [UInt8] {
        var frame = [UInt8](repeating: 0, count: totalLength)

        write(&frame, at: 0, mac: broadcast)
        write(&frame, at: 6, mac: senderMAC)
        write(&frame, at: 12, u16: ethertype)

        write(&frame, at: 14, u16: hardwareTypeEthernet)
        write(&frame, at: 16, u16: protocolTypeIPv4)
        frame[18] = 6
        frame[19] = 4
        write(&frame, at: 20, u16: operationRequest)
        write(&frame, at: 22, mac: senderMAC)
        write(&frame, at: 28, ip: senderIP)
        // 32..38 — target hardware address, left zero. This is the question.
        write(&frame, at: 38, ip: target)

        return frame
    }

    /// What one ARP frame said.
    struct Message: Sendable, Hashable {
        /// 1 for a request, 2 for a reply.
        var operation: UInt16
        /// The hardware address of whoever sent it.
        var senderMAC: MACAddress
        /// The protocol address of whoever sent it — the evidence that a host exists.
        var senderIP: IPv4Address
        /// Who it was addressed to, at layer 2.
        var targetMAC: MACAddress
        /// Who it was addressed to, at layer 3.
        var targetIP: IPv4Address

        /// Whether this is an answer rather than a question.
        var isReply: Bool { operation == ARPFrame.operationReply }
    }

    /// Reads an Ethernet frame, returning its ARP payload when it has one.
    ///
    /// Returns nil rather than throwing for anything that is not an IPv4-over-Ethernet
    /// ARP frame. The kernel filter already rejects non-ARP ethertypes, so this is the
    /// second of two checks rather than the only one — and it is still worth making,
    /// because a filter that failed to install must not silently turn every frame on
    /// the segment into a host.
    ///
    /// **VLAN-tagged ARP is not read.** An 802.1Q tag shifts the ethertype from offset
    /// 12 to 16, and both the filter and this parser look at 12. A tagged segment would
    /// produce a sweep that sends and hears nothing rather than one that quietly
    /// half-works, and the engine says so in a degradation when it happens.
    static func parse(_ bytes: Span<UInt8>) -> Message? {
        guard bytes.count >= totalLength else { return nil }
        guard u16(bytes, 12) == ethertype else { return nil }
        guard u16(bytes, 14) == hardwareTypeEthernet else { return nil }
        guard u16(bytes, 16) == protocolTypeIPv4 else { return nil }
        guard bytes[18] == 6, bytes[19] == 4 else { return nil }

        guard let senderMAC = mac(bytes, 22), let targetMAC = mac(bytes, 32) else {
            return nil
        }
        return Message(
            operation: u16(bytes, 20),
            senderMAC: senderMAC,
            senderIP: ip(bytes, 28),
            targetMAC: targetMAC,
            targetIP: ip(bytes, 38)
        )
    }

    // MARK: - Scalars, written and read big-endian on purpose

    private static func write(_ frame: inout [UInt8], at offset: Int, u16 value: UInt16) {
        frame[offset] = UInt8(truncatingIfNeeded: value >> 8)
        frame[offset + 1] = UInt8(truncatingIfNeeded: value)
    }

    private static func write(_ frame: inout [UInt8], at offset: Int, mac: MACAddress) {
        for (index, byte) in mac.bytes.enumerated() { frame[offset + index] = byte }
    }

    private static func write(_ frame: inout [UInt8], at offset: Int, ip: IPv4Address) {
        frame[offset] = UInt8(truncatingIfNeeded: ip.raw >> 24)
        frame[offset + 1] = UInt8(truncatingIfNeeded: ip.raw >> 16)
        frame[offset + 2] = UInt8(truncatingIfNeeded: ip.raw >> 8)
        frame[offset + 3] = UInt8(truncatingIfNeeded: ip.raw)
    }

    private static func u16(_ bytes: Span<UInt8>, _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func ip(_ bytes: Span<UInt8>, _ offset: Int) -> IPv4Address {
        var raw: UInt32 = 0
        for index in 0..<4 { raw = (raw << 8) | UInt32(bytes[offset + index]) }
        return IPv4Address(raw: raw)
    }

    private static func mac(_ bytes: Span<UInt8>, _ offset: Int) -> MACAddress? {
        var packed: UInt64 = 0
        for index in 0..<6 { packed = (packed << 8) | UInt64(bytes[offset + index]) }
        return MACAddress(raw: packed)
    }
}

#endif
