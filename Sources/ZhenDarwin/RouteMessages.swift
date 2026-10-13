// RouteMessages.swift — parsing the kernel's routing socket replies by byte offset.
//
// A `sysctl` over `PF_ROUTE` returns a packed stream of variable-length messages, and
// each message is followed by a variable number of variable-length `sockaddr`s. Two
// things about that shape make the obvious approach wrong.
//
// First, `sockaddr_dl` — the link-layer address that carries the MAC — is genuinely
// variable length: the interface name and the hardware address share a trailing
// `sdl_data` array whose declared size (12 bytes) is a lie for anything with a name
// longer than six characters. `MemoryLayout<sockaddr_dl>.size` is 20 and the real
// record is often larger.
//
// Second, and worse, these records are not aligned. They are packed end to end at
// four-byte boundaries inside a buffer the kernel filled. `bindMemory` or a
// `assumingMemoryBound` cast over one is alignment undefined behaviour — the kind that
// works on every machine you own and crashes on someone else's, or works for a year
// and then stops when a struct grows by two bytes.
//
// So: one parser, one file, explicit byte offsets over a `RawSpan`, exhaustively
// tested against captured bytes committed as fixtures. Bounds are checked by the span
// and no pointer escapes the buffer's lifetime. Every offset below was measured on the
// target SDK rather than recalled:
//
//     rt_msghdr (92 bytes)   msglen@0:u16  version@2:u8  type@3:u8
//                            index@4:u16   flags@8:i32   addrs@12:i32
//     sockaddr_dl (>=20)     len@0:u8  family@1:u8  index@2:u16
//                            nlen@5:u8 alen@6:u8    data@8
//     sockaddr_in (16)       len@0:u8  family@1:u8  addr@4:u32be
//     sockaddr_in6 (28)      len@0:u8  family@1:u8  addr@8..<24  scope_id@24:u32
#if canImport(Darwin)

import Darwin
import ZhenCore

/// One parsed routing-socket message: the header fields we use, and its addresses.
struct RouteMessage {
    /// `rtm_type` — RTM_GET, RTM_ADD and so on.
    var type: UInt8
    /// `rtm_index` — the interface this entry belongs to.
    var interfaceIndex: UInt16
    /// `rtm_flags` — RTF_UP, RTF_GATEWAY, RTF_LLINFO.
    var flags: Int32
    /// The IPv4 destination, when `RTA_DST` was present and AF_INET.
    var destination: IPv4Address?
    /// The IPv6 destination, when `RTA_DST` was present and AF_INET6. No zone: the
    /// caller names it from `interfaceIndex`.
    var destination6: IPv6Address?
    /// The IPv4 gateway, when `RTA_GATEWAY` was present and AF_INET.
    var gateway: IPv4Address?
    /// The link-layer address, when `RTA_GATEWAY` was present and AF_LINK. In an ARP
    /// entry the "gateway" slot holds the MAC, which is the whole point of reading it.
    var linkAddress: MACAddress?
    /// The netmask, when `RTA_NETMASK` was present.
    var netmask: UInt32?
}

/// Decodes the packed message stream a `PF_ROUTE` sysctl returns.
enum RouteMessageParser {
    /// Size of `rt_msghdr` on this platform, measured rather than assumed.
    static let headerSize = MemoryLayout<rt_msghdr>.size

    /// The address slots, in the bit order the kernel emits them.
    static let addressSlots: [Int32] = [
        RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK,
        RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD,
    ]

    /// Rounds a `sa_len` up to the kernel's four-byte packing.
    ///
    /// A zero length still advances a full word — that is the kernel's own `ROUNDUP`
    /// macro, and getting it wrong desynchronises the whole rest of the buffer rather
    /// than corrupting one field, so it fails loudly if at all.
    static func roundUp(_ length: Int) -> Int {
        length == 0 ? MemoryLayout<UInt32>.size
                    : (1 + ((length - 1) | (MemoryLayout<UInt32>.size - 1)))
    }

    /// Parses every message in a buffer.
    ///
    /// Malformed input truncates the walk rather than throwing. A short read or a
    /// message claiming a length that runs past the end is corruption we cannot act on,
    /// and returning what parsed cleanly is more useful than discarding all of it.
    static func parse(_ bytes: RawSpan) -> [RouteMessage] {
        var messages: [RouteMessage] = []
        var offset = 0
        while offset + headerSize <= bytes.byteCount {
            let length = Int(u16(bytes, offset))
            // A zero or short length would loop forever; a long one would read past
            // the buffer. Both mean the stream is no longer trustworthy.
            guard length >= headerSize, offset + length <= bytes.byteCount else { break }
            if let message = parseOne(bytes, at: offset, length: length) {
                messages.append(message)
            }
            offset += length
        }
        return messages
    }

    private static func parseOne(_ bytes: RawSpan, at base: Int, length: Int) -> RouteMessage? {
        var message = RouteMessage(
            type: u8(bytes, base + 3),
            interfaceIndex: u16(bytes, base + 4),
            flags: i32(bytes, base + 8),
            destination: nil, destination6: nil, gateway: nil, linkAddress: nil, netmask: nil
        )
        let present = i32(bytes, base + 12)
        var cursor = base + headerSize
        let end = base + length

        for slot in addressSlots {
            guard present & slot != 0 else { continue }
            guard cursor + 2 <= end else { break }
            let saLen = Int(u8(bytes, cursor))
            let family = u8(bytes, cursor + 1)
            let advance = roundUp(saLen)
            guard cursor + max(advance, 2) <= end else { break }

            switch (slot, Int32(family)) {
            case (RTA_DST, AF_INET) where saLen >= 8:
                message.destination = IPv4Address(raw: u32be(bytes, cursor + 4))
            case (RTA_DST, AF_INET) where saLen > 0:
                // A default route's destination is emitted as a truncated sockaddr —
                // sa_len 0 or 4, no address bytes at all — which means 0.0.0.0.
                message.destination = IPv4Address(raw: 0)
            case (RTA_DST, AF_INET6) where saLen >= 24:
                var raw: [UInt8] = []
                raw.reserveCapacity(16)
                for index in 0..<16 { raw.append(u8(bytes, cursor + 8 + index)) }
                // The KAME stack embeds a link-local address's scope in bytes 2-3 inside
                // the kernel, and routing messages leak it: `fe80:e::…` for en0. It is
                // not part of the address. Cleared here, as `ndp` itself does.
                if raw[0] == 0xFE, raw[1] & 0xC0 == 0x80 {
                    raw[2] = 0
                    raw[3] = 0
                }
                message.destination6 = IPv6Address(bytes: raw)
            case (RTA_GATEWAY, AF_INET) where saLen >= 8:
                message.gateway = IPv4Address(raw: u32be(bytes, cursor + 4))
            case (RTA_GATEWAY, AF_LINK):
                message.linkAddress = linkLayerAddress(bytes, at: cursor, limit: end)
            case (RTA_NETMASK, _):
                message.netmask = netmask(bytes, at: cursor, length: saLen)
            default:
                break
            }
            cursor += advance
        }
        // A default route arrives with RTA_DST present but zero-length, which the loop
        // above cannot distinguish from absent. Flags plus a gateway are what identify
        // it, so leave destination nil and let the caller decide.
        return message
    }

    /// Extracts the hardware address from a `sockaddr_dl`.
    ///
    /// The MAC sits at `sdl_data + sdl_nlen` for `sdl_alen` bytes — after the interface
    /// name, which shares the same trailing array. An entry with `sdl_alen == 0` is an
    /// incomplete ARP entry: a request that got no answer, which is evidence of absence
    /// and must not be reported as a device.
    static func linkLayerAddress(_ bytes: RawSpan, at offset: Int, limit: Int) -> MACAddress? {
        guard offset + 8 <= limit else { return nil }
        let nameLength = Int(u8(bytes, offset + 5))
        let addressLength = Int(u8(bytes, offset + 6))
        guard addressLength == 6 else { return nil }
        let start = offset + 8 + nameLength
        guard start + 6 <= limit else { return nil }
        var packed: UInt64 = 0
        for index in 0..<6 { packed = (packed << 8) | UInt64(u8(bytes, start + index)) }
        return MACAddress(raw: packed)
    }

    /// Extracts a netmask, which the kernel truncates to its significant bytes.
    ///
    /// A /24 arrives as a five-byte sockaddr carrying only `255.255.255`, not a full
    /// sixteen-byte `sockaddr_in`. Reading it as one yields whatever followed it in the
    /// buffer, so the trailing zero octets have to be supplied here.
    static func netmask(_ bytes: RawSpan, at offset: Int, length: Int) -> UInt32? {
        guard length > 0 else { return 0 }
        var mask: UInt32 = 0
        for index in 0..<4 {
            let position = offset + 4 + index
            let octet: UInt8 = position < offset + length ? u8(bytes, position) : 0
            mask = (mask << 8) | UInt32(octet)
        }
        return mask
    }

    // MARK: - Bounds-checked scalar reads
    //
    // Each is one `unsafe` expression and no more. `RawSpan.unsafeLoadUnaligned` is
    // marked unsafe because it will reinterpret arbitrary bytes as any type, including
    // ones with invalid bit patterns; here the types are fixed-width integers, for
    // which every bit pattern is valid, and the span has already bounds-checked the
    // offset. That is the whole justification, and it is why these four functions are
    // the only unsafe surface in this file.

    static func u8(_ bytes: RawSpan, _ offset: Int) -> UInt8 {
        guard offset >= 0, offset + 1 <= bytes.byteCount else { return 0 }
        return unsafe bytes.unsafeLoadUnaligned(fromByteOffset: offset, as: UInt8.self)
    }

    static func u16(_ bytes: RawSpan, _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= bytes.byteCount else { return 0 }
        return unsafe bytes.unsafeLoadUnaligned(fromByteOffset: offset, as: UInt16.self)
    }

    static func i32(_ bytes: RawSpan, _ offset: Int) -> Int32 {
        guard offset >= 0, offset + 4 <= bytes.byteCount else { return 0 }
        return unsafe bytes.unsafeLoadUnaligned(fromByteOffset: offset, as: Int32.self)
    }

    /// Reads four bytes in network order, which is how addresses arrive on the wire.
    static func u32be(_ bytes: RawSpan, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= bytes.byteCount else { return 0 }
        let raw = unsafe bytes.unsafeLoadUnaligned(fromByteOffset: offset, as: UInt32.self)
        return UInt32(bigEndian: raw)
    }
}

/// Reads a `PF_ROUTE` sysctl into a byte buffer.
enum RouteSysctl {
    /// Fetches one routing-socket table.
    ///
    /// Two calls: one to size the buffer, one to fill it. The table can grow between
    /// them — a device joining the network is enough — so a short second call is
    /// retried rather than treated as an error.
    static func fetch(_ mib: [Int32]) throws(PlatformError) -> [UInt8] {
        var mib = mib
        for _ in 0..<4 {
            var needed = 0
            // SAFETY: sysctl sizing call. `nil` output pointer with a valid `needed`
            // out-parameter is the documented way to ask for the length.
            guard unsafe sysctl(&mib, u_int(mib.count), nil, &needed, nil, 0) == 0 else {
                throw PlatformError.syscall("sysctl(PF_ROUTE) sizing")
            }
            guard needed > 0 else { return [] }
            // Overshoot the reported size. The table is live and can grow between the
            // sizing call and the fill; a fixed margin turns the common case of a
            // one-entry race into no retry at all.
            var buffer = [UInt8](repeating: 0, count: needed + 4096)
            var capacity = buffer.count
            let result = unsafe buffer.withUnsafeMutableBytes { raw in
                unsafe sysctl(&mib, u_int(mib.count), raw.baseAddress, &capacity, nil, 0)
            }
            if result == 0 {
                buffer.removeLast(buffer.count - capacity)
                return buffer
            }
            // ENOMEM means it grew past even the margin. Anything else is real.
            guard errno == ENOMEM else { throw PlatformError.syscall("sysctl(PF_ROUTE)") }
        }
        throw PlatformError.unavailable("The routing table kept changing while it was being read.")
    }
}

#endif
