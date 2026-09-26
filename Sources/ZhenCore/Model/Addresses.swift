// Addresses.swift — packed network address value types.
//
// Normalization is a property of the type, not a parsing step performed at call
// sites. macOS emits unpadded MACs from the ARP table ("0:92:35:30:a:1"), and any
// string-keyed identity scheme would treat that as a different device from
// "00:92:35:30:0A:01". Packing into an integer makes that impossible.

/// A 48-bit hardware address, packed into the low bits of a `UInt64`.
///
/// Packing rather than storing text is what makes normalization a property of the type:
/// macOS emits unpadded MACs from the ARP table, and a string-keyed identity scheme
/// would read `0:92:35:30:a:1` and `00:92:35:30:0A:01` as two different devices.
public struct MACAddress: Hashable, Sendable, CustomStringConvertible {
    /// Low 48 bits hold the address; the high 16 bits are always zero.
    public let raw: UInt64

    /// Packs a raw value, masking off anything above 48 bits so the invariant holds
    /// however the value was obtained.
    public init(raw: UInt64) {
        self.raw = raw & 0x0000_FFFF_FFFF_FFFF
    }

    /// Packs six bytes in wire order. Returns nil for any other length.
    public init?(bytes: some Collection<UInt8>) {
        guard bytes.count == 6 else { return nil }
        var packed: UInt64 = 0
        for byte in bytes { packed = (packed << 8) | UInt64(byte) }
        self.raw = packed
    }

    /// Accepts colon- or hyphen-separated forms with one or two hex digits per
    /// group, which is what the ARP table actually produces.
    public init?(_ text: String) {
        let groups = text.split(whereSeparator: { $0 == ":" || $0 == "-" })
        guard groups.count == 6 else { return nil }
        var packed: UInt64 = 0
        for group in groups {
            guard group.count <= 2, let byte = UInt8(group, radix: 16) else { return nil }
            packed = (packed << 8) | UInt64(byte)
        }
        self.raw = packed
    }

    /// The six bytes in wire order.
    public var bytes: [UInt8] {
        (0..<6).reversed().map { UInt8((raw >> (UInt64($0) * 8)) & 0xFF) }
    }

    /// The identity system's key test: a locally administered address is a private
    /// Wi-Fi address that rotates, and must never be treated as a stable identifier.
    public var isLocallyAdministered: Bool { (raw >> 40) & 0x02 != 0 }

    /// The group bit. A multicast address never identifies a device.
    public var isMulticast: Bool { (raw >> 40) & 0x01 != 0 }

    /// Organizationally Unique Identifier — the vendor prefix. Meaningless when
    /// `isLocallyAdministered` is true.
    public var oui: UInt32 { UInt32(raw >> 24) }

    /// Canonical uppercase colon-separated form. This is also the wire encoding and
    /// the normalized value of a MAC-derived identity key, so there is exactly one
    /// spelling of any given address anywhere in the system.
    public var description: String {
        let digits = Array("0123456789ABCDEF")
        var out = ""
        out.reserveCapacity(17)
        for (index, byte) in bytes.enumerated() {
            if index > 0 { out.append(":") }
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return out
    }
}

/// An IPv4 address, packed into a `UInt32` in host order.
public struct IPv4Address: Hashable, Sendable, Comparable, CustomStringConvertible {
    /// The address as a big-endian-ordered integer: the first octet is the high byte.
    public let raw: UInt32

    /// Wraps a packed value.
    public init(raw: UInt32) { self.raw = raw }

    /// Parses dotted-quad text. Returns nil for anything else, including an octet
    /// above 255 and a partial address.
    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var packed: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3, let octet = UInt8(part) else { return nil }
            packed = (packed << 8) | UInt32(octet)
        }
        self.raw = packed
    }

    /// The four octets, most significant first.
    public var octets: (UInt8, UInt8, UInt8, UInt8) {
        (UInt8(raw >> 24), UInt8((raw >> 16) & 0xFF), UInt8((raw >> 8) & 0xFF), UInt8(raw & 0xFF))
    }

    /// Whether this is in 127/8. Relevant because the local machine resolves itself
    /// to 127.0.0.1 over mDNS and that sighting has to be remapped to its real
    /// address before it joins the cascade.
    public var isLoopback: Bool { raw >> 24 == 127 }

    /// Whether this is in 224/4.
    ///
    /// A multicast group is not a device. The kernel's neighbour table lists every
    /// group the machine has joined — 224.0.0.251 for mDNS, among others — and a
    /// scanner that read those as hosts would invent devices on every network it saw.
    public var isMulticast: Bool { raw >> 28 == 0xE }

    /// Numeric order, so a sweep and a report both iterate a network in the order a
    /// person expects to read it.
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.raw < rhs.raw }

    /// Dotted quad, which is also the wire encoding.
    public var description: String {
        let o = octets
        return "\(o.0).\(o.1).\(o.2).\(o.3)"
    }
}

/// An IPv4 network: a base address and a prefix length.
///
/// The base is masked on construction, so `10.10.20.57/24` and `10.10.20.0/24` are the
/// same value. Normalization being a property of the type rather than a step a caller
/// remembers is what makes network-scoped identity keys reliable.
public struct IPv4Network: Hashable, Sendable, CustomStringConvertible {
    /// Already masked to `prefix` bits.
    public let base: UInt32
    /// Prefix length in bits, 0…32.
    public let prefix: UInt8

    /// Builds a network, masking the base and clamping the prefix to 32.
    public init(base: IPv4Address, prefix: UInt8) {
        let clamped = min(prefix, 32)
        let mask: UInt32 = clamped == 0 ? 0 : ~UInt32(0) << (32 - UInt32(clamped))
        self.base = base.raw & mask
        self.prefix = clamped
    }

    /// Parses CIDR text such as `10.10.20.0/24`. Returns nil for anything else.
    public init?(_ cidr: String) {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let address = IPv4Address(String(parts[0])),
              let prefix = UInt8(parts[1]), prefix <= 32
        else { return nil }
        self.init(base: address, prefix: prefix)
    }

    /// The netmask implied by the prefix.
    public var mask: UInt32 { prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix)) }

    /// The all-zeros host address.
    public var networkAddress: IPv4Address { IPv4Address(raw: base) }

    /// The all-ones host address.
    public var broadcastAddress: IPv4Address { IPv4Address(raw: base | ~mask) }

    /// Whether an address falls inside this network.
    public func contains(_ address: IPv4Address) -> Bool { address.raw & mask == base }

    /// Number of scannable addresses, without materializing them.
    public var hostCount: Int {
        let size = UInt64(~mask) + 1
        return prefix >= 31 ? Int(size) : Int(size >= 2 ? size - 2 : 0)
    }

    /// The narrowest prefix this type will enumerate address-by-address.
    ///
    /// A /16 is 65,534 addresses, which is a long scan but a real one. A /15 is twice
    /// that and a /8 is sixteen million — at which point enumerating into an array is
    /// not a scan strategy, it is an allocation failure waiting for a slow machine.
    public static let minimumEnumerablePrefix: UInt8 = 16

    /// Whether this network can be enumerated into an address list.
    public var isEnumerable: Bool { prefix >= Self.minimumEnumerablePrefix }

    /// Scannable hosts, excluding network and broadcast addresses for prefixes that
    /// have them. A /31 or /32 yields every address it covers.
    ///
    /// **Empty for a network wider than `minimumEnumerablePrefix`, and a caller must
    /// check `isEnumerable` rather than reading that emptiness as "no hosts".** This
    /// used to be the whole of the story and it was a silent wrong answer: a /8
    /// enumerated to zero addresses, which meant zero probes, which meant an outcome
    /// of `.complete` with an empty device list — the tool telling a user with sixteen
    /// million addressable hosts that their network was empty. The denial heuristic
    /// could not rescue it either, since that guards on `probesSent > 0`.
    ///
    /// `ScanTarget.resolution` is the safe entry point and refuses with a
    /// `Degradation`; `chunked(into:)` is the way to scan a wide network deliberately.
    public var hosts: [IPv4Address] {
        guard isEnumerable else { return [] }
        guard prefix < 31 else {
            return (base...(base | ~mask)).map(IPv4Address.init(raw:))
        }
        let first = base + 1
        let last = (base | ~mask) - 1
        guard first <= last else { return [] }
        return (first...last).map(IPv4Address.init(raw:))
    }

    /// Splits this network into enumerable sub-networks.
    ///
    /// The deliberate way to scan something wider than a /16: the caller decides to
    /// spend the time, and gets back pieces each of which is a real scan with its own
    /// budget and its own partial result. Returns `[self]` when already narrow enough.
    ///
    /// - Parameter prefix: the sub-network width. Clamped to at least
    ///   `minimumEnumerablePrefix`, and never narrower than this network is wide.
    public func chunked(into prefix: UInt8 = IPv4Network.minimumEnumerablePrefix) -> [IPv4Network] {
        let target = max(prefix, Self.minimumEnumerablePrefix)
        guard target > self.prefix else { return [self] }
        let step = UInt64(1) << (32 - UInt64(target))
        let span = UInt64(~mask) + 1
        return stride(from: UInt64(0), to: span, by: Int(step)).map {
            IPv4Network(base: IPv4Address(raw: base &+ UInt32($0)), prefix: target)
        }
    }

    /// CIDR text, which is also the wire encoding.
    public var description: String { "\(networkAddress)/\(prefix)" }
}
