// IPAddress.swift — one address type over two families.
//
// `IPv4Address` is unchanged and becomes a case. That is deliberate and it is what makes
// C1 additive: 69 files name `IPv4Address` and none of them has to move for this stage
// to land. `Device.addresses` is C2's job.
//
// ── Ordering across families ──────────────────────────────────────────────────
//
// v4 before v6, then numerically within each. There is no natural order between
// families — an address is not larger or smaller than one in a different space — so the
// choice is arbitrary and the reason for making it is not: a report has to iterate in a
// stable, reproducible order or two runs of the same scan produce two different
// documents. v4 first because a dual-stack host's v4 address is the one a person
// recognises.

import Foundation

/// An address in either family.
public enum IPAddress: Hashable, Sendable, Comparable, CustomStringConvertible {
    case v4(IPv4Address)
    case v6(IPv6Address)

    /// The v4 address, if this is one. Nil for v6, including a v4-mapped v6 —
    /// see `mappedIPv4`, which is a different question deliberately.
    public var v4: IPv4Address? {
        if case .v4(let address) = self { return address }
        return nil
    }

    /// The v6 address, if this is one.
    public var v6: IPv6Address? {
        if case .v6(let address) = self { return address }
        return nil
    }

    /// Which family this is, for an artifact that has to say.
    public var family: AddressFamily {
        switch self {
        case .v4: .v4
        case .v6: .v6
        }
    }

    /// Parses either family. A dotted quad is v4; anything with a colon is v6.
    ///
    /// The colon is the discriminator rather than a try-both-and-see, because
    /// `IPv6Address` accepts a trailing dotted quad — `::ffff:192.0.2.1` — and trying v6
    /// first would make `192.0.2.1` ambiguous to a reader of this function even though
    /// it is not ambiguous to the parsers.
    public init?(_ text: String) {
        if text.contains(":") {
            guard let address = IPv6Address(text) else { return nil }
            self = .v6(address)
        } else {
            guard let address = IPv4Address(text) else { return nil }
            self = .v4(address)
        }
    }

    /// Whether this address is a device rather than a group or a placeholder.
    ///
    /// The neighbour table lists every multicast group the machine has joined, and a
    /// scanner that read those as hosts would invent devices on every network it saw.
    /// The same reasoning as `IPv4Address.isMulticast`, applied across both families so
    /// the caller does not have to switch.
    public var isAddressableHost: Bool {
        switch self {
        case .v4(let address): !address.isMulticast && !address.isLoopback
        case .v6(let address):
            !address.isMulticast && !address.isLoopback && !address.isUnspecified
        }
    }

    /// v4 before v6, numeric within each. See the file header for why the cross-family
    /// order is arbitrary and why it still has to exist.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.v4(let left), .v4(let right)): left < right
        case (.v6(let left), .v6(let right)): left < right
        case (.v4, .v6): true
        case (.v6, .v4): false
        }
    }

    /// The address as text: dotted quad, or RFC 5952 canonical form with its zone.
    public var description: String {
        switch self {
        case .v4(let address): address.description
        case .v6(let address): address.description
        }
    }
}

/// Which address family an observation belongs to.
///
/// Spelled out on the wire, because `4` and `6` as integers invite arithmetic and this
/// is a label.
public enum AddressFamily: String, Sendable, Hashable, CaseIterable, Codable {
    case v4 = "ipv4"
    case v6 = "ipv6"
}

// MARK: - Wire form

/// Encoded as its text, not as a pair of fields.
///
/// A tagged object — `{"family":"ipv6","value":"fe80::1"}` — would be more obviously
/// self-describing and is the wrong choice here: `"10.10.20.1"` is already
/// unambiguous, it is what every other tool on a network emits, and `jq` over an
/// artifact should not need to know this type exists. The family is derivable from the
/// text and is carried separately where a consumer needs to filter on it.
extension IPAddress: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let address = IPAddress(text) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "'\(text)' is not an IP address")
        }
        self = address
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension IPv6Address: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let address = IPv6Address(text) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "'\(text)' is not an IPv6 address")
        }
        self = address
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
