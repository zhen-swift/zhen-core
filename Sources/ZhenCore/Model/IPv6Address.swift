// IPv6Address.swift — 128 bits, a zone, and RFC 5952 text.
//
// ── Why the text rules are a type's job and not a caller's ────────────────────
//
// `2001:db8::1`, `2001:0db8::1`, `2001:db8:0:0:0:0:0:1` and `2001:DB8::1` are the same
// address written four ways. A tool that treats them as four strings reports one host as
// four devices, and a history store keyed on the text does it permanently.
//
// RFC 5952 settles it: lowercase, leading zeros suppressed, `::` over the LONGEST run of
// zero groups, leftmost on a tie, and never over a single group. `description` is that
// form and nothing else produces text, so two spellings of one address cannot survive
// being parsed.
//
// ── The zone, and why it is part of the address ───────────────────────────────
//
// `fe80::1` is not an address you can connect to. Every interface has its own link-local
// range and the same `fe80::1` may exist on three of them, so the zone — `%en0` — is
// what makes it routable. It is carried here rather than beside here because an address
// without it is ambiguous, and a type that can represent an ambiguous value will be
// handed one.
//
// **The zone is not part of identity for ordering or equality of the numeric address.**
// Two values differing only by zone are different values, because they are different
// destinations.

import Foundation

/// A 128-bit IPv6 address, with an optional zone identifier.
public struct IPv6Address: Hashable, Sendable, Comparable, CustomStringConvertible {
    /// The high 64 bits, host order.
    public let high: UInt64
    /// The low 64 bits, host order.
    public let low: UInt64
    /// The zone, without the `%`. Nil for anything that is not link-local scoped.
    public let zone: String?

    /// Wraps a packed value.
    public init(high: UInt64, low: UInt64, zone: String? = nil) {
        self.high = high
        self.low = low
        self.zone = zone
    }

    /// The sixteen bytes, most significant first.
    ///
    /// **Written as loops with explicit types on purpose.** The obvious spelling —
    /// two `map`s over a range, concatenated, with the shift arithmetic inline — type
    /// checks on macOS and defeats the Linux compiler outright: *"unable to type-check
    /// this expression in reasonable time"*. `verify-linux.sh` caught it, which is what
    /// the Linux job is for, and the fix is to stop making the inference engine solve a
    /// puzzle it does not need to solve.
    public var bytes: [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(16)
        for index in 0..<8 {
            let shift: UInt64 = UInt64(56 - 8 * index)
            result.append(UInt8((high >> shift) & 0xFF))
        }
        for index in 0..<8 {
            let shift: UInt64 = UInt64(56 - 8 * index)
            result.append(UInt8((low >> shift) & 0xFF))
        }
        return result
    }

    /// The eight 16-bit groups, most significant first. See `bytes` on the spelling.
    public var groups: [UInt16] {
        var result: [UInt16] = []
        result.reserveCapacity(8)
        for index in 0..<4 {
            let shift: UInt64 = UInt64(48 - 16 * index)
            result.append(UInt16((high >> shift) & 0xFFFF))
        }
        for index in 0..<4 {
            let shift: UInt64 = UInt64(48 - 16 * index)
            result.append(UInt16((low >> shift) & 0xFFFF))
        }
        return result
    }

    /// Builds from sixteen bytes. Nil unless there are exactly sixteen.
    public init?(bytes: [UInt8], zone: String? = nil) {
        guard bytes.count == 16 else { return nil }
        var high: UInt64 = 0, low: UInt64 = 0
        for index in 0..<8 { high = (high << 8) | UInt64(bytes[index]) }
        for index in 8..<16 { low = (low << 8) | UInt64(bytes[index]) }
        self.init(high: high, low: low, zone: zone)
    }

    // MARK: Scope

    /// `fe80::/10`. The address every modern host self-assigns, and the reason IPv6
    /// discovery works on a link where nothing is configured.
    public var isLinkLocal: Bool { (high >> 54) == 0x3FA }

    /// `ff00::/8`. A multicast group is not a device — the same reason the v4 type
    /// carries this: the neighbour table lists every group the machine has joined.
    public var isMulticast: Bool { (high >> 56) == 0xFF }

    /// `::1`.
    public var isLoopback: Bool { high == 0 && low == 1 }

    /// `::`, which is never a host.
    public var isUnspecified: Bool { high == 0 && low == 0 }

    /// `::ffff:0:0/96` — an IPv4 address carried in a v6 field.
    ///
    /// Reported rather than silently unwrapped. A socket that hands back a mapped
    /// address is telling you the peer is v4, and flattening that on the way in would
    /// lose the one fact worth keeping.
    public var mappedIPv4: IPv4Address? {
        guard high == 0, (low >> 32) == 0xFFFF else { return nil }
        return IPv4Address(raw: UInt32(low & 0xFFFF_FFFF))
    }

    // MARK: Text

    /// Parses RFC 4291 text, in any of its spellings, with an optional `%zone`.
    public init?(_ text: String) {
        var body = text
        var zone: String?
        // The zone comes off first: it may contain characters the address grammar
        // would choke on, and on Darwin it is routinely a numeric index.
        if let separator = body.firstIndex(of: "%") {
            zone = String(body[body.index(after: separator)...])
            body = String(body[..<separator])
            if zone?.isEmpty == true { return nil }
        }
        guard !body.isEmpty, body.count <= 45 else { return nil }

        // A trailing dotted quad, as in `::ffff:192.0.2.1`, becomes two groups.
        var trailing: [UInt16] = []
        if let lastColon = body.lastIndex(of: ":"), body[body.index(after: lastColon)...].contains(".") {
            let quad = String(body[body.index(after: lastColon)...])
            guard let v4 = IPv4Address(quad) else { return nil }
            trailing = [UInt16(v4.raw >> 16), UInt16(v4.raw & 0xFFFF)]
            body = String(body[...lastColon])
        }

        var groups: [UInt16] = []
        if let range = body.range(of: "::") {
            // Exactly one `::` is allowed, and a second is what makes an address
            // ambiguous rather than merely ugly.
            let rest = body[range.upperBound...]
            if rest.contains("::") { return nil }
            let leftText = String(body[..<range.lowerBound])
            let rightText = String(rest)
            guard let left = Self.parseGroups(leftText), let right = Self.parseGroups(rightText)
            else { return nil }
            // `filled` already counts the trailing quad's two groups, so the zero run
            // is `8 - filled` and nothing else. Subtracting the quad a second time here
            // produced six groups for `::ffff:192.0.2.1` and the parse simply failed.
            let filled = left.count + right.count + trailing.count
            guard filled <= 7 else { return nil }  // `::` must cover at least one group
            groups = left + Array(repeating: 0, count: 8 - filled) + right + trailing
        } else {
            guard let parsed = Self.parseGroups(body) else { return nil }
            groups = parsed + trailing
        }
        guard groups.count == 8 else { return nil }

        var high: UInt64 = 0, low: UInt64 = 0
        for index in 0..<4 { high = (high << 16) | UInt64(groups[index]) }
        for index in 4..<8 { low = (low << 16) | UInt64(groups[index]) }
        self.init(high: high, low: low, zone: zone)
    }

    /// Colon-separated hex groups, or nil if any piece is not one.
    private static func parseGroups(_ text: String) -> [UInt16]? {
        guard !text.isEmpty else { return [] }
        var trimmed = text
        if trimmed.hasPrefix(":") { trimmed.removeFirst() }
        if trimmed.hasSuffix(":") { trimmed.removeLast() }
        guard !trimmed.isEmpty else { return [] }
        var groups: [UInt16] = []
        for piece in trimmed.split(separator: ":", omittingEmptySubsequences: false) {
            guard !piece.isEmpty, piece.count <= 4,
                  piece.allSatisfy(\.isHexDigit),
                  let value = UInt16(piece, radix: 16)
            else { return nil }
            groups.append(value)
        }
        return groups
    }

    /// RFC 5952 canonical form, with the zone appended when there is one.
    ///
    /// The four rules, in the order they are applied: lowercase hex, leading zeros
    /// suppressed, `::` over the longest run of zero groups, and never `::` over a run
    /// of one — because `2001:db8:0:1:1:1:1:1` is shorter to read than the alternative
    /// and the RFC says so.
    public var description: String {
        let groups = self.groups
        var bestStart = -1, bestLength = 0
        var runStart = -1, runLength = 0
        for (index, group) in groups.enumerated() {
            if group == 0 {
                if runStart < 0 { runStart = index; runLength = 1 } else { runLength += 1 }
                // Strictly greater, so the LEFTMOST of two equal runs wins.
                if runLength > bestLength { bestStart = runStart; bestLength = runLength }
            } else {
                runStart = -1; runLength = 0
            }
        }
        var text = ""
        if bestLength >= 2 {
            let head = groups[..<bestStart].map { String($0, radix: 16) }.joined(separator: ":")
            let tail = groups[(bestStart + bestLength)...]
                .map { String($0, radix: 16) }.joined(separator: ":")
            text = head + "::" + tail
        } else {
            text = groups.map { String($0, radix: 16) }.joined(separator: ":")
        }
        return zone.map { "\(text)%\($0)" } ?? text
    }

    /// Numeric order, zone last, so a report iterates a link the way a person reads it.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.high != rhs.high { return lhs.high < rhs.high }
        if lhs.low != rhs.low { return lhs.low < rhs.low }
        return (lhs.zone ?? "") < (rhs.zone ?? "")
    }
}
