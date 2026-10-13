import Foundation
import Testing
@testable import ZhenCore

// C1's gate: RFC 5952, the zone, and the 69 files that name `IPv4Address`.
//
// ── Why canonical text is the thing under test ────────────────────────────────
//
// `2001:db8::1`, `2001:0db8::1`, `2001:db8:0:0:0:0:0:1` and `2001:DB8::1` are one
// address written four ways. A tool that treats them as four strings reports one host as
// four devices, and a history store keyed on the text does it permanently. RFC 5952
// exists to settle that, and this suite is the RFC.

@Suite("RFC 5952 canonical form")
struct RFC5952Tests {
    /// Section 4's rules, each with the example the RFC gives for it.
    ///
    /// The left column is what may arrive; the right is the only thing this type will
    /// ever produce.
    static let canonical: [(input: String, canonical: String, rule: String)] = [
        // 4.1 — leading zeros suppressed.
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "4.1 leading zeros"),
        ("2001:0db8::0001", "2001:db8::1", "4.1 leading zeros"),
        // 4.2.1 — `::` must not replace a single zero group.
        ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1", "4.2.1 not one group"),
        // 4.2.2 — `::` replaces the longest run.
        ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1", "4.2.2 longest run"),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1", "4.2.3 leftmost on a tie"),
        // 4.3 — lowercase.
        ("2001:DB8::1", "2001:db8::1", "4.3 lowercase"),
        ("FE80::0202:B3FF:FE1E:8329", "fe80::202:b3ff:fe1e:8329", "4.3 lowercase"),
        // Whole-address edge cases.
        ("::", "::", "the unspecified address"),
        ("::1", "::1", "loopback"),
        ("0:0:0:0:0:0:0:1", "::1", "loopback, expanded"),
        ("0:0:0:0:0:0:0:0", "::", "unspecified, expanded"),
        ("ff02::1", "ff02::1", "all-nodes multicast"),
        ("2001:db8::", "2001:db8::", "trailing run"),
        ("::ffff:192.0.2.1", "::ffff:c000:201", "v4-mapped, as groups"),
    ]

    @Test("Every canonical-form example round-trips")
    func everyExample() throws {
        for example in Self.canonical {
            let parsed = try #require(IPv6Address(example.input),
                                      Comment(rawValue: "\(example.input) did not parse "
                                              + "(\(example.rule))"))
            #expect(parsed.description == example.canonical,
                    Comment(rawValue: "\(example.rule): \(example.input) rendered as "
                            + "\(parsed.description), expected \(example.canonical)"))
            // And the canonical form is a fixed point: parsing our own output gives the
            // same value and the same text. Without this, a round trip through the
            // history store could drift.
            let reparsed = try #require(IPv6Address(parsed.description))
            #expect(reparsed == parsed, Comment(rawValue: "\(example.canonical) is not stable"))
            #expect(reparsed.description == example.canonical)
        }
    }

    @Test("Four spellings of one address are one value")
    func spellingsCollapse() throws {
        let spellings = ["2001:db8::1", "2001:0db8::1", "2001:db8:0:0:0:0:0:1", "2001:DB8::1"]
        let parsed = try spellings.map { try #require(IPv6Address($0)) }
        #expect(Set(parsed).count == 1,
                Comment(rawValue: "\(Set(parsed).count) distinct values from one address"))
        #expect(Set(parsed.map(\.description)).count == 1)
    }

    @Test("What is refused")
    func rejections() {
        let bad = [
            "2001:db8::1::2",          // two `::`
            "2001:db8:0:0:0:0:0:1:2",  // nine groups
            "2001:db8:0:0:0:0:1",      // seven groups, no `::`
            "2001:dg8::1",             // not hex
            "2001:db8::12345",         // group too long
            "",
            "192.0.2.1",               // v4 is not v6
            "fe80::1%",                // an empty zone is not a zone
        ]
        for text in bad {
            #expect(IPv6Address(text) == nil,
                    Comment(rawValue: "'\(text)' parsed, and should not have"))
        }
    }

    @Test("A single zero group is never compressed, which is the rule most parsers get wrong")
    func neverCompressOneGroup() throws {
        let address = try #require(IPv6Address("2001:db8:0:1:1:1:1:1"))
        #expect(!address.description.contains("::"),
                Comment(rawValue: "compressed a single zero group: \(address.description)"))
    }

    @Test("The leftmost of two equal runs wins")
    func leftmostOnATie() throws {
        // Two runs of two. RFC 5952 4.2.3 says the first.
        let address = try #require(IPv6Address("2001:db8:0:0:1:0:0:1"))
        #expect(address.description == "2001:db8::1:0:0:1",
                Comment(rawValue: "got \(address.description)"))
    }
}

@Suite("The zone is part of the address")
struct ZoneIdentifierTests {
    @Test("fe80::1%en0 parses with its zone")
    func theGateExample() throws {
        let address = try #require(IPv6Address("fe80::1%en0"))
        #expect(address.zone == "en0")
        #expect(address.description == "fe80::1%en0")
        #expect(address.isLinkLocal)
    }

    /// **Two addresses differing only by zone are different destinations.**
    ///
    /// Every interface has its own link-local range, so the same `fe80::1` may exist on
    /// three of them. Collapsing them would merge three hosts into one.
    @Test("The same numbers on two links are two addresses")
    func zonesDoNotCollapse() throws {
        let first = try #require(IPv6Address("fe80::1%en0"))
        let second = try #require(IPv6Address("fe80::1%en1"))
        let bare = try #require(IPv6Address("fe80::1"))
        #expect(first != second)
        #expect(first != bare)
        #expect(Set([first, second, bare]).count == 3)
        // And they order stably rather than arbitrarily.
        #expect(bare < first && first < second)
    }

    @Test("A numeric zone, as Darwin hands them back")
    func numericZone() throws {
        let address = try #require(IPv6Address("fe80::1%1"))
        #expect(address.zone == "1")
        #expect(address.description == "fe80::1%1")
    }
}

@Suite("One address type over two families")
struct IPAddressEnumTests {
    @Test("Either family parses, and says which it is")
    func parsingBothFamilies() throws {
        let v4 = try #require(IPAddress("10.10.20.1"))
        let v6 = try #require(IPAddress("fe80::1%en0"))
        #expect(v4.family == .v4)
        #expect(v6.family == .v6)
        #expect(v4.v4 == IPv4Address("10.10.20.1"))
        #expect(v6.v6?.zone == "en0")
        #expect(v4.description == "10.10.20.1")
        #expect(v6.description == "fe80::1%en0")
    }

    @Test("Ordering is stable and puts v4 first")
    func ordering() throws {
        let addresses = try ["fe80::2", "10.10.20.8", "::1", "10.10.20.1"]
            .map { try #require(IPAddress($0)) }
        let sorted = addresses.sorted()
        #expect(sorted.map(\.description) == ["10.10.20.1", "10.10.20.8", "::1", "fe80::2"],
                Comment(rawValue: "got \(sorted.map(\.description))"))
        // Sorting twice gives the same answer, which is what a reproducible artifact
        // needs and what an arbitrary cross-family comparison would not give.
        #expect(sorted.sorted() == sorted)
    }

    @Test("Round trips through JSON as plain text")
    func wireForm() throws {
        for text in ["10.10.20.1", "fe80::1%en0", "2001:db8::1", "::1"] {
            let address = try #require(IPAddress(text))
            let data = try JSONEncoder().encode(address)
            // Plain text, not a tagged object: `jq` over an artifact should not need to
            // know this type exists.
            #expect(String(data: data, encoding: .utf8) == "\"\(text)\"",
                    Comment(rawValue: "encoded as \(String(data: data, encoding: .utf8) ?? "?")"))
            let decoded = try JSONDecoder().decode(IPAddress.self, from: data)
            #expect(decoded == address)
        }
    }

    @Test("A group or a placeholder is not an addressable host")
    func multicastAndFriends() throws {
        // The neighbour table lists every group the machine has joined; reading those
        // as hosts invents devices on every network.
        #expect(try #require(IPAddress("ff02::1")).isAddressableHost == false)
        #expect(try #require(IPAddress("224.0.0.251")).isAddressableHost == false)
        #expect(try #require(IPAddress("::1")).isAddressableHost == false)
        #expect(try #require(IPAddress("::")).isAddressableHost == false)
        #expect(try #require(IPAddress("127.0.0.1")).isAddressableHost == false)
        #expect(try #require(IPAddress("fe80::1%en0")).isAddressableHost)
        #expect(try #require(IPAddress("10.10.20.1")).isAddressableHost)
    }

    @Test("A v4-mapped address is reported as mapped, not silently unwrapped")
    func mappedIsNotFlattened() throws {
        let mapped = try #require(IPv6Address("::ffff:192.0.2.1"))
        #expect(mapped.mappedIPv4 == IPv4Address("192.0.2.1"))
        // Still a v6 value. A socket handing back a mapped address is telling you the
        // peer is v4, and flattening it on the way in loses the one fact worth keeping.
        #expect(IPAddress.v6(mapped).v4 == nil)
        #expect(IPAddress.v6(mapped).family == .v6)
    }

    @Test("Link-local, multicast and loopback are recognised")
    func scopes() throws {
        #expect(try #require(IPv6Address("fe80::1")).isLinkLocal)
        #expect(try #require(IPv6Address("febf:ffff::")).isLinkLocal)
        #expect(try #require(IPv6Address("2001:db8::1")).isLinkLocal == false)
        #expect(try #require(IPv6Address("ff02::1")).isMulticast)
        #expect(try #require(IPv6Address("::1")).isLoopback)
        #expect(try #require(IPv6Address("::")).isUnspecified)
    }

    @Test("Bytes round-trip, which is what a socket hands over")
    func byteForm() throws {
        let address = try #require(IPv6Address("2001:db8::1"))
        #expect(address.bytes.count == 16)
        #expect(address.bytes.first == 0x20 && address.bytes.last == 0x01)
        #expect(IPv6Address(bytes: address.bytes) == address)
        #expect(IPv6Address(bytes: [0, 1]) == nil)
    }
}
