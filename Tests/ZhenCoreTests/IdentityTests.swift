import Foundation
import Testing
@testable import ZhenCore

@Suite("Identification and stability are two different numbers")
struct IdentityTests {
    static let network = IPv4Network("10.10.20.0/24")!

    private func device(_ facts: HostFacts) -> Device {
        Device(observing: facts, in: Self.network, lastSeen: Timestamp(millisecondsSinceEpoch: 0))
    }

    // ── The real network, from the specification's device table ──────────────────

    @Test("A Bonjour name alone identifies a device, even behind a rotating MAC")
    func bonjourNameIdentifies() throws {
        // 10.10.20.3, JC's MacBook Pro: named over mDNS, randomized MAC, no vendor
        // and no model. The brief is explicit that this reads as identified.
        let macbook = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.3")),
            mac: try MACAddress.required("DA:5C:22:81:F3:0A"),
            allNames: [NameCandidate(value: "JC's MacBook Pro", source: .mdns)]
        ))
        #expect(macbook.identification == .identified)
        #expect(macbook.vendor == nil)

        // And yet the record is only moderately stable: the MAC rotates, so the
        // Bonjour instance name is the only thing holding it together across runs.
        #expect(macbook.identityStability == .moderate)
    }

    @Test("A device named only by its model string is partial, however stable its MAC")
    func modelStringIsNotAName() throws {
        // 10.10.20.1, the ER7206 gateway: burned-in MAC, no friendly name anywhere,
        // and the only name available is the model echoed back.
        let gateway = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.1")),
            mac: try MACAddress.required("30:DE:4B:77:A2:10"),
            allNames: [NameCandidate(value: "ER7206", source: .ssdp, model: "ER7206")],
            vendor: "TP-Link Systems"
        ))
        #expect(gateway.identification == .partial)
        // The exact inverse of the MacBook: we barely know what it is, and the record
        // will never fragment.
        #expect(gateway.identityStability == .strong)
    }

    @Test("The two confidences disagree in both directions, which is why there are two")
    func confidencesAreIndependent() throws {
        let macbook = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.3")),
            mac: try MACAddress.required("DA:5C:22:81:F3:0A"),
            allNames: [NameCandidate(value: "JC's MacBook Pro", source: .mdns)]
        ))
        let gateway = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.1")),
            mac: try MACAddress.required("30:DE:4B:77:A2:10"),
            vendor: "TP-Link Systems"
        ))

        // Better identified, less stable.
        #expect(macbook.identification < gateway.identification)
        #expect(gateway.identityStability < macbook.identityStability)
        // Collapsing these into one field would have to lose one of these two facts.
    }

    @Test("A vendor alone is partial; nothing at all is minimal")
    func vendorOnlyAndNothingAtAll() throws {
        let appleish = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.7")),
            mac: try MACAddress.required("A8:51:AB:2F:19:6C"),
            vendor: "Apple"
        ))
        #expect(appleish.identification == .partial)

        let anonymous = device(HostFacts(ip: try #require(IPv4Address("10.10.20.8"))))
        #expect(anonymous.identification == .minimal)
        // Minimal is a normal row, not an error state.
        #expect(anonymous.names.isEmpty)
    }

    @Test("A TTL is enough evidence to lift a device off minimal")
    func ttlIsFreeEvidence() throws {
        let ttlOnly = device(HostFacts(ip: try #require(IPv4Address("10.10.20.9")), ttl: 64))
        #expect(ttlOnly.osHint == .unixLike)
        #expect(ttlOnly.identification == .partial)
    }

    @Test("TTL bands hint at an OS, and an unrecognized value hints at nothing")
    func ttlBands() {
        #expect(OSHint(ttl: 64) == .unixLike)
        #expect(OSHint(ttl: 63) == .unixLike)        // one hop
        #expect(OSHint(ttl: 128) == .windows)
        #expect(OSHint(ttl: 255) == .networkDevice)
        #expect(OSHint(ttl: 254) == .networkDevice)
        // Between the bands: honest silence rather than a guess.
        #expect(OSHint(ttl: 80) == nil)
        #expect(OSHint(ttl: 200) == nil)
    }

    // ── How many independent sources agree ───────────────────────────────────────

    @Test("A reverse-DNS name alone is not an identification")
    func reverseDNSAloneIsPartial() throws {
        // "10-10-20-8.lan" looks like a name and identifies nothing.
        let guessed = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.8")),
            allNames: [NameCandidate(value: "10-10-20-8.lan", source: .dns)]
        ))
        #expect(guessed.identification == .partial)
    }

    @Test("A second independent source promotes a weak name to an identification")
    func corroborationPromotes() throws {
        let corroborated = device(HostFacts(
            ip: try #require(IPv4Address("10.10.20.8")),
            allNames: [
                NameCandidate(value: "officeprinter.lan", source: .dns),
                NameCandidate(value: "OFFICEPRINTER", source: .netbios),
            ]
        ))
        #expect(corroborated.identificationEvidence.independentSources == 2)
        #expect(corroborated.identification == .identified)
    }

    @Test("The evidence behind the verdict is carried, so it can be shown not asserted")
    func evidenceIsCarried() throws {
        let facts = HostFacts(
            ip: try #require(IPv4Address("10.10.20.2")),
            allNames: [NameCandidate(value: "Sala de entretenimiento", source: .mdns, rank: 1, model: "AppleTV5,3")],
            vendor: "Apple, Inc.",
            ttl: 64
        )
        let evidence = IdentificationEvidence(facts: facts)
        #expect(evidence.hasDistinctName)
        #expect(evidence.nameSourceIsSelfSufficient)
        #expect(evidence.hasModel)
        #expect(evidence.hasVendor)
        #expect(evidence.hasOSHint)
        #expect(Identification(evidence: evidence) == .identified)
    }

    // ── Join keys and stability ──────────────────────────────────────────────────

    @Test("The locally administered bit, not the caller, decides whether a MAC is a key")
    func macKindComesFromTheAddress() throws {
        let stable = HostIdentifier.fromMAC(try MACAddress.required("30:DE:4B:77:A2:10"))
        #expect(stable.kind == .universalMAC)
        #expect(stable.weight == 100)

        let rotating = HostIdentifier.fromMAC(try MACAddress.required("DA:5C:22:81:F3:0A"))
        #expect(rotating.kind == .randomizedMAC)
        #expect(rotating.weight == 30)
    }

    @Test("An mDNS instance outranks a randomized MAC, which is what keeps a phone one device")
    func mdnsOutranksRandomizedMAC() {
        #expect(HostIdentifierKind.mdnsInstance.weight > HostIdentifierKind.randomizedMAC.weight)
        #expect(HostIdentifierKind.mdnsInstance < HostIdentifierKind.randomizedMAC)
    }

    @Test("Candidate keys come out strongest first and deduplicated")
    func candidateKeysAreOrdered() throws {
        let facts = HostFacts(
            ip: try #require(IPv4Address("10.10.20.4")),
            mac: try MACAddress.required("F2:3A:91:6B:0D:44"),
            allNames: [
                NameCandidate(value: "Mac Studio de Jose", source: .mdns, rank: 1),
                // Same instance from a second service type, differing only in case.
                NameCandidate(value: "mac studio de jose", source: .mdns, rank: 4),
            ],
            dhcpHostname: "mac-studio"
        )
        let keys = HostIdentifier.candidates(for: facts, in: Self.network)
        #expect(keys.map(\.kind) == [.mdnsInstance, .dhcpHostname, .randomizedMAC, .ipLease])
        // Two spellings of one Bonjour name must collapse, or the join silently splits.
        #expect(keys.filter { $0.kind == .mdnsInstance }.count == 1)
    }

    @Test("Stability comes from the strongest key available")
    func stabilityFromStrongestKey() throws {
        let universal = HostIdentifier.fromMAC(try MACAddress.required("30:DE:4B:77:A2:10"))
        let mdns = HostIdentifier.mdnsInstance("Mac Studio de Jose")
        let random = HostIdentifier.fromMAC(try MACAddress.required("DA:5C:22:81:F3:0A"))
        let lease = HostIdentifier.ipLease(try #require(IPv4Address("10.10.20.8")), in: Self.network)

        #expect(Stability(strongestOf: [universal, random, lease]) == .strong)
        #expect(Stability(strongestOf: [mdns, random, lease]) == .moderate)
        #expect(Stability(strongestOf: [random, lease]) == .weak)
        #expect(Stability(strongestOf: [lease]) == .ephemeral)
        #expect(Stability(strongestOf: [HostIdentifier]()) == .ephemeral)
    }

    @Test("An address key is scoped to its network, so two LANs do not merge")
    func leaseKeysAreScoped() throws {
        let home = IPv4Network("192.168.1.0/24")!
        let office = IPv4Network("10.10.20.0/24")!
        let address = try #require(IPv4Address("192.168.1.10"))
        let otherAddress = try #require(IPv4Address("10.10.20.10"))
        #expect(HostIdentifier.ipLease(address, in: home)
                != HostIdentifier.ipLease(otherAddress, in: office))
    }
}
