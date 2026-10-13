// DiscoverySourceTests.swift — the provenance a discovery result now carries.
//
// These exist because the artifact could not answer a question that was put to it. A
// measurement study compared `hosts_found` against the echo replies in a packet capture
// and found them disagreeing in 431 of 485 runs. Settling it took the raw pcaps, and the
// answer was that two of the study's hosts answered ARP and ignored ICMP, so they were
// reported from the kernel's neighbour table having never sent a frame the capture could
// have seen. That is the engine working correctly and an artifact failing to say so.

import Foundation
import Testing
@testable import ZhenCore

@Suite("A found host says how it was found")
struct DiscoverySourceTests {
    static let ip = IPv4Address("10.0.0.7")!

    @Test("A host from the neighbour table is distinguishable from one that answered")
    func neighbourIsDistinguishable() {
        // The defect, stated as a test. Before this, these two were the same shape and a
        // reader holding a packet capture could not tell which was which.
        let answered = HostFacts(ip: Self.ip, discoveredVia: [.probeReply])
        let remembered = HostFacts(ip: Self.ip, discoveredVia: [.neighborTable])
        #expect(answered.discoveredVia != remembered.discoveredVia)

        // The predicate a reader reconciling against a capture actually wants: whose
        // frames should be on the wire.
        #expect(answered.discoveredVia.answeredThisScan)
        #expect(!remembered.discoveredVia.answeredThisScan)
    }

    @Test("This machine's own address is marked, because a capture can never show it")
    func localInterfaceIsMarked() {
        // A probe a host sends to its own address is answered inside the kernel and
        // never reaches the interface. Measured: three pings to this machine's own
        // address, three replies, zero frames captured. The mark is what stops the next
        // person hunting a phantom that is really the scanner looking at itself.
        let own = HostFacts(
            ip: Self.ip,
            discoveredVia: Set<DiscoverySource>([.probeReply, .localInterface])
        )
        #expect(own.discoveredVia.contains(.localInterface))
        // It did answer — the reply is real, it just took the short path.
        #expect(own.discoveredVia.answeredThisScan)
    }

    @Test("Sources encode in a stable order, so two identical scans compare equal")
    func canonicalOrder() throws {
        // A Set has no order of its own, and the synthesized encoder would emit whatever
        // the hash seed produced that run. `allNames` and `ports` are sorted for exactly
        // this reason; an unstable artifact is not diffable.
        let host = HostFacts(
            ip: Self.ip,
            discoveredVia: Set<DiscoverySource>(
                [.localInterface, .neighborTable, .probeReply, .arpReply]
            )
        )
        // `.sortedKeys` because JSONEncoder does not otherwise fix the ORDER OF KEYS —
        // it fills a dictionary, so two encodes of the same value can differ byte for
        // byte no matter what this type does. That is the encoder's business. What this
        // type owes is a stable order WITHIN `discovered_via`, which is what the
        // substring below pins.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let first = try encoder.encode(host)
        let second = try encoder.encode(host)
        #expect(first == second)

        let text = String(decoding: try encoder.encode(host), as: UTF8.self)
        #expect(text.contains(
            #""discovered_via":["probe_reply","arp_reply","neighbor_table","local_interface"]"#
        ))
    }

    @Test("Provenance survives the round trip, and an older artifact decodes as unstated")
    func roundTrip() throws {
        let host = HostFacts(
            ip: Self.ip, discoveredVia: Set<DiscoverySource>([.arpReply, .probeReply])
        )
        let decoded = try JSONDecoder().decode(
            HostFacts.self, from: try JSONEncoder().encode(host)
        )
        #expect(decoded.discoveredVia == Set<DiscoverySource>([.probeReply, .arpReply]))

        // An artifact written before this field existed says nothing about provenance,
        // which decodes as an empty set — not as a claim that nothing found the host.
        let old = #"{"ip":"10.0.0.7","all_names":[],"ports":[]}"#
        let older = try JSONDecoder().decode(HostFacts.self, from: Data(old.utf8))
        let sources = older.discoveredVia
        #expect(sources.isEmpty)
        #expect(!sources.answeredThisScan)
    }

    @Test("A merge unions the routes rather than preferring one")
    func mergeUnions() {
        // The composite engine's whole output. Two engines reaching the same host by two
        // independent routes is the strongest statement it can make, and keeping only
        // the stronger would throw away the agreement.
        let viaICMP = HostFacts(ip: Self.ip, ttl: 64, discoveredVia: [.probeReply])
        let viaARP = HostFacts(
            ip: Self.ip, mac: MACAddress("aa:bb:cc:00:11:22"),
            discoveredVia: [.arpReply]
        )
        let merged = viaICMP.merged(with: viaARP)
        #expect(merged.discoveredVia == Set<DiscoverySource>([.probeReply, .arpReply]))
        // And the merge still carries what each side knew.
        #expect(merged.ttl == 64)
        #expect(merged.mac != nil)
    }
}
