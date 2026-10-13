// Apple-only, like the target it tests.
//
// `ZhenDarwin`'s sources are each wrapped this way so a Linux build produces an
// empty module rather than a failure. Its tests were not, which meant `swift test` could
// not run at all on Linux — so core's own tests, which are portable and are the ones
// worth running there, could only ever be compiled. Same rule, same reason.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// Real bytes off a real routing socket, captured once and committed.
///
/// A hand-built buffer would test the wrong thing. The hazard in this parser is
/// alignment and variable length — packed records at four-byte boundaries where
/// `sockaddr_dl`'s declared size is a lie — and a fixture assembled in Swift would be
/// laid out by Swift, not by the kernel.
enum Fixture {
    static func bytes(_ name: String) throws -> [UInt8] {
        let url = try #require(
            Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: "bin"),
            "fixture \(name).bin is missing"
        )
        return [UInt8](try Data(contentsOf: url))
    }
}

@Suite("Route messages parse from captured kernel bytes")
struct RouteMessageTests {
    @Test("The whole ARP table walks without desynchronising")
    func walksTheTable() throws {
        let bytes = try Fixture.bytes("arp-cache")
        let messages = unsafe RouteMessageParser.parse(bytes.span.bytes)
        // The capture holds ten messages. A parser that got ROUNDUP wrong would
        // desynchronise and produce garbage or stop early rather than miscount by one,
        // which is why the exact number is asserted.
        #expect(messages.count == 10)
        #expect(messages.allSatisfy { $0.destination != nil })
    }

    @Test("Hardware addresses come out of the variable-length sockaddr_dl")
    func extractsMACs() throws {
        let bytes = try Fixture.bytes("arp-cache")
        let messages = unsafe RouteMessageParser.parse(bytes.span.bytes)
        let byIP = Dictionary(
            messages.compactMap { message -> (IPv4Address, MACAddress)? in
                guard let ip = message.destination, let mac = message.linkAddress else { return nil }
                return (ip, mac)
            },
            uniquingKeysWith: { first, _ in first }
        )
        #expect(byIP[try #require(IPv4Address("10.10.20.1"))]?.description == "78:20:51:5E:07:28")
        #expect(byIP[try #require(IPv4Address("10.10.20.2"))]?.description == "C8:69:CD:5E:01:E1")
        // An unpadded octet — 00:92:... — is exactly the case the packed MACAddress
        // type exists for, and it appears in the real capture.
        #expect(byIP[try #require(IPv4Address("10.10.20.4"))]?.description == "00:92:35:5E:18:80")
    }

    @Test("An incomplete entry yields no hardware address")
    func incompleteEntry() throws {
        // 10.10.20.9 in the capture has sdl_alen == 0: an ARP request that got no
        // answer. It is evidence of ABSENCE, and reading past it — into whatever
        // followed in the buffer — would invent a MAC for a host that is not there.
        let bytes = try Fixture.bytes("arp-cache")
        let messages = unsafe RouteMessageParser.parse(bytes.span.bytes)
        let incomplete = messages.first { $0.destination == IPv4Address("10.10.20.9") }
        #expect(incomplete != nil)
        #expect(incomplete?.linkAddress == nil)
    }

    @Test("The routing table's default route is found")
    func findsDefaultRoute() throws {
        let bytes = try Fixture.bytes("route-dump")
        let messages = unsafe RouteMessageParser.parse(bytes.span.bytes)
        let defaults = messages.filter {
            $0.flags & RTF_UP != 0 && $0.flags & RTF_GATEWAY != 0
                && ($0.destination == nil || $0.destination?.raw == 0)
                && $0.gateway != nil
        }
        #expect(!defaults.isEmpty)
        #expect(defaults.first?.interfaceIndex ?? 0 > 0)
    }

    @Test("A full route dump walks too, which is a different message shape")
    func walksRouteDump() throws {
        let bytes = try Fixture.bytes("route-dump")
        let messages = unsafe RouteMessageParser.parse(bytes.span.bytes)
        #expect(messages.count > 100)
        // Desynchronisation shows up as absurd interface indices long before it shows
        // up as a wrong address.
        #expect(messages.allSatisfy { $0.interfaceIndex < 1000 })
    }

    @Test("Truncated input stops rather than reading past the end")
    func truncationIsSafe() throws {
        let bytes = try Fixture.bytes("arp-cache")
        // Every prefix of a valid buffer, including ones cutting a record in half.
        for cut in stride(from: 0, to: bytes.count, by: 7) {
            let prefix = Array(bytes[0..<cut])
            let messages = unsafe RouteMessageParser.parse(prefix.span.bytes)
            #expect(messages.count <= 10)
        }
    }

    @Test("Garbage does not loop forever or crash")
    func garbageIsSafe() {
        // A message claiming zero length would spin; one claiming a huge length would
        // read past the end. Both are guarded, and this is the test that says so.
        var evil = [UInt8](repeating: 0, count: 512)
        evil[0] = 0; evil[1] = 0                       // msglen 0
        #expect(unsafe RouteMessageParser.parse(evil.span.bytes).isEmpty)

        evil[0] = 0xFF; evil[1] = 0xFF                 // msglen 65535, past the end
        #expect(unsafe RouteMessageParser.parse(evil.span.bytes).isEmpty)

        var random = (0..<1024).map { _ in UInt8.random(in: 0...255) }
        _ = unsafe RouteMessageParser.parse(random.span.bytes)   // must simply return
        random[0] = 92; random[1] = 0
        _ = unsafe RouteMessageParser.parse(random.span.bytes)
    }

    @Test("ROUNDUP matches the kernel's macro, including the zero case")
    func roundUp() {
        // A zero-length sockaddr still advances a full word. Getting this wrong
        // desynchronises the entire rest of the buffer rather than corrupting one
        // field, which is why it is asserted separately from the walk.
        #expect(RouteMessageParser.roundUp(0) == 4)
        #expect(RouteMessageParser.roundUp(1) == 4)
        #expect(RouteMessageParser.roundUp(4) == 4)
        #expect(RouteMessageParser.roundUp(5) == 8)
        #expect(RouteMessageParser.roundUp(16) == 16)
        #expect(RouteMessageParser.roundUp(17) == 20)
    }
}

@Suite("The neighbour table is devices, not link-layer plumbing")
struct NeighborTableTests {
    @Test("Broadcast and multicast entries are not reported as devices")
    func filtersPlumbing() throws {
        // The capture contains 10.10.20.255 against ff:ff:ff:ff:ff:ff and 224.0.0.251
        // against 01:00:5e:00:00:fb — the subnet broadcast and the mDNS group. Both are
        // in every ARP table on every network, and a scanner that reported them would
        // invent two devices everywhere it ever looked. This is the test that caught it.
        let bytes = try Fixture.bytes("arp-cache")
        let entries = unsafe DarwinNeighborCache.decode(bytes.span.bytes)
        #expect(!entries.contains { $0.ip.description == "10.10.20.255" })
        #expect(!entries.contains { $0.ip.description == "224.0.0.251" })
        #expect(!entries.contains { $0.mac.isMulticast })
    }

    @Test("Real hosts survive, in address order")
    func keepsRealHosts() throws {
        let bytes = try Fixture.bytes("arp-cache")
        let entries = unsafe DarwinNeighborCache.decode(bytes.span.bytes)
        let complete = entries.filter(\.isComplete)
        #expect(complete.count == 7)
        #expect(complete.map(\.ip) == complete.map(\.ip).sorted())
        #expect(complete.first?.ip.description == "10.10.20.1")
    }

    @Test("An incomplete entry is kept and marked, because absence is evidence")
    func keepsIncompleteEntries() throws {
        let bytes = try Fixture.bytes("arp-cache")
        let entries = unsafe DarwinNeighborCache.decode(bytes.span.bytes)
        let incomplete = entries.first { $0.ip == IPv4Address("10.10.20.9") }
        #expect(incomplete?.isComplete == false)
    }
}

#endif
