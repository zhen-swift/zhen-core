// Apple-only, like the target it tests.
//
// What an iPadOS build of the scanner is, and the parts of it that are pure enough to
// check on macOS too: a sweep that has no neighbour table must neither read one nor claim
// one, and an interface has to be chosen without a routing table to ask.
#if canImport(Darwin)

import Foundation
import Synchronization
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

/// A neighbour cache that counts its reads, readable or not as the test says.
private final class CountingNeighborCache: NeighborCache {
    let isReadable: Bool
    private let reads = Mutex(0)

    init(isReadable: Bool) { self.isReadable = isReadable }

    var readCount: Int { reads.withLock { $0 } }

    func entries() async throws(PlatformError) -> [NeighborEntry] {
        reads.withLock { $0 += 1 }
        return []
    }
}

@Suite("A platform without a neighbour table")
struct NoNeighborTableTests {
    @Test("The sweep does not claim a table it cannot read")
    func descriptorIsHonest() {
        let without = ICMPSweepEngine(neighbors: UnavailableNeighborCache()).descriptor
        #expect(without.capabilities == [.icmpSweep])
        #expect(without.kind == .unprivileged)

        let with = ICMPSweepEngine(neighbors: CountingNeighborCache(isReadable: true)).descriptor
        #expect(with.capabilities == [.icmpSweep, .neighborTable])
    }

    @Test("The sweep never reads it, and does not report its absence as a degradation")
    func neverRead() async {
        // Loopback, one address, a short budget: the point is what the sweep does with
        // the table, not what it finds. The readable cache is the control — without it,
        // a sweep that refused the target before reaching the table would pass too.
        let interface = NetworkInterface(
            name: "lo0", address: IPv4Address("127.0.0.1")!,
            network: IPv4Network("127.0.0.1/32")!
        )
        let target = ScanTarget(scanning: interface)

        let readable = CountingNeighborCache(isReadable: true)
        let control = await ICMPSweepEngine(neighbors: readable, neighborWatch: true)
            .discover(target, deadline: Deadline(after: .milliseconds(400)))
        #expect(readable.readCount >= 1, "the control never reached the table")
        #expect(control.usedCapabilities.contains(.neighborTable))

        let unreadable = CountingNeighborCache(isReadable: false)
        let result = await ICMPSweepEngine(neighbors: unreadable, neighborWatch: true)
            .discover(target, deadline: Deadline(after: .milliseconds(400)))
        #expect(unreadable.readCount == 0)
        #expect(!result.usedCapabilities.contains(.neighborTable))
        #expect(!result.degradations.contains { $0.reason.contains("neighbour table") })
        #expect(result.neighborWatch == .disabled, "a watch over nothing was reported as on")
    }

    @Test("An accidental read says what it ran into")
    func accidentalRead() async {
        await #expect(throws: PlatformError.unavailable("none here")) {
            _ = try await UnavailableNeighborCache(reason: "none here").entries()
        }
    }
}

@Suite("Choosing an interface without a routing table")
struct InterfaceWithoutRoutesTests {
    private func interface(_ name: String, _ address: String) -> NetworkInterface {
        NetworkInterface(
            name: name, address: IPv4Address(address)!,
            network: IPv4Network(base: IPv4Address(address)!, prefix: 24)
        )
    }

    @Test("Wi-Fi wins over cellular, a VPN and the hotspot bridge, whatever their order")
    func wifiFirst() {
        let chosen = DarwinInterfaceProvider.preferredWithoutRoutes([
            interface("pdp_ip0", "100.64.1.2"),
            interface("utun3", "10.8.0.2"),
            interface("bridge100", "172.20.10.1"),
            interface("en0", "10.10.20.31"),
        ])
        #expect(chosen.name == "en0")
    }

    @Test("Ties keep enumeration order, and an unknown kind beats the ones known to be wrong")
    func ties() {
        #expect(DarwinInterfaceProvider.preferredWithoutRoutes([
            interface("en2", "192.168.1.5"), interface("en0", "10.10.20.31"),
        ]).name == "en2")
        #expect(DarwinInterfaceProvider.preferredWithoutRoutes([
            interface("pdp_ip0", "100.64.1.2"), interface("ap1", "192.168.2.1"),
        ]).name == "ap1")
        #expect(DarwinInterfaceProvider.preferredWithoutRoutes([
            interface("pdp_ip0", "100.64.1.2"),
        ]).name == "pdp_ip0")
    }
}

#if !os(macOS)
@Suite("The iPadOS composition")
struct IPadCompositionTests {
    @Test("Unprivileged engines only, with nothing claimed that needs capture or the table")
    func capabilities() async throws {
        let scanner = try await DarwinScanner.make()
        let claimed = scanner.capabilities
        #expect(claimed.contains(.icmpSweep))
        #expect(claimed.contains(.connectScan))
        #expect(claimed.contains(.bannerProbe))
        for absent: EngineCapabilities in [.arpSweep, .synScan, .osFingerprint, .neighborTable] {
            #expect(!claimed.contains(absent))
        }
        #expect(scanner.descriptor.kind == .unprivileged)
        #expect(scanner.privilegedEngineNotice == nil)
        #expect(!scanner.naming.usesSSDP, "SSDP needs the multicast entitlement")
        #expect(scanner.neighbors.isReadable == false)
    }

    @Test("Asking for SYN is refused as unavailable, not quietly downgraded")
    func synRefused() async {
        do {
            _ = try await DarwinScanner.make(portScanType: .syn)
            Issue.record("a SYN scan was assembled on iPadOS")
        } catch {
            guard case .unavailable(let reason) = error else {
                Issue.record("expected .unavailable, got \(error)")
                return
            }
            #expect(reason.contains("iPadOS"))
        }
    }
}
#endif

#endif
