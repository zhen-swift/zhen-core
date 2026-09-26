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

@Suite("Scanner composition")
struct DarwinScannerTests {
    @Test("Concurrency is clamped, not rejected, and the clamp travels in the artifact")
    func clampIsADegradation() {
        // Asking for more probes in flight than the descriptor table supports is a
        // preference, not a usage error — failing the scan over it would be obnoxious.
        // But it must not be silent either, so it becomes a Degradation and reaches the
        // JSON rather than only a terminal nobody was watching.
        let notice = DarwinScanner.clampNotice(requested: 999_999, granted: 1_048_576, effective: 512)
        let raised = try! #require(notice)
        #expect(raised.stage == .setup)
        #expect(raised.recoverable)
        #expect(raised.reason.contains("999999"))
        #expect(raised.reason.contains("512"))
    }

    @Test("A request within the limit raises nothing")
    func noNoticeWhenHonoured() {
        #expect(DarwinScanner.clampNotice(requested: 64, granted: 1_048_576, effective: 64) == nil)
        #expect(DarwinScanner.clampNotice(requested: nil, granted: 256, effective: 64) == nil)
    }

    @Test("The engines describe what they can actually do")
    func descriptors() {
        // A surface says "OS fingerprint unavailable — requires the privileged engine"
        // by reading this, so it has to be honest about the unprivileged path's limits.
        let discovery = ICMPSweepEngine().descriptor
        #expect(discovery.kind == .unprivileged)
        #expect(discovery.capabilities.contains(.icmpSweep))
        // Not `.arpSweep`: this engine reads the kernel's neighbour table and emits no
        // ARP of its own. A capture taken on 2026-09-12 settled which of the two it is.
        #expect(discovery.capabilities.contains(.neighborTable))
        #expect(!discovery.capabilities.contains(.arpSweep),
                "the unprivileged engine cannot sweep layer 2 and must not claim to")
        #expect(!discovery.capabilities.contains(.synScan))
        #expect(!discovery.capabilities.contains(.osFingerprint))

        let ports = TCPConnectScanEngine().descriptor
        #expect(ports.capabilities.contains(.connectScan))
        #expect(!ports.capabilities.contains(.synScan))
    }

    @Test("A connect failure maps to the right port state, keeping closed apart from filtered")
    func connectErrnoMapping() {
        // ECONNREFUSED is a RST: the host is there and said no. That is positive
        // information and strictly more than silence, and collapsing the two throws
        // away the only signal separating a firewalled live host from a dead address.
        #expect(TCPConnectScanEngine.state(for: 0) == .open)
        #expect(TCPConnectScanEngine.state(for: ECONNREFUSED) == .closed)
        #expect(TCPConnectScanEngine.state(for: ETIMEDOUT) == .filtered)
        // Unreachable says something about the path, not the port. Reporting it as
        // closed would claim knowledge of a host we never reached.
        #expect(TCPConnectScanEngine.state(for: EHOSTUNREACH) == .filtered)
        #expect(TCPConnectScanEngine.state(for: ENETUNREACH) == .filtered)
    }

    @Test("A live interface can be enumerated and has a usable network")
    func enumeratesInterfaces() throws {
        // Needs a machine with a network, which any machine running this has. It does
        // not need the network under test to contain anything.
        let provider = DarwinInterfaceProvider()
        let all = try provider.interfaces()
        #expect(!all.isEmpty)
        #expect(all.allSatisfy { !$0.name.isEmpty })
        #expect(all.allSatisfy { !$0.address.isLoopback })
        let primary = try provider.primaryInterface()
        #expect(all.contains { $0.name == primary.name })
        // A /24 or thereabouts. A prefix of 0 would mean the netmask was misread.
        #expect(primary.network.prefix > 0)
    }

    @Test("An unprivileged ICMP socket opens without a password")
    func icmpSocketIsUnprivileged() throws {
        // The claim the whole tool rests on: SOCK_DGRAM/IPPROTO_ICMP is available to a
        // normal user on macOS, which is why this needs no sudo and nmap's equivalent
        // does.
        #expect(throws: Never.self) { _ = try ICMPSocket() }
    }
}

#endif
