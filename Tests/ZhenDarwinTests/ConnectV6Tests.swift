// Apple-only, like the target it tests — see AdaptiveTests.swift for why.
#if canImport(Darwin)

import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

// P2: the connect scan over IPv6, against real sockets on this machine's own v6
// addresses. `fe80::1%lo0` is the part that matters: a link-local address is only
// reachable with its zone, so it is the test of `sin6_scope_id` that a `::1` test is not.
// The live gate — a real host on the LAN — is in the ledger.

/// A TCP socket listening on a v6 address. No accept loop: the kernel completes the
/// handshake from the backlog, which is all a connect scan observes. No thread either,
/// so closing it cannot race a reader (see `LoopbackListener` in UDPTests.swift).
private final class V6Listener {
    let port: UInt16
    private let fd: Int32

    init(_ address: IPv6Address) throws {
        let descriptor = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        try #require(descriptor >= 0)
        var local = ICMPv6Socket.socketAddress(address)
        let bound = unsafe withUnsafePointer(to: &local) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        try #require(bound == 0, "bind(\(address)) failed: errno \(errno)")
        try #require(listen(descriptor, 16) == 0)
        var actual = sockaddr_in6()
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        _ = unsafe withUnsafeMutablePointer(to: &actual) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe getsockname(descriptor, $0, &length)
            }
        }
        fd = descriptor
        port = UInt16(bigEndian: actual.sin6_port)
    }

    func close() { _ = Darwin.close(fd) }
}

private let loopback6 = IPv6Address("::1")!
private let linkLocal = IPv6Address("fe80::1%lo0")!

private func probe(_ address: IPv6Address, _ port: UInt16) async -> PortObservation? {
    let probed = await TCPConnectScanEngine.probe(
        .init(ip: .v6(address), port: port), budget: .seconds(1))
    guard case .observed(let observation, _) = probed else { return nil }
    return observation
}

@Suite("Connect scan over IPv6")
struct ConnectV6Tests {
    @Test("A listening port on ::1 is open")
    func loopbackOpen() async throws {
        let listener = try V6Listener(loopback6)
        defer { listener.close() }
        #expect(await probe(loopback6, listener.port)?.state == .open)
    }

    @Test("A port nobody listens on, on ::1, is closed — refused, not silent")
    func loopbackClosed() async throws {
        let listener = try V6Listener(loopback6)
        let port = listener.port
        listener.close()
        #expect(await probe(loopback6, port)?.state == .closed)
    }

    @Test("A link-local listener is reached through its zone")
    func linkLocalWithZone() async throws {
        let listener = try V6Listener(linkLocal)
        defer { listener.close() }
        #expect(await probe(linkLocal, listener.port)?.state == .open)
    }

    @Test("The zone becomes the scope id, and the port is in network order")
    func socketAddressCarriesZone() {
        let (scope, port, length) = withSocketAddress(.v6(linkLocal), port: 22) { addr, length in
            unsafe addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                unsafe ($0.pointee.sin6_scope_id, $0.pointee.sin6_port, length)
            }
        }
        #expect(scope == if_nametoindex("lo0"))
        #expect(scope != 0)
        #expect(UInt16(bigEndian: port) == 22)
        #expect(length == socklen_t(MemoryLayout<sockaddr_in6>.size))
    }

    @Test("The engine reports v6 hosts under their own address, next to v4 ones")
    func engineMixesFamilies() async throws {
        let listener = try V6Listener(loopback6)
        defer { listener.close() }
        let result = await TCPConnectScanEngine(concurrency: 8).scan(
            [.v6(loopback6), .v4(IPv4Address("127.0.0.1")!)],
            ports: PortSpec([listener.port]),
            perHostDeadline: .seconds(1),
            deadline: Deadline(after: .seconds(5)))
        #expect(result.ports[.v6(loopback6)]?.first?.state == .open)
        #expect(result.ports[.v4(IPv4Address("127.0.0.1")!)] != nil,
                "the v4 target was dropped")
        #expect(result.degradations.isEmpty, "the connect scan no longer skips v6")
    }
}

/// The live half of the P2 gate, run by hand on the LAN:
/// `ZHEN_LIVE_V6='fe80::…%en0 7000,22' swift test --filter liveV6`. Prints what the
/// engine reports so the ledger can quote it; asserts nothing, because what is open on
/// somebody's Apple TV is not a property of this code.
@Suite("Connect scan over IPv6, live")
struct ConnectV6LiveTests {
    @Test("live", .enabled(if: ProcessInfo.processInfo.environment["ZHEN_LIVE_V6"] != nil))
    func liveV6() async throws {
        let spec = try #require(ProcessInfo.processInfo.environment["ZHEN_LIVE_V6"])
        let parts = spec.split(separator: " ")
        let address = try #require(IPAddress(String(parts[0])))
        let ports = parts[1].split(separator: ",").compactMap { UInt16($0) }
        let result = await TCPConnectScanEngine(concurrency: 8).scan(
            [address], ports: PortSpec(ports), perHostDeadline: .milliseconds(800),
            deadline: Deadline(after: .seconds(10)))
        for observation in result.ports[address] ?? [] {
            print("LIVE \(address) \(observation.port)/tcp \(observation.state.rawValue)"
                  + " rtt=\(observation.rtt.map { String($0.millis) } ?? "-")")
        }
        print("LIVE degradations=\(result.degradations.count) outcome=\(result.outcome.rawValue)")
    }
}

#endif
