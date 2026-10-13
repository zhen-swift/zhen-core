// Apple-only, like the target it tests — see AdaptiveTests.swift for why.
#if canImport(Darwin)

import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

// The UDP engine's three outcomes, against real sockets on loopback — deterministic,
// where the gateway rate-limits its ICMP and changes its answer between runs.
// `Scripts/verify-udp-outcomes.sh` is the same claim measured against the network.

/// A UDP socket on 127.0.0.1 that either answers every datagram with `reply` or, with
/// `reply == nil`, reads and says nothing.
private final class LoopbackListener: @unchecked Sendable {
    let port: UInt16
    private let fd: Int32
    private let thread: Thread
    // `close()` must not release the descriptor while the reader can still use it. The
    // number is recycled at once, and the next socket to get it in a parallel test — the
    // probe's own, typically — would have its reply read and dropped by this thread,
    // which reports an open port as `open_filtered`. That was a ~5% flake in the suite.
    private let closing = ClosingFlag()
    private let finished = DispatchSemaphore(value: 0)

    init(reply: [UInt8]?, on address: IPAddress = .v4(IPv4Address("127.0.0.1")!)) throws {
        let descriptor = socket(socketFamily(address), SOCK_DGRAM, IPPROTO_UDP)
        try #require(descriptor >= 0)
        let bound = withSocketAddress(address, port: 0) { unsafe bind(descriptor, $0, $1) }
        try #require(bound == 0, "bind(\(address)) failed: errno \(errno)")
        var actual = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = unsafe withUnsafeMutablePointer(to: &actual) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe getsockname(descriptor, $0, &length)
            }
        }
        fd = descriptor
        // sin_port and sin6_port sit at the same offset, 2, in both layouts.
        port = unsafe withUnsafeBytes(of: actual) { raw in
            UInt16(bigEndian: unsafe raw.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
        }
        let finished = self.finished, closing = self.closing
        thread = Thread {
            defer { finished.signal() }
            var buffer = [UInt8](repeating: 0, count: 2048)
            var from = sockaddr_storage()
            var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            while true {
                // Poll rather than block: on Darwin, `shutdown` does not wake a UDP
                // `recvfrom` already waiting, so a blocked reader could never be joined.
                var ready = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                let polled = unsafe poll(&ready, 1, 20)
                if closing.isSet { return }
                if polled <= 0 { continue }
                let received = unsafe buffer.withUnsafeMutableBytes { bytes in
                    unsafe withUnsafeMutablePointer(to: &from) { pointer in
                        unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            unsafe recvfrom(descriptor, bytes.baseAddress, bytes.count, 0, $0, &fromLength)
                        }
                    }
                }
                if received < 0 { return }
                guard let reply else { continue }
                _ = unsafe reply.withUnsafeBytes { bytes in
                    unsafe withUnsafePointer(to: &from) { pointer in
                        unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            unsafe sendto(descriptor, bytes.baseAddress, bytes.count, 0, $0, fromLength)
                        }
                    }
                }
            }
        }
        thread.start()
    }

    func close() {
        closing.set()
        finished.wait()
        _ = Darwin.close(fd)
    }
}

private final class ClosingFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}

/// A loopback port nobody is listening on: bound for a moment to get a free number, then
/// closed, so the kernel answers a datagram to it with port-unreachable.
private func vacantPort(on address: IPAddress = .v4(IPv4Address("127.0.0.1")!)) throws -> UInt16 {
    let listener = try LoopbackListener(reply: nil, on: address)
    let port = listener.port
    listener.close()
    return port
}

private let loopback = IPv4Address("127.0.0.1")!

@Suite("UDP: an answer is open, a refusal is closed, silence is open_filtered")
struct UDPOutcomeTests {
    @Test("A datagram back from the port is open")
    func answerIsOpen() async throws {
        let listener = try LoopbackListener(reply: [0x01, 0x02])
        defer { listener.close() }
        let observed = await DarwinUDPPortScan.probe(.init(ip: .v4(loopback), port: listener.port),
                                                    budget: .milliseconds(500))
        let observation = try #require(observed)
        #expect(observation.state == .open)
        #expect(observation.proto == .udp)
        // No payload table entry for an ephemeral port, so nothing names a service: the
        // port number is not evidence.
        #expect(observation.service == nil)
    }

    @Test("ICMP port-unreachable is closed")
    func refusalIsClosed() async throws {
        let observed = await DarwinUDPPortScan.probe(.init(ip: .v4(loopback), port: try vacantPort()),
                                                    budget: .milliseconds(500))
        let observation = try #require(observed)
        #expect(observation.state == .closed)
        #expect(observation.rtt != nil, "a refusal is a real round trip and is timed")
    }

    @Test("Silence is open_filtered, and never filtered")
    func silenceIsOpenFiltered() async throws {
        let listener = try LoopbackListener(reply: nil)
        defer { listener.close() }
        let observed = await DarwinUDPPortScan.probe(.init(ip: .v4(loopback), port: listener.port),
                                                    budget: .milliseconds(300))
        let observation = try #require(observed)
        #expect(observation.state == .openFiltered)
        #expect(observation.state != .filtered)
        #expect(observation.rtt == nil, "silence has no round trip to time")
    }

    @Test("The engine reports all three together, and only UDP ports")
    func engineReportsAllThree() async throws {
        let answering = try LoopbackListener(reply: [0x00])
        let silent = try LoopbackListener(reply: nil)
        defer { answering.close(); silent.close() }
        let vacant = try vacantPort()
        let result = await DarwinUDPPortScan().scan(
            [.v4(loopback)],
            ports: PortSpec([22], udp: [answering.port, silent.port, vacant]),
            perHostDeadline: .milliseconds(300),
            deadline: Deadline(after: .seconds(5)),
            progress: ProgressSink { _ in }
        )
        let byPort = Dictionary(uniqueKeysWithValues: (result.ports[.v4(loopback)] ?? []).map { ($0.port, $0) })
        #expect(byPort.count == 3, "the TCP port in the spec is not this engine's")
        #expect(byPort[answering.port]?.state == .open)
        #expect(byPort[silent.port]?.state == .openFiltered)
        #expect(byPort[vacant]?.state == .closed)
        #expect(result.usedCapabilities.contains(.udpScan))
    }
}

@Suite("UDP payloads say something a service understands")
struct UDPPayloadTests {
    @Test("A recognized answer names its service from the evidence")
    func recognizedAnswerNamesService() throws {
        let dns = try #require(UDPPayloads.payload(for: 53))
        var reply = dns.bytes
        reply[2] |= 0x80   // the same message with the response bit set
        let observation = try #require(DarwinUDPPortScan.observation(
            for: .answered(reply), port: 53, payload: dns, elapsed: .milliseconds(1)))
        #expect(observation.state == .open)
        #expect(observation.service?.name == "dns")
        #expect(observation.service?.evidence == .protocolHandshake)
    }

    @Test("An unrecognized answer is still open, and names nothing")
    func unrecognizedAnswerIsOpenAndUnnamed() throws {
        let dns = try #require(UDPPayloads.payload(for: 53))
        let observation = try #require(DarwinUDPPortScan.observation(
            for: .answered([0xDE, 0xAD]), port: 53, payload: dns, elapsed: .milliseconds(1)))
        #expect(observation.state == .open)
        #expect(observation.service == nil, "port 53 is not evidence that this is DNS")
    }

    @Test("Our own query is not mistaken for an answer")
    func requestsAreNotResponses() throws {
        for port: UInt16 in [53, 137, 5353] {
            let payload = try #require(UDPPayloads.payload(for: port))
            #expect(!payload.recognizes(payload.bytes), "port \(port) recognizes its own query")
        }
        let ntp = try #require(UDPPayloads.payload(for: 123))
        #expect(!ntp.recognizes(ntp.bytes), "a client-mode request is not a server reply")
        #expect(ntp.bytes.count == 48 && ntp.bytes[0] == 0x23)
    }

    @Test("The SNMP probe is a well-formed v3 message with no community string")
    func snmpIsV3Discovery() throws {
        let snmp = try #require(UDPPayloads.payload(for: 161))
        let bytes = snmp.bytes
        #expect(bytes[0] == 0x30)
        #expect(Int(bytes[1]) == bytes.count - 2, "outer length must cover the message exactly")
        #expect(UDPPayloads.isSNMPv3Message(bytes))
        // msgFlags = reportable, and the only OCTET STRING with content in the whole
        // message — there is no community, and no user name.
        #expect(!String(decoding: bytes, as: UTF8.self).contains("public"))
    }

    @Test("BER integers take the fewest octets and stay non-negative")
    func berIntegers() {
        #expect(UDPPayloads.berInteger(0) == [0x02, 0x01, 0x00])
        #expect(UDPPayloads.berInteger(3) == [0x02, 0x01, 0x03])
        #expect(UDPPayloads.berInteger(128) == [0x02, 0x02, 0x00, 0x80])
        #expect(UDPPayloads.berInteger(65_507) == [0x02, 0x03, 0x00, 0xFF, 0xE3])
    }
}

@Suite("Two engines' results combine without losing the worse outcome")
struct CombinedResultTests {
    @Test("The worse outcome wins and observations join per host")
    func combine() {
        let host = IPAddress.v4(loopback)
        let tcp = PortScanResult(ports: [host: [PortObservation(port: 22, state: .open)]],
                                 usedCapabilities: [.connectScan], outcome: .complete)
        let udp = PortScanResult(ports: [host: [PortObservation(port: 53, proto: .udp, state: .openFiltered)]],
                                 usedCapabilities: [.udpScan], outcome: .deadlineExpired)
        let both = tcp.combined(with: udp)
        #expect(both.outcome == .deadlineExpired)
        #expect(both.ports[host]?.count == 2)
        #expect(both.usedCapabilities == [.connectScan, .udpScan])
    }
}

private let loopback6 = IPAddress("::1")!
private let linkLocal6 = IPAddress("fe80::1%lo0")!

// P3: the same three outcomes over IPv6, on `::1` and on `fe80::1%lo0` — the second
// because a link-local peer is only reachable through its zone, so it is what tests
// `sin6_scope_id` on the connected UDP socket. The live half, a real host on the LAN,
// is `udpLiveV6` below and the P3 section of Docs/process/V6-progress.md.
@Suite("UDP over IPv6: the same three outcomes")
struct UDPv6OutcomeTests {
    private func probe(_ address: IPAddress, _ port: UInt16) async throws -> PortObservation {
        let observed = await DarwinUDPPortScan.probe(.init(ip: address, port: port),
                                                    budget: .milliseconds(500))
        return try #require(observed)
    }

    // `::1` only. With the application firewall set to block all incoming — this Mac's
    // setting — an inbound datagram to `fe80::1%lo0` is dropped for every process, Python
    // included, while `::1` is exempt. The zone is covered by the refusal case below: a
    // refusal from a link-local peer only comes back if the zone got the datagram there.
    @Test("A datagram back is open", arguments: [loopback6])
    func answerIsOpen(_ address: IPAddress) async throws {
        let listener = try LoopbackListener(reply: [0x01, 0x02], on: address)
        defer { listener.close() }
        #expect(try await probe(address, listener.port).state == .open)
    }

    @Test("A refusal is closed", arguments: [loopback6, linkLocal6])
    func refusalIsClosed(_ address: IPAddress) async throws {
        let observation = try await probe(address, try vacantPort(on: address))
        #expect(observation.state == .closed)
        #expect(observation.rtt != nil, "a refusal is a round trip")
    }

    // The link-local case here passes for the firewall's reason as much as the engine's,
    // so it proves only that silence is not misread — which is the claim.
    @Test("Silence is open_filtered, and never filtered", arguments: [loopback6, linkLocal6])
    func silenceIsOpenFiltered(_ address: IPAddress) async throws {
        let listener = try LoopbackListener(reply: nil, on: address)
        defer { listener.close() }
        #expect(try await probe(address, listener.port).state == .openFiltered)
    }

    @Test("A v6 answer's source is read, not discarded")
    func sourceIsParsed() {
        var storage = sockaddr_storage()
        let bytes = withSocketAddress(linkLocal6, port: 53) { addr, length in
            unsafe Array(UnsafeRawBufferPointer(start: addr, count: Int(length)))
        }
        unsafe withUnsafeMutableBytes(of: &storage) { raw in
            for (index, byte) in bytes.enumerated() { unsafe raw[index] = byte }
        }
        #expect(ipAddress(from: storage) == linkLocal6)
    }
}

/// Live, by hand: `ZHEN_LIVE_V6_UDP='fe80::…%en0 5353,53 [budget-ms]' swift test --filter udpLiveV6`.
/// Prints what the engine reports; asserts nothing about somebody else's network.
@Suite("UDP over IPv6, live")
struct UDPv6LiveTests {
    @Test("live", .enabled(if: ProcessInfo.processInfo.environment["ZHEN_LIVE_V6_UDP"] != nil))
    func udpLiveV6() async throws {
        let spec = try #require(ProcessInfo.processInfo.environment["ZHEN_LIVE_V6_UDP"])
        let parts = spec.split(separator: " ")
        let address = try #require(IPAddress(String(parts[0])))
        let ports = parts[1].split(separator: ",").compactMap { UInt16($0) }
        let result = await DarwinUDPPortScan().scan(
            [address], ports: PortSpec([], udp: ports),
            perHostDeadline: .milliseconds(parts.count > 2 ? Int(parts[2]) ?? 1_000 : 1_000),
            deadline: Deadline(after: .seconds(15)))
        for observation in result.ports[address] ?? [] {
            print("LIVE \(address) \(observation.port)/udp \(observation.state.rawValue)"
                  + " service=\(observation.service?.name ?? "-")")
        }
        print("LIVE degradations=\(result.degradations.count) outcome=\(result.outcome.rawValue)")
    }
}

#endif
