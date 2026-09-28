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

    init(reply: [UInt8]?) throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        try #require(descriptor >= 0)
        var address = socketAddress(IPv4Address("127.0.0.1")!, port: 0)
        let bound = unsafe withUnsafePointer(to: &address) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        try #require(bound == 0)
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = unsafe withUnsafeMutablePointer(to: &actual) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe getsockname(descriptor, $0, &length)
            }
        }
        fd = descriptor
        port = UInt16(bigEndian: actual.sin_port)
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
private func vacantPort() throws -> UInt16 {
    let listener = try LoopbackListener(reply: nil)
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
        let observed = await DarwinUDPPortScan.probe(.init(ip: loopback, port: listener.port),
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
        let observed = await DarwinUDPPortScan.probe(.init(ip: loopback, port: try vacantPort()),
                                                    budget: .milliseconds(500))
        let observation = try #require(observed)
        #expect(observation.state == .closed)
        #expect(observation.rtt != nil, "a refusal is a real round trip and is timed")
    }

    @Test("Silence is open_filtered, and never filtered")
    func silenceIsOpenFiltered() async throws {
        let listener = try LoopbackListener(reply: nil)
        defer { listener.close() }
        let observed = await DarwinUDPPortScan.probe(.init(ip: loopback, port: listener.port),
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

#endif
