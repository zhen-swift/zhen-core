import Testing
@testable import ZhenCore

/// Records which half of the spec it was asked about and the per-host budget it got, and
/// answers for its own transport only, the way the real engines do.
private final class TransportPorts: PortScanning, @unchecked Sendable {
    let descriptor: EngineDescriptor
    let proto: TransportProtocol
    private(set) var calls = 0
    private(set) var perHost: Duration?

    init(_ proto: TransportProtocol) {
        self.proto = proto
        descriptor = EngineDescriptor(
            name: proto.rawValue, kind: .unprivileged,
            capabilities: proto == .tcp ? [.connectScan] : [.udpScan]
        )
    }

    func scan(_ targets: [IPAddress], ports: PortSpec, perHostDeadline: Duration,
              deadline: Deadline, progress: ProgressSink) async -> PortScanResult {
        calls += 1
        perHost = perHostDeadline
        let numbers = proto == .tcp ? ports.ports : ports.udpPorts
        var result = PortScanResult(usedCapabilities: descriptor.capabilities)
        for target in targets {
            result.ports[target] = numbers.map {
                PortObservation(port: $0, proto: proto, state: proto == .tcp ? .open : .openFiltered)
            }
        }
        return result
    }

    func stream(_ targets: [IPAddress], ports: PortSpec, perHostDeadline: Duration,
                deadline: Deadline) -> AsyncStream<ProbeEvent> { AsyncStream { $0.finish() } }
}

// 0.9.0: the app's `probePorts` handed a mixed spec to the TCP engine alone, and the UDP
// half was never probed and never mentioned.
@Suite("A spec's TCP and UDP halves each reach the engine that speaks them")
struct TransportSplitPortScanTests {
    private let host = IPAddress("10.10.20.1")!

    private func run(_ spec: PortSpec) async -> (TransportPorts, TransportPorts, PortScanResult) {
        let tcp = TransportPorts(.tcp), udp = TransportPorts(.udp)
        let result = await TransportSplitPortScan(tcp: tcp, udp: udp).scan(
            [host], ports: spec, perHostDeadline: .milliseconds(600),
            deadline: Deadline(after: .seconds(5)))
        return (tcp, udp, result)
    }

    @Test("TCP only: the TCP engine alone, so the common case is what it always was")
    func tcpOnly() async {
        let (tcp, udp, result) = await run(PortSpec([22, 80]))
        #expect(tcp.calls == 1)
        #expect(udp.calls == 0)
        #expect(result.ports[host]?.map(\.port) == [22, 80])
    }

    @Test("UDP only: the UDP engine alone")
    func udpOnly() async {
        let (tcp, udp, result) = await run(PortSpec([], udp: [53]))
        #expect(tcp.calls == 0)
        #expect(udp.calls == 1)
        #expect(result.ports[host]?.map(\.proto) == [.udp])
    }

    @Test("Mixed: both engines, one result with both transports for the host")
    func mixed() async {
        let (tcp, udp, result) = await run(PortSpec([22], udp: [53, 123]))
        #expect(tcp.calls == 1)
        #expect(udp.calls == 1)
        let observed = result.ports[host] ?? []
        #expect(observed.filter { $0.proto == .tcp }.map(\.port) == [22])
        #expect(observed.filter { $0.proto == .udp }.map(\.port).sorted() == [53, 123])
        #expect(result.usedCapabilities.contains(.connectScan))
        #expect(result.usedCapabilities.contains(.udpScan))
    }

    @Test("UDP gets its own per-host budget, the second zhen ports has always given it")
    func udpBudget() async {
        let (tcp, udp, _) = await run(PortSpec([22], udp: [53]))
        #expect(tcp.perHost == .milliseconds(600))
        #expect(udp.perHost == .seconds(1))
    }

    @Test("The descriptor is the TCP engine's")
    func descriptor() {
        let split = TransportSplitPortScan(tcp: TransportPorts(.tcp), udp: TransportPorts(.udp))
        #expect(split.descriptor.name == "tcp")
    }
}
