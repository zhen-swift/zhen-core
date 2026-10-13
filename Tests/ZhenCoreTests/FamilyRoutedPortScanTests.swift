import Testing
@testable import ZhenCore

/// Records what it was asked and answers `open` for every port of every target.
private final class RecordingPorts: PortScanning, @unchecked Sendable {
    let descriptor: EngineDescriptor
    private(set) var asked: [[IPAddress]] = []
    init(_ name: String) {
        descriptor = EngineDescriptor(name: name, kind: .unprivileged, capabilities: [.connectScan])
    }
    func scan(_ targets: [IPAddress], ports: PortSpec, perHostDeadline: Duration,
              deadline: Deadline, progress: ProgressSink) async -> PortScanResult {
        asked.append(targets)
        var result = PortScanResult(usedCapabilities: descriptor.capabilities)
        for target in targets {
            result.ports[target] = ports.ports.map { PortObservation(port: $0, state: .open) }
        }
        return result
    }
    func stream(_ targets: [IPAddress], ports: PortSpec, perHostDeadline: Duration,
                deadline: Deadline) -> AsyncStream<ProbeEvent> { AsyncStream { $0.finish() } }
}

// P4: under `auto` with a capture device, v4 goes to half-open and v6 to connect.
@Suite("auto sends each family to an engine that speaks it")
struct FamilyRoutedPortScanTests {
    private let v4 = IPAddress("10.10.20.1")!
    private let v6 = IPAddress("fe80::1%en0")!

    private func run(_ targets: [IPAddress]) async -> (RecordingPorts, RecordingPorts, PortScanResult) {
        let syn = RecordingPorts("syn"), connect = RecordingPorts("connect")
        let result = await FamilyRoutedPortScan(v4: syn, v6: connect).scan(
            targets, ports: PortSpec([22]), perHostDeadline: .seconds(1),
            deadline: Deadline(after: .seconds(5)))
        return (syn, connect, result)
    }

    @Test("v4 only: the v4 engine alone, asked exactly what it always was")
    func v4Only() async {
        let (syn, connect, result) = await run([v4])
        #expect(syn.asked == [[v4]])
        #expect(connect.asked.isEmpty)
        #expect(result.ports.keys.sorted() == [v4])
    }

    @Test("mixed: each family to its engine, one result covering both")
    func mixed() async {
        let (syn, connect, result) = await run([v4, v6])
        #expect(syn.asked == [[v4]])
        #expect(connect.asked == [[v6]])
        #expect(result.ports.keys.sorted() == [v4, v6])
    }

    @Test("The descriptor is the v4 engine's, so a v4 artifact names what it always named")
    func descriptorUnchanged() {
        let routed = FamilyRoutedPortScan(v4: RecordingPorts("syn"), v6: RecordingPorts("connect"))
        #expect(routed.descriptor.name == "syn")
    }
}
