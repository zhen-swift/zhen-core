import Testing
@testable import ZhenCore

// P1: `PortScanning` takes `IPAddress`. An engine that probes IPv4 only must say which
// targets it did not scan, and must say nothing at all when there were none — the
// second half is what keeps a v4 run's artifact byte-identical.
@Suite("An IPv4-only engine names the targets it did not scan")
struct PortScanFamilyTests {
    private let v4 = IPAddress("10.10.20.1")!
    private let v6 = IPAddress("fe80::1%en0")!

    @Test("With no v6 target there is no degradation")
    func v4OnlyIsSilent() {
        let split = IPv4OnlyTargets([v4], engine: "The SYN scan")
        #expect(split.probed == [IPv4Address("10.10.20.1")!])
        #expect(split.degradations.isEmpty)
    }

    @Test("A v6 target is not probed, and the degradation names it and the engine")
    func v6IsNamed() {
        let split = IPv4OnlyTargets([v4, v6], engine: "The SYN scan")
        #expect(split.probed == [IPv4Address("10.10.20.1")!])
        let reason = try? #require(split.degradations.first).reason
        #expect(split.degradations.count == 1)
        #expect(reason?.contains("fe80::1%en0") == true)
        #expect(reason?.contains("The SYN scan") == true)
        #expect(reason?.contains("IPv4 only") == true)
    }

    @Test("Progress hosts are the v4 ones, in address order")
    func ipv4HostsSkipsV6() {
        var result = PortScanResult()
        result.ports[IPAddress("10.10.20.9")!] = [PortObservation(port: 22, state: .open)]
        result.ports[v6] = [PortObservation(port: 22, state: .open)]
        result.ports[v4] = [PortObservation(port: 80, state: .closed)]
        #expect(result.ipv4Hosts.map(\.ip.description) == ["10.10.20.1", "10.10.20.9"])
    }
}
