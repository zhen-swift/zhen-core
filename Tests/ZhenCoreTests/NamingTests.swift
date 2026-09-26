import Testing
@testable import ZhenCore

@Suite("Name cascade")
struct NamingTests {
    @Test("A deliberately assigned name beats one the device advertises about itself")
    func administrativeWinsOverMDNS() {
        let candidates = [
            NameCandidate(value: "JCs-MacBook-Pro.local", source: .mdns),
            NameCandidate(value: "JC's MacBook Pro", source: .administrative),
            NameCandidate(value: "JCS-MBP", source: .netbios),
        ]
        #expect(candidates.best?.value == "JC's MacBook Pro")
        #expect(candidates.alternates.map(\.source) == [.mdns, .netbios])
    }

    @Test("Within a source, the cleaner service type wins")
    func rankBreaksTies() {
        // The same device advertises a clean name on one service type and a
        // prefixed one on another.
        let candidates = [
            NameCandidate(value: "70-35-60-63.1 Sala de entretenimiento", source: .mdns, rank: 9),
            NameCandidate(value: "Sala de entretenimiento", source: .mdns, rank: 1),
        ]
        #expect(candidates.best?.value == "Sala de entretenimiento")
    }

    @Test("Source priority dominates rank")
    func priorityBeatsRank() {
        let candidates = [
            NameCandidate(value: "from-mdns", source: .mdns, rank: 99),
            NameCandidate(value: "from-ssdp", source: .ssdp, rank: 0),
        ]
        #expect(candidates.best?.value == "from-mdns")
    }

    @Test("No candidates is a normal state, not an error")
    func unidentified() {
        let host = HostFacts(ip: IPv4Address(raw: 0x0A0A1470))
        #expect(host.isUnidentified)
        #expect(host.displayName == nil)
    }

    @Test("A model can survive even when a different source supplies the winning name")
    func modelFallsBack() {
        let host = HostFacts(
            ip: IPv4Address(raw: 0x0A0A1402),
            allNames: [
                NameCandidate(value: "Sala de entretenimiento", source: .administrative),
                NameCandidate(value: "Sala de entretenimiento", source: .mdns, rank: 1, model: "AppleTV5,3"),
            ]
        )
        #expect(host.displayName == "Sala de entretenimiento")
        #expect(host.displayModel == "AppleTV5,3")
    }
}
