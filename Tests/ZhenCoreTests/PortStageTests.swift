import Testing
@testable import ZhenCore

// Which hosts a run probes for ports: none, all, or only the ones history has never seen.
@Suite("The port stage can be limited to devices seen for the first time")
struct PortStageTests {
    static let hosts = ["10.10.20.9", "10.10.20.1", "10.10.20.5"].map { IPv4Address($0)! }
    static let known: [IPv4Address: Timestamp] = [
        IPv4Address("10.10.20.1")!: Timestamp(millisecondsSinceEpoch: 1),
        IPv4Address("10.10.20.9")!: Timestamp(millisecondsSinceEpoch: 2),
    ]

    @Test("Off probes nothing")
    func off() {
        #expect(PortStage.off.targets(among: Self.hosts, known: Self.known).isEmpty)
    }

    @Test("Every host probes every host that answered, in address order")
    func everyHost() {
        #expect(PortStage.everyHost.targets(among: Self.hosts, known: Self.known).map(\.description)
                == ["10.10.20.1", "10.10.20.5", "10.10.20.9"])
    }

    @Test("New hosts probes only the ones history has no record of")
    func newHosts() {
        #expect(PortStage.newHosts.targets(among: Self.hosts, known: Self.known).map(\.description)
                == ["10.10.20.5"])
    }

    @Test("On a first run every host is new")
    func firstRun() {
        #expect(PortStage.newHosts.targets(among: Self.hosts, known: [:]).count == 3)
    }

    @Test("Nothing new is nothing probed, not everything")
    func nothingNew() {
        let all = Dictionary(uniqueKeysWithValues: Self.hosts.map { ($0, Timestamp(millisecondsSinceEpoch: 0)) })
        #expect(PortStage.newHosts.targets(among: Self.hosts, known: all).isEmpty)
    }
}
