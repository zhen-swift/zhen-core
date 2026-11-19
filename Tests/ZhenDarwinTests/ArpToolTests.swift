// macOS only, like the code it tests (`ArpTool` runs `/usr/sbin/arp`).
#if os(macOS)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

@Suite("The neighbour table through arp, when the kernel withholds it")
struct ArpToolTests {
    /// What `arp -an` prints, as captured on macOS 27.2: complete, incomplete, static, the
    /// subnet broadcast, an mDNS group, and the one-digit groups `arp` prints.
    static let output = """
    ? (192.168.64.1) at ca:80:6d:74:ed:64 on bridge100 ifscope permanent [bridge]
    ? (192.168.64.2) at 52:55:55:ab:97:99 on bridge100 ifscope [bridge]
    ? (192.168.64.3) at (incomplete) on bridge100 ifscope [bridge]
    ? (192.168.64.9) at 52:55:55:1:a:b on bridge100 ifscope [bridge]
    ? (192.168.64.255) at ff:ff:ff:ff:ff:ff on bridge100 ifscope [bridge]
    ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
    ? (192.168.64.2) at 52:55:55:00:00:01 on bridge101 ifscope [bridge]
    not an entry
    """

    @Test("decodes as the kernel decoder does")
    func parse() throws {
        let entries = ArpTool.parse(Self.output)
        #expect(entries.map(\.ip.description) == ["192.168.64.1", "192.168.64.2", "192.168.64.3", "192.168.64.9"])

        let gateway = try #require(entries.first)
        #expect(gateway.mac == MACAddress("ca:80:6d:74:ed:64"))
        #expect(gateway.isComplete && gateway.isPermanent)

        // The first entry for an address wins, as in `decode`.
        #expect(entries[1].mac == MACAddress("52:55:55:ab:97:99"))
        #expect(entries[1].isComplete && !entries[1].isPermanent)

        // Incomplete is kept, and marked: evidence of absence, not a device.
        #expect(!entries[2].isComplete)

        // One-digit groups are whole bytes.
        #expect(entries[3].mac == MACAddress("52:55:55:01:0a:0b"))
    }

    @Test("empty output is an empty table")
    func empty() {
        #expect(ArpTool.parse("").isEmpty)
    }

    @Test("arp runs, exits cleanly and parses")
    func live() throws {
        let text = try ArpTool.output()
        let lines = text.split(separator: "\n").filter { $0.contains(" at ") }
        #expect(ArpTool.parse(text).count <= lines.count)
    }

    @Test("a snapshot names its source, and falls back only when the kernel gives nothing")
    func snapshotSource() async throws {
        let snapshot = try await DarwinNeighborCache().snapshot()
        let mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
        if try RouteSysctl.fetch(mib).isEmpty {
            #expect(snapshot.source == ArpTool.source)
            #expect(snapshot.byteCount == 0)
        } else {
            #expect(snapshot.source == "sysctl")
        }
    }

    @Test("the watch report carries table_source")
    func reportKey() throws {
        let report = NeighborWatchReport(enabled: false, tableSource: "arp_tool")
        let json = try #require(String(data: try JSONEncoder().encode(report), encoding: .utf8))
        #expect(json.contains("\"table_source\":\"arp_tool\""))
    }
}

#endif
