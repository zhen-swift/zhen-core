// RunInterfaceTests.swift — F5 of the fixes brief, R3's round trip.
//
// `run.interface` has been on `ScanRun` since 0.7.0, in the artifact and in history's run
// line. Look-longer reads it from the latest run, so it has to survive both: the schema-4
// codec, and a store written and reopened — including one 0.7.0 wrote.

import Foundation
import Testing
@testable import ZhenCore

@Suite("The run's interface survives the codec and history (F5, R3)")
struct RunInterfaceTests {
    static func run(on interface: String) -> ScanRun {
        ScanRun(
            id: UUID(), startedAt: Timestamp(millisecondsSinceEpoch: 1_790_000_000_000),
            target: IPv4Network("192.168.64.0/24")!, interface: interface,
            engine: EngineDescriptor(name: "fixture", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing()
        )
    }

    @Test("Through the schema-4 codec")
    func codec() throws {
        let report = ScanReport(run: Self.run(on: "bridge100"))
        let back = try JSONDecoder().decode(ScanReport.self, from: JSONEncoder().encode(report))
        #expect(back.run.interface == "bridge100")
        #expect(back == report)
    }

    @Test("Through a store written and reopened: the latest run keeps its interface")
    func store() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-run-interface-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        let run = Self.run(on: "bridge100")
        _ = await LogHistoryStore(url: url).record(ScanReport(run: run))
        let latest = try #require(await LogHistoryStore(url: url).latestRun())
        #expect(latest == run)
        #expect(latest.interface == "bridge100")
    }

    @Test("A store 0.7.0 wrote: its latest run already names its interface")
    func written070() async throws {
        let fixture = try #require(
            Bundle.module.url(forResource: "history-0.7.0", withExtension: "ndjson", subdirectory: "Fixtures")
        )
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "zhen-run-interface-070-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "history.ndjson")
        try FileManager.default.copyItem(at: fixture, to: url)
        let latest = try #require(await LogHistoryStore(url: url).latestRun())
        #expect(latest.interface == "en0")
    }
}
