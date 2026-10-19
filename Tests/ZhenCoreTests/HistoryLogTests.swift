import Foundation
import Testing
@testable import ZhenCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// What only the file-backed store can get wrong.
//
// The rules for folding a run into history are `HistoryLedger`'s and are tested as
// rules. What is left for a store is faithfulness: everything the ledger knew before it
// was written down has to still be true after it is read back, and the failures are all
// silent. A dropped identifier does not throw — the device comes back as new. A lost
// first-seen does not throw — the device claims to have arrived today. So these tests
// check the properties through a reopen, which is the only place those can show up.
@Suite("History in an append-only file")
struct HistoryLogTests {
    private func temporaryDirectory() throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zhen-log-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func device(ip: String, mac: String?, name: String? = nil, at: Timestamp) -> Device {
        var names: [NameCandidate] = []
        if let name { names.append(NameCandidate(value: name, source: .mdns, rank: 1)) }
        return Device(
            observing: HostFacts(
                ip: IPv4Address(ip)!, mac: mac.flatMap(MACAddress.init), allNames: names
            ),
            in: IPv4Network("10.10.20.0/24")!, firstSeen: at, lastSeen: at
        )
    }

    private func report(_ devices: [Device], at: Timestamp) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at,
                target: IPv4Network("10.10.20.0/24")!, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    @Test("Nothing is written until something is recorded")
    func lazyCreation() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let store = LogHistoryStore(url: url)
        #expect(await store.devices().isEmpty)
        #expect(await store.latestRun() == nil)
        #expect(!FileManager.default.fileExists(atPath: url.path),
                "reading an empty store must not create a file")
        #expect(!FileManager.default.fileExists(atPath: url.path + ".lock"),
                "reading an empty store must not create the lock file either")
    }

    @Test("A device, its first-seen and the run survive a reopen")
    func survivesReopen() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let early = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let later = Timestamp(millisecondsSinceEpoch: 2_000_000)

        do {
            let store = LogHistoryStore(url: url)
            _ = await store.record(
                report([device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: early)], at: early)
            )
        }

        let reopened = LogHistoryStore(url: url)
        #expect(await reopened.devices().count == 1)
        #expect(await reopened.latestRun() != nil)
        let facts = HostFacts(ip: IPv4Address("10.10.20.2")!, mac: MACAddress("C8:69:CD:5E:01:E1"))
        let seen = await reopened.firstSeen(for: [facts], in: IPv4Network("10.10.20.0/24")!)
        #expect(seen[IPv4Address("10.10.20.2")!] == early, "first-seen was rewritten by the reopen")

        // The device was here before the restart, so it did not "appear" after it.
        let events = await reopened.record(
            report([device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: later)], at: later)
        )
        #expect(!events.contains { $0.kind == .appeared })
        #expect(await reopened.devices().count == 1)
    }

    @Test("A join survives a reopen, which an append would not have made it do")
    func mergeSurvivesAReopen() async throws {
        // The failure this prevents is specific and silent. A merge REMOVES a record.
        // `append` writes only the records the ledger still holds, and `reload` rebuilds
        // them keyed by stored key with the last line winning — so an append after a
        // merge leaves the absorbed record's old device line on disk, and the next open
        // reads it straight back. The duplicate returns, the device list goes back to
        // two rows, and nothing anywhere reports a failure.
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let t1 = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let t2 = Timestamp(millisecondsSinceEpoch: 2_000_000)
        let t3 = Timestamp(millisecondsSinceEpoch: 3_000_000)

        // Two runs that cannot be joined at the time: the first sees a named device, the
        // second sees the same machine after a MAC rotation with no name to go on. This
        // is a discovery-only scan's view, and it mints a second record.
        do {
            let store = LogHistoryStore(url: url)
            _ = await store.record(report(
                [device(ip: "10.10.20.88", mac: "52:A1:8A:5E:04:8A", name: "Mac", at: t1)], at: t1
            ))
            // A different address as well as a different MAC. On the SAME address the
            // `ipLease` fallback joins the two runs and no second record is ever minted,
            // which is correct behaviour and makes this test prove nothing.
            _ = await store.record(report(
                [device(ip: "10.10.20.131", mac: "D6:0A:97:5E:06:9C", at: t2)], at: t2
            ))
            #expect(await store.devices().count == 2, "the split this test needs did not happen")
        }

        // A full scan carrying both the name and the rotated MAC is the evidence.
        let reopened = LogHistoryStore(url: url)
        let events = await reopened.record(report(
            [device(ip: "10.10.20.131", mac: "D6:0A:97:5E:06:9C", name: "Mac", at: t3)], at: t3
        ))
        #expect(await reopened.devices().count == 1, "the two records did not join")
        #expect(events.contains { $0.kind == .merged }, "the join was not reported")

        // And again from disk, which is the half that append would have failed.
        let again = LogHistoryStore(url: url)
        #expect(await again.devices().count == 1,
                "the absorbed record came back from the file")
    }

    @Test("A duplicate already in the file is joined when the file is opened")
    func mergeAppliesOnLoad() async throws {
        // Reconciliation on load, not only on fold, which is what makes this fix reach
        // histories already on disk. A device that never answers again would otherwise
        // stay split for good, and the person looking at two rows has no way to know
        // which one to believe.
        //
        // The file has to be put into the state the PREVIOUS version of this code left
        // behind, because any store that folds now also reconciles — so the duplicate
        // cannot be created through the front door any more. That state is: two records,
        // one of which has absorbed the other's key into its join set without the other
        // having been removed. The surgery below writes exactly that, by re-appending
        // the older record's own line with the newer record's MAC added to it. `reload`
        // takes the last line for a key, so the append updates that record in place.
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let t1 = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let t2 = Timestamp(millisecondsSinceEpoch: 2_000_000)

        do {
            let store = LogHistoryStore(url: url)
            _ = await store.record(report(
                [device(ip: "10.10.20.88", mac: "52:A1:8A:5E:04:8A", name: "Mac", at: t1)], at: t1
            ))
            _ = await store.record(report(
                [device(ip: "10.10.20.131", mac: "D6:0A:97:5E:06:9C", at: t2)], at: t2
            ))
            #expect(await store.devices().count == 2, "the split this test needs did not happen")
        }

        let text = try String(contentsOf: url, encoding: .utf8)
        var lines = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        // Found by the MAC it carries rather than by its key. The older record has a
        // name, so its PRIMARY key is the mDNS instance and not the address at all —
        // which is the whole reason the rotation split the device in the first place.
        let older = try #require(
            lines.last { $0.contains("\"type\":\"device\"") && $0.contains("52:A1:8A:5E:04:8A") },
            "the older record's line was not found to operate on"
        )
        let patched = older.replacingOccurrences(
            of: "\"identifiers\":[",
            with: "\"identifiers\":[\"randomized_mac|D6:0A:97:5E:06:9C\","
        )
        #expect(patched != older, "the surgery did not change anything")
        lines.append(patched)
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)

        // Nothing is recorded here. Opening the file is enough.
        let reopened = LogHistoryStore(url: url)
        #expect(await reopened.devices().count == 1,
                "opening the file did not join a duplicate already in it")

        // And the join is durable rather than an artefact of this one process's memory.
        let again = LogHistoryStore(url: url)
        #expect(await again.devices().count == 1, "the duplicate came back on the next open")
    }

    // The join set is what makes a device that changes address stay one device. It is
    // also the part most easily lost in a round trip, because it is the only field that
    // is a collection of keys rather than a scalar.
    @Test("The identifiers a device has presented survive, so it is still one device")
    func identifiersSurvive() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let t1 = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let t2 = Timestamp(millisecondsSinceEpoch: 2_000_000)

        do {
            let store = LogHistoryStore(url: url)
            _ = await store.record(report(
                [device(ip: "10.10.20.9", mac: "52:A1:8A:5E:04:8A", name: "Mac", at: t1)], at: t1
            ))
        }

        let reopened = LogHistoryStore(url: url)
        let events = await reopened.record(report(
            [device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", name: "Mac", at: t2)], at: t2
        ))
        #expect(await reopened.devices().count == 1, "the device split in two across the reopen")
        #expect(events.contains { $0.kind == .ipChanged })
    }

    @Test("The event log accumulates across reopens rather than restarting")
    func eventsAccumulate() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let t1 = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let t2 = Timestamp(millisecondsSinceEpoch: 2_000_000)

        do {
            let store = LogHistoryStore(url: url)
            _ = await store.record(
                report([device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: t1)], at: t1)
            )
            _ = await store.record(report([
                device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: t2),
                device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: t2),
            ], at: t2))
        }

        let reopened = LogHistoryStore(url: url)
        let events = await reopened.events()
        #expect(events.count == 1, "the event log did not survive the reopen")
        #expect(events.first?.kind == .appeared)
    }

    // Compaction is the one moment this design rewrites rather than appends, so it is
    // the one moment it can lose everything. The threshold is lowered rather than
    // writing thousands of runs, because what is under test is the rewrite, not the
    // arithmetic that decides when to do it.
    @Test("Compaction shrinks the file and changes nothing it says")
    func compactionPreservesHistory() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let store = LogHistoryStore(url: url, compactionThreshold: 12)

        var expectedFirstSeen: Timestamp?
        for index in 0..<12 {
            let at = Timestamp(millisecondsSinceEpoch: Int64(1_000_000 + index * 1_000))
            if index == 0 { expectedFirstSeen = at }
            _ = await store.record(report([
                device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: at),
                device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: at),
            ], at: at))
        }

        let linesAfter = try lineCount(of: url)
        #expect(linesAfter < 36, "the file was never compacted")

        let reopened = LogHistoryStore(url: url)
        #expect(await reopened.devices().count == 2, "compaction lost a device")
        let facts = HostFacts(ip: IPv4Address("10.10.20.2")!, mac: MACAddress("C8:69:CD:5E:01:E1"))
        let seen = await reopened.firstSeen(for: [facts], in: IPv4Network("10.10.20.0/24")!)
        #expect(seen[IPv4Address("10.10.20.2")!] == expectedFirstSeen,
                "compaction rewrote first-seen")
        #expect(await reopened.latestRun() != nil, "compaction lost the run")
    }

    // A truncated last line is what an interrupted write leaves behind, and it is the
    // whole reason the format is one object per line. Losing that line is the intended
    // outcome; losing the file is not.
    @Test("A torn final line costs that line and nothing else")
    func tornLineIsSurvivable() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let at = Timestamp(millisecondsSinceEpoch: 1_000_000)

        do {
            let store = LogHistoryStore(url: url)
            _ = await store.record(report([
                device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: at),
                device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: at),
            ], at: at))
        }

        let text = try String(contentsOf: url, encoding: .utf8)
        let torn = text + #"{"v":1,"type":"device","dev"#
        try torn.write(to: url, atomically: true, encoding: .utf8)

        let reopened = LogHistoryStore(url: url)
        #expect(await reopened.devices().count == 2, "a torn trailing line cost the whole file")
        #expect(await reopened.latestRun() != nil)
    }

    // ── The failure this prevents has a name and it nearly happened ────────────────
    //
    // `reload` skips a line it cannot decode; `compact` rewrites the file from the
    // ledger. Together, before the store kept them, that DELETED any line this build did
    // not understand — and the line a build does not understand is usually one a newer
    // build wrote. Schema 3 added `addresses` to a device record, so an older binary
    // reading a current store drops every schema-3 device and erases them on its next
    // compaction.
    //
    // This is the guard for the next schema rather than that one, since the old reader is
    // where the fault was. What would make it fail: dropping the line, which is exactly
    // what the code did before `unreadable` existed, and which the `originalSurvives`
    // expectation below catches. The device count alone would NOT catch it — the two
    // real devices come back either way, which is why that assertion is not the point.
    @Test("A line from a newer schema survives compaction instead of being erased")
    func unknownLineSurvivesCompaction() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")

        // Well-formed JSON, one object on one line, and undecodable as a `Line`: a
        // version this build has never heard of. Not corrupt — the point is that it is
        // somebody else's valid record.
        let fromTheFuture =
            #"{"v":99,"type":"device","payload":{"unheard_of":true,"note":"schema 4"}}"#

        do {
            let store = LogHistoryStore(url: url, compactionThreshold: 12)
            let first = Timestamp(millisecondsSinceEpoch: 1_000_000)
            _ = await store.record(report([
                device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: first),
            ], at: first))
            let text = try String(contentsOf: url, encoding: .utf8)
            try (text + fromTheFuture + "\n").write(to: url, atomically: true, encoding: .utf8)

            // Past the threshold, so compaction certainly runs and rewrites from the
            // ledger — the moment the line used to disappear at.
            let reopened = LogHistoryStore(url: url, compactionThreshold: 12)
            for index in 1..<14 {
                let at = Timestamp(millisecondsSinceEpoch: Int64(1_000_000 + index * 1_000))
                _ = await reopened.record(report([
                    device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: at),
                    device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: at),
                ], at: at))
            }
        }

        let after = try String(contentsOf: url, encoding: .utf8)
        #expect(after.contains(fromTheFuture),
                "compaction erased a line written by a newer schema")
        let lines = try lineCount(of: url)
        #expect(lines < 30, "the file was never compacted, so this proves nothing")

        // And the store still works around it.
        let finally = LogHistoryStore(url: url)
        #expect(await finally.devices().count == 2, "the preserved line broke the reload")
        #expect(await finally.latestRun() != nil)
    }

    @Test("The file is one JSON object per line, greppable and line-truncatable")
    func formatIsLineOriented() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let at = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let store = LogHistoryStore(url: url)
        _ = await store.record(
            report([device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: at)], at: at)
        )

        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.hasSuffix("\n"), "a file not ending in a newline cannot be appended to safely")
        for line in text.split(separator: "\n") {
            #expect((try? JSONSerialization.jsonObject(with: Data(line.utf8))) != nil,
                    "a line was not a self-contained JSON object")
        }
        #expect(text.contains("C8:69:CD:5E:01:E1"), "the MAC should be greppable in the log")
    }

    // ── Sharing the file with something else that has it open ───────────────────
    //
    // The app and `zhen scan` write the same file on purpose, and an actor does
    // nothing about that: it orders the writers inside one process and knows nothing of
    // the one in the other terminal. Everything below is about that seam.
    //
    // Two stores in one process rather than two processes, and this is not a weakening
    // of the experiment. `flock` locks belong to the open file description, not to the
    // process — two `open` calls on one path are as independent as two programs, which
    // is exactly why POSIX record locks were not used and is pinned by its own test
    // below. Each store here opens its own descriptors and neither can see the other's
    // memory that matters: what they share is the file, which is the thing under test.
    // What this cannot reach is a second address space, and nothing in this design
    // depends on having one.

    @Test("Two writers racing on one file lose no run, compaction included")
    func concurrentWritersLoseNothing() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")

        let runs = 10
        // Low enough that compaction fires repeatedly DURING the race rather than once
        // at the end. Compaction is the operation that can delete another writer's work
        // rather than merely misorder it, so a race that never crosses one is a race
        // that skipped the interesting half.
        let stores = [
            LogHistoryStore(url: url, compactionThreshold: 25),
            LogHistoryStore(url: url, compactionThreshold: 25),
        ]

        func address(writer: Int, index: Int) -> String { "10.10.20.\(10 + writer * 100 + index)" }
        func hardware(writer: Int, index: Int) -> String { "AA:BB:CC:00:0\(writer):0\(index)" }

        await withTaskGroup(of: Void.self) { group in
            for writer in 0..<2 {
                group.addTask {
                    for index in 0..<runs {
                        let at = Timestamp(
                            millisecondsSinceEpoch: Int64(1_000_000 + (index * 2 + writer) * 1_000)
                        )
                        _ = await stores[writer].record(self.report([
                            self.device(
                                ip: address(writer: writer, index: index),
                                mac: hardware(writer: writer, index: index), at: at
                            ),
                        ], at: at))
                        // Hand the executor over, so the two writers interleave rather
                        // than each running to completion on its own thread.
                        await Task.yield()
                    }
                }
            }
        }

        // Every run that was appended is still in the file.
        let reopened = LogHistoryStore(url: url)
        let survivors = Set(await reopened.devices().map(\.device.primaryAddress.description))
        var expected: Set<String> = []
        for writer in 0..<2 {
            for index in 0..<runs { expected.insert(address(writer: writer, index: index)) }
        }
        #expect(survivors == expected,
                "lost \(expected.subtracting(survivors).sorted()) of \(expected.count) runs")
        #expect(await reopened.latestRun() != nil)

        // And the event log went through the same rewrites. Every device but the one
        // folded into an empty ledger is named in an event; the log losing them silently
        // is the same defect one table over.
        let details = await reopened.events().map(\.detail)
        let named = expected.filter { address in details.contains { $0.contains(address) } }
        #expect(named.count >= expected.count - 1,
                "\(expected.count - named.count) devices have no event naming them")

        // The race really did cross a compaction. Without one this file holds a device
        // line per record per fold — 210 of them for twenty folds — plus a run line
        // each; anything under a hundred lines is a file that was rewritten.
        let lines = try lineCount(of: url)
        #expect(lines < 100, "\(lines) lines: never compacted, so the race never crossed one")

        // Nothing was torn. Two appends landing on top of each other leave a line that
        // is half of one record and half of another, and the reader skips it silently —
        // which is how this would show up as a device quietly missing rather than as a
        // failure.
        let text = try String(contentsOf: url, encoding: .utf8)
        for line in text.split(separator: "\n") {
            #expect((try? JSONSerialization.jsonObject(with: Data(line.utf8))) != nil,
                    "a line was torn: \(line.prefix(120))")
        }
    }

    // The race above is the general case; this is the specific one it was written for,
    // without the concurrency, so it fails the same way every time.
    @Test("A compaction cannot delete a run another store recorded")
    func compactionKeepsTheOtherWriterRuns() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let t1 = Timestamp(millisecondsSinceEpoch: 1_000_000)
        let t2 = Timestamp(millisecondsSinceEpoch: 2_000_000)

        // Opened and read first, so anything it remembers about the file is from before
        // the other store wrote. This is an app sitting on the Devices screen.
        let app = LogHistoryStore(url: url, compactionThreshold: 1)
        #expect(await app.devices().isEmpty)

        // And this is `zhen scan` in a terminal, recording a device the app has
        // never seen.
        let terminal = LogHistoryStore(url: url)
        _ = await terminal.record(
            report([device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: t1)], at: t1)
        )

        // The app scans, crosses its threshold, and rewrites the file from what it knows.
        // What it knows has to include the terminal's run, or the rewrite is a deletion.
        _ = await app.record(
            report([device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: t2)], at: t2)
        )

        let reopened = LogHistoryStore(url: url)
        let survivors = Set(await reopened.devices().map(\.device.primaryAddress.description))
        #expect(survivors == ["10.10.20.2", "10.10.20.8"],
                "compaction wrote a snapshot of a stale ledger over the other store's run")
    }

    // Why the race above is allowed to be two stores rather than two processes, pinned
    // rather than asserted in a comment. `flock` is per open file description: a second
    // `open` of the same path is excluded by the first even from inside one program.
    // POSIX record locks are per process and would not be, which would make that test
    // prove nothing at all — and would make a second store in the app invisible to the
    // one the scan writes through.
    @Test("A second open of the same file is locked out, in the same process")
    func lockIsPerDescriptorNotPerProcess() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("lockable").path
        FileManager.default.createFile(atPath: path, contents: nil)

        let held = try #require(FileHandle(forUpdatingAtPath: path))
        defer { try? held.close() }
        let other = try #require(FileHandle(forUpdatingAtPath: path))
        defer { try? other.close() }

        #expect(flock(held.fileDescriptor, LOCK_EX) == 0)
        #expect(flock(other.fileDescriptor, LOCK_EX | LOCK_NB) == -1,
                "the second descriptor took a lock the first was holding")
        #expect(flock(held.fileDescriptor, LOCK_UN) == 0)
        #expect(flock(other.fileDescriptor, LOCK_EX | LOCK_NB) == 0,
                "the lock was not released")
        #expect(flock(other.fileDescriptor, LOCK_UN) == 0)
    }

    // The cross-process half, which used to be an argument in a comment.
    //
    // The test above it proves a second *descriptor* is excluded, and reasons from there
    // that a second *process* is too, because `flock` is per open file description. That
    // reasoning is correct and it is also exactly what would keep passing if someone
    // swapped `flock` for `fcntl` record locks — those are per process, a second open
    // from inside one program would no longer be excluded, and every same-process test
    // here would go green while the guarantee the store depends on had gone. So the
    // property gets a test in the only place it can actually be observed.
    //
    // The second process is `perl`, which is in the macOS base system and has `flock`
    // built in. `fork` is unavailable to Swift on Darwin, there is no `flock(1)` to
    // spawn, and a compiled helper would need a build product this package does not
    // otherwise have. The test skips rather than fails where perl is absent, because on
    // a machine without it this is unprovable rather than broken.
    //
    // A subprocess in a test is not the rule CONTRIBUTING sets. That rule is about how
    // zhen scans — no shelling out to reach the network — and a test of
    // cross-process locking cannot be written without a second process by definition.
    // Not on iOS, which has no `Process` and no second process an app may start.
    #if os(macOS) || os(Linux)
    @Test("A lock held by a different process excludes this one")
    func lockExcludesASecondProcess() async throws {
        let perl = "/usr/bin/perl"
        try #require(FileManager.default.isExecutableFile(atPath: perl),
                     "no perl, so cross-process locking cannot be observed here")

        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("history.ndjson.lock").path
        FileManager.default.createFile(atPath: path, contents: nil)

        // The child announces that it holds the lock and then keeps holding it. The
        // parent waits for that line rather than sleeping: a race test that opens with a
        // guess about timing is measuring the guess.
        let child = Process()
        child.executableURL = URL(fileURLWithPath: perl)
        child.arguments = ["-e", """
            open(my $f, '<', $ARGV[0]) or exit 10;
            flock($f, 2) or exit 11;
            $| = 1; print "locked\n";
            sleep 30;
            """, path]
        let out = Pipe()
        child.standardOutput = out
        try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }

        var announced = false
        let deadline = Date().addingTimeInterval(10)
        var buffer = Data()
        while Date() < deadline {
            let chunk = out.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            buffer.append(chunk)
            if String(decoding: buffer, as: UTF8.self).contains("locked") {
                announced = true
                break
            }
        }
        try #require(announced, "the child never reported holding the lock")

        // It is holding an exclusive lock, from its own address space. A non-blocking
        // attempt from here has to fail, and fail for that reason and not another.
        let mine = open(path, O_RDWR)
        try #require(mine >= 0)
        defer { close(mine) }
        #expect(flock(mine, LOCK_EX | LOCK_NB) == -1,
                "took a lock another process was holding")
        #expect(errno == EWOULDBLOCK, "refused for some reason other than the lock")

        // And it becomes available the moment that process is gone. The kernel releases
        // on close, which includes the holder dying, and that is why this design carries
        // no stale-lock detection and no recovery path to get wrong.
        //
        // SIGKILL, not `terminate()`. On Linux, Foundation spawns the child with the
        // spawning thread's signal mask, and a Swift concurrency thread blocks nearly
        // every signal — so SIGTERM sat pending until perl's `sleep 30` ran out, and this
        // test took thirty seconds to pass. A kill that cannot be blocked is also the
        // holder dying in the strongest sense, which is the case the claim is about.
        kill(child.processIdentifier, SIGKILL)
        child.waitUntilExit()
        #expect(flock(mine, LOCK_EX | LOCK_NB) == 0,
                "the lock outlived the process that held it")
        #expect(flock(mine, LOCK_UN) == 0)
    }
    #endif

    @Test("The lock lives beside the file, so compaction cannot replace it")
    func lockIsASidecar() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let at = Timestamp(millisecondsSinceEpoch: 1_000_000)

        // Threshold 1, so this records and immediately rewrites the file through a
        // rename — the operation that would strand a lock taken on the log itself.
        let store = LogHistoryStore(url: url, compactionThreshold: 1)
        _ = await store.record(
            report([device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: at)], at: at)
        )

        let lock = url.appendingPathExtension("lock")
        #expect(FileManager.default.fileExists(atPath: lock.path))
        let before = try FileManager.default.attributesOfItem(atPath: lock.path)[.systemFileNumber]
            as? Int
        _ = await store.record(
            report([device(ip: "10.10.20.3", mac: "C8:69:CD:5E:01:E2", at: at)], at: at)
        )
        let after = try FileManager.default.attributesOfItem(atPath: lock.path)[.systemFileNumber]
            as? Int
        #expect(before != nil && before == after,
                "the lock file was replaced, so two holders would lock different inodes")
    }

    // ── Retention ───────────────────────────────────────────────────────────────

    /// A clock the test moves by hand.
    ///
    /// Needed because retention applies when the file is replayed as well as when a run
    /// is folded in, so a store built on synthetic 1970-relative timestamps would have
    /// every one of them fall outside a thirty-day window measured from the real today.
    /// That is the store behaving correctly and the test lying about what time it is.
    final class TestClock: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Timestamp
        init(_ value: Timestamp) { self.value = value }
        var now: Timestamp { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ value: Timestamp) { lock.lock(); self.value = value; lock.unlock() }
    }

    // A prune that is not written down is a prune that undoes itself on the next open,
    // and in an append-only file that is the default outcome: the lines for the dropped
    // events are still there. This is the test that the deletion reaches the disk.
    @Test("Pruned events do not come back when the file is reopened")
    func retentionSurvivesAReopen() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let day: (Int) -> Timestamp = { Timestamp(millisecondsSinceEpoch: Int64($0) * 86_400_000) }

        let clock = TestClock(day(101))
        let store = LogHistoryStore(url: url, retention: .days(30), clock: { clock.now })
        let first = device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: day(100))
        let second = device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: day(101))
        _ = await store.record(report([first], at: day(100)))
        _ = await store.record(report([first, second], at: day(101)))
        #expect(await store.events().count == 1, "the second device should have appeared")

        // Ninety days later. The day-101 event is outside the window and goes.
        clock.set(day(191))
        _ = await store.record(report([first, second], at: day(191)))
        #expect(await store.events().isEmpty, "the event outside the window was kept")

        // And it is gone from the file, not merely from something held in memory. The
        // reopened store keeps everything, so anything it finds was genuinely on disk.
        let reopened = LogHistoryStore(url: url)
        #expect(await reopened.events().isEmpty, "the pruned event came back on reopen")
        #expect(await reopened.devices().count == 2,
                "retention took a device record with it: that device comes back as new")
        let facts = HostFacts(ip: IPv4Address("10.10.20.2")!, mac: MACAddress("C8:69:CD:5E:01:E1"))
        let seen = await reopened.firstSeen(for: [facts], in: IPv4Network("10.10.20.0/24")!)
        #expect(seen[IPv4Address("10.10.20.2")!] == day(100), "first-seen was pruned away")
    }

    // The defect this exists for: retention used to run only when a run was folded in,
    // so "keep events for 30 days" meant 30 days *of scanning*. A store opened and read
    // but never written kept handing back events the policy said were gone, and the
    // setting appeared to work right up until someone stopped scanning for a month.
    @Test("Retention applies when the file is opened, not only when a run is recorded")
    func retentionAppliesOnLoad() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let day: (Int) -> Timestamp = { Timestamp(millisecondsSinceEpoch: Int64($0) * 86_400_000) }

        // Written with no retention at all, so the file genuinely holds the events.
        let writer = LogHistoryStore(url: url)
        let first = device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: day(100))
        let second = device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: day(101))
        _ = await writer.record(report([first], at: day(100)))
        _ = await writer.record(report([first, second], at: day(101)))
        #expect(await writer.events().count == 1)

        // Now open the same file under a seven-day policy, ninety days later, and read.
        // Nothing is recorded — this is the case the old code could not reach.
        let clock = TestClock(day(191))
        let reader = LogHistoryStore(url: url, retention: .days(7), clock: { clock.now })
        #expect(await reader.events().isEmpty,
                "an event outside the window survived a read-only open")
        #expect(await reader.devices().count == 2,
                "retention took a device record with it")

        // The same store under a policy wide enough to include it still sees it, which
        // is what says the emptiness above is retention and not a broken read.
        let wide = LogHistoryStore(url: url, retention: .days(365), clock: { clock.now })
        #expect(await wide.events().count == 1)
    }

    @Test("A store keeps everything unless it is asked not to")
    func defaultRetentionIsForever() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.ndjson")
        let day: (Int) -> Timestamp = { Timestamp(millisecondsSinceEpoch: Int64($0) * 86_400_000) }

        // No retention argument: this is the command line, which has no such setting and
        // must not acquire one.
        let store = LogHistoryStore(url: url)
        let first = device(ip: "10.10.20.2", mac: "C8:69:CD:5E:01:E1", at: day(0))
        let second = device(ip: "10.10.20.8", mac: "52:A1:8A:5E:04:8A", at: day(1))
        _ = await store.record(report([first], at: day(0)))
        _ = await store.record(report([first, second], at: day(1)))
        _ = await store.record(report([first, second], at: day(10_000)))
        #expect(await store.events().count == 1, "an event was dropped by a store told to keep it")
    }

    private func lineCount(of url: URL) throws -> Int {
        try String(contentsOf: url, encoding: .utf8).split(separator: "\n").count
    }
}

@Suite("Where history lives is named, not derived")
struct HistoryNameTests {
    @Test("The store's names are the ones already on disk")
    func namesArePinned() {
        // These name history that already exists. A change to either is not a rename:
        // the next run opens an empty store beside the populated one and reports every
        // device as new, and nothing fails.
        #expect(HistoryLocation.overrideVariable == "ZHEN_HISTORY")
        #expect(HistoryLocation.directoryName == "zhen")
    }
}
