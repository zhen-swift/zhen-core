import Foundation
import Testing
@testable import ZhenCore

// The rules, tested as rules.
//
// `HistoryLedger` is where folding a run into history MEANS something, and it is a value
// type with no I/O precisely so that the meaning can be checked without a file, a
// database or a clock. Until this file existed the rules were only reachable through a
// store, which tested the rules and the storage together and would have reported a
// storage failure for a rule defect.
@Suite("What the ledger keeps, and for how long")
struct HistoryLedgerTests {
    static let network = IPv4Network("10.10.20.0/24")!
    /// Day zero. Every stamp below is this plus a whole number of days, so an assertion
    /// about "thirty days" is arithmetic a reader can do in their head.
    static let epoch: Int64 = 1_700_000_000_000

    private func day(_ number: Int) -> Timestamp {
        Timestamp(millisecondsSinceEpoch: Self.epoch + Int64(number) * 86_400_000)
    }

    private func device(ip: String, mac: String, at: Timestamp) -> Device {
        Device(
            observing: HostFacts(ip: IPv4Address(ip)!, mac: MACAddress(mac)),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    private func report(_ devices: [Device], at: Timestamp) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: at, finishedAt: at,
                target: Self.network, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    /// A hundred days of history: one new device per day, every one of them still
    /// answering, so each day after the first derives exactly one `appeared` and nothing
    /// else. A hundred days rather than a year because the addresses have to stay
    /// distinct — two devices sharing one would derive address churn, and this suite is
    /// about what is kept rather than about what is derived.
    private func aHundredDays(retention: RetentionPolicy) -> HistoryLedger {
        var ledger = HistoryLedger(retention: retention)
        var seen: [Device] = []
        for index in 0..<100 {
            let at = day(index)
            seen.append(device(ip: "10.10.20.\(20 + index)",
                               mac: "AA:BB:CC:00:00:\(hex(index))", at: at))
            ledger.fold(report(seen, at: at))
        }
        return ledger
    }

    private func hex(_ value: Int) -> String {
        let digits = "0123456789ABCDEF"
        let high = digits[digits.index(digits.startIndex, offsetBy: (value / 16) % 16)]
        let low = digits[digits.index(digits.startIndex, offsetBy: value % 16)]
        return "\(high)\(low)"
    }

    @Test("Forever keeps everything, which is what the command line opens with")
    func foreverKeepsEverything() {
        let ledger = aHundredDays(retention: .forever)
        #expect(ledger.retention == .forever, "the default is not forever")
        // Ninety-nine: one device joins on each day but the first, and a first run is
        // quiet by design.
        #expect(ledger.events().count == 99, "an event was dropped under 'forever'")
    }

    @Test("A default-constructed ledger keeps everything, so a caller has to ask to prune")
    func defaultIsForever() {
        #expect(HistoryLedger().retention == .forever)
        #expect(HistoryLedger(records: [:], log: [], latestRun: nil).retention == .forever)
    }

    @Test("Thirty days keeps the last thirty days of events and drops the rest")
    func thirtyDaysDropsTheOlder() {
        let ledger = aHundredDays(retention: .days(30))
        let events = ledger.events()
        #expect(!events.isEmpty, "everything was pruned")
        // The last fold is stamped day 99, so the window opens on day 69 and the events
        // of days 69 through 99 are kept: thirty-one of them.
        let cutoff = day(99 - 30)
        #expect(events.allSatisfy { $0.at >= cutoff }, "an event older than the window survived")
        #expect(events.count == 31, "kept \(events.count) events rather than the window's 31")
    }

    // The constraint that decides whether retention is correct at all. Events are
    // housekeeping; a device record is identity. Dropping one makes a device that has
    // been on the network for a year come back as newly discovered — a false alarm about
    // the exact thing this product exists to report accurately, raised by a settings
    // picker.
    @Test("Retention drops events and never a device record")
    func devicesAreNeverPruned() {
        let kept = aHundredDays(retention: .forever)
        let pruned = aHundredDays(retention: .days(30))
        #expect(pruned.devices().count == kept.devices().count,
                "retention deleted \(kept.devices().count - pruned.devices().count) devices")
        #expect(pruned.events().count < kept.events().count, "nothing was pruned at all")

        // And the identity those records carry is intact: the device first seen on day
        // zero still says day zero, so it is not about to be reported as new.
        let facts = HostFacts(ip: IPv4Address("10.10.20.20")!, mac: MACAddress("AA:BB:CC:00:00:00"))
        let firstSeen = pruned.firstSeen(for: [facts], in: Self.network)
        #expect(firstSeen[IPv4Address("10.10.20.20")!] == day(0),
                "a pruned ledger lost the first-seen that keeps a device one device")
    }

    // The ledger has no clock, which is what makes a rule about elapsed time testable in
    // microseconds. It also means a store replaying an old file prunes against the run
    // it is folding rather than against the moment it happened to be opened.
    @Test("The window is measured from the run being folded, not from the wall clock")
    func cutoffComesFromTheRun() {
        var ledger = HistoryLedger(retention: .days(30))
        // Two runs a hundred days apart, both of them years in the past.
        let old = device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1", at: day(0))
        ledger.fold(report([old], at: day(0)))
        ledger.fold(report([old, device(ip: "10.10.20.3", mac: "C8:69:CD:7F:33:E2", at: day(1))],
                           at: day(1)))
        #expect(ledger.events().count == 1, "the second run derived no event to prune")

        ledger.fold(report([old], at: day(101)))
        #expect(ledger.events().allSatisfy { $0.at >= day(71) },
                "an event from day one survived a fold stamped at day 101")

        // `.forever` is not "a very long time": a run stamped in the far future must not
        // empty a log that a person asked to keep.
        var forever = HistoryLedger(retention: .forever)
        forever.fold(report([old], at: day(0)))
        forever.fold(report([old, device(ip: "10.10.20.4", mac: "C8:69:CD:7F:33:E3", at: day(1))],
                            at: day(1)))
        forever.fold(report([old], at: day(100_000)))
        #expect(forever.events().count == 2, "'forever' dropped an event")
    }

    // What the store needs to know and the returned events do not say. An append-only
    // file can express "these events happened"; it cannot express "these events are
    // gone", so a store that is not told has to be assumed not to have written it down.
    @Test("A fold reports how many events it pruned, because a deletion is not an append")
    func foldReportsThePrune() {
        var ledger = HistoryLedger(retention: .days(30))
        let old = device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1", at: day(0))
        let second = device(ip: "10.10.20.3", mac: "C8:69:CD:7F:33:E2", at: day(1))
        #expect(ledger.fold(report([old], at: day(0))).prunedEvents == 0)
        #expect(ledger.fold(report([old, second], at: day(1))).prunedEvents == 0)

        let late = ledger.fold(report([old, second], at: day(100)))
        #expect(late.prunedEvents == 1, "the day-one event was not reported as pruned")
        #expect(late.events.isEmpty, "the quiet run derived an event it should not have")
    }

    // ── Identity resolution ─────────────────────────────────────────────────────
    //
    // Two records carrying the same identifier is not a hypothetical. A record
    // accumulates every key it has ever presented, the file is written by two processes
    // and read back by a third, and nothing anywhere stops one key ending up in two join
    // sets. When it happens, which record a run folds into decided itself by Dictionary
    // hash order — so the same file could fold the same run two different ways on two
    // different runs, and a device's history would move between records for no reason
    // anybody could see. Determinism about identity is the whole job of that function.

    /// A record with a primary key of its own and one shared identifier beside it.
    private func colliding(
        ip: String, mac: String, ordinal: Int, firstSeen: Timestamp, sharing: HostIdentifier
    ) -> (HostIdentifier, HistoryLedger.Record) {
        let key = HostIdentifier.fromMAC(MACAddress(mac)!)
        return (key, HistoryLedger.Record(
            device: device(ip: ip, mac: mac, at: firstSeen), firstSeen: firstSeen,
            lastRunID: UUID(), identifiers: [key, sharing], ordinal: ordinal
        ))
    }

    /// A device presenting the shared name and a MAC neither record has seen, so the
    /// shared identifier is the only thing it can be joined on.
    private func claimant(at: Timestamp) -> Device {
        Device(
            observing: HostFacts(
                ip: IPv4Address("10.10.20.77")!, mac: MACAddress("F2:11:22:33:44:55"),
                allNames: [NameCandidate(value: "living-room", source: .mdns, rank: 1)]
            ),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    @Test("Two records carrying one identifier resolve to the same record every time")
    func collisionsResolveDeterministically() {
        let shared = HostIdentifier.mdnsInstance("living-room")
        let older = colliding(ip: "10.10.20.20", mac: "AA:BB:CC:00:00:01",
                              ordinal: 3, firstSeen: day(0), sharing: shared)
        let newer = colliding(ip: "10.10.20.21", mac: "AA:BB:CC:00:00:02",
                              ordinal: 9, firstSeen: day(10), sharing: shared)

        // Built repeatedly in both insertion orders: a Dictionary's iteration order
        // depends on how it was built as well as on the process's hash seed, so one
        // construction proves nothing about the next.
        var answers: Set<Timestamp> = []
        for trial in 0..<20 {
            var records: [HostIdentifier: HistoryLedger.Record] = [:]
            for pair in (trial.isMultiple(of: 2) ? [older, newer] : [newer, older]) {
                records[pair.0] = pair.1
            }
            var ledger = HistoryLedger(
                records: records, log: [],
                latestRun: report([], at: day(20)).run
            )
            ledger.fold(report([claimant(at: day(21))], at: day(21)))
            // Whichever record absorbed the observation now carries its address, and the
            // first-seen it reports is the one that says which record that was.
            let moved = ledger.devices().first { $0.device.primaryAddress.description == "10.10.20.77" }
            #expect(moved != nil, "the observation joined nothing at all")
            let facts = HostFacts(
                ip: IPv4Address("10.10.20.77")!, mac: MACAddress("F2:11:22:33:44:55"),
                allNames: [NameCandidate(value: "living-room", source: .mdns, rank: 1)]
            )
            if let seen = ledger.firstSeen(for: [facts], in: Self.network)[
                IPv4Address("10.10.20.77")!
            ] {
                answers.insert(seen)
            }
            // One, because two records sharing an mDNS instance are two records for
            // one device, and reconciliation joins them. Before that existed this
            // asserted 2: the observation resolved to one of them deterministically and
            // the other was left standing for the next scan to find again.
            #expect(ledger.devices().count == 1, "the colliding records did not join")
        }

        #expect(answers.count == 1, "the same collision resolved \(answers.count) different ways")
        // Oldest wins, which is the only choice that stays the same as records are added.
        #expect(answers.first == day(0), "the newer record won rather than the older one")
    }

    @Test("A record keyed by the identifier beats one that merely carries it")
    func primaryKeyBeatsJoinSet() {
        let shared = HostIdentifier.mdnsInstance("living-room")
        // The claimant is younger — ordinal 40 against 1 — so if the join set won, it
        // would win here, and the rule about age would be the only rule there was.
        let carrier = colliding(ip: "10.10.20.20", mac: "AA:BB:CC:00:00:01",
                                ordinal: 1, firstSeen: day(0), sharing: shared)
        let owner = HistoryLedger.Record(
            device: device(ip: "10.10.20.30", mac: "AA:BB:CC:00:00:03", at: day(5)),
            firstSeen: day(5), lastRunID: UUID(), identifiers: [shared], ordinal: 40
        )
        var ledger = HistoryLedger(
            records: [carrier.0: carrier.1, shared: owner], log: [],
            latestRun: report([], at: day(20)).run
        )
        let facts = HostFacts(
            ip: IPv4Address("10.10.20.77")!, mac: MACAddress("F2:11:22:33:44:55"),
            allNames: [NameCandidate(value: "living-room", source: .mdns, rank: 1)]
        )

        // Asked BEFORE any fold, because that is the only window in which the question
        // has two possible answers. `firstSeen(for:in:)` resolves and does not mutate,
        // so this is the resolution rule on its own: of two records presenting one
        // identifier, the one that claimed it as its primary key wins over the one
        // merely carrying it in a join set, even though the carrier is far older.
        #expect(ledger.firstSeen(for: [facts], in: Self.network)[IPv4Address("10.10.20.77")!]
                == day(5),
                "the record that claimed the identifier as its key did not win")

        ledger.fold(report([claimant(at: day(21))], at: day(21)))

        // And after the fold the question stops being askable, because the two records
        // were never two devices. They join, and the survivor is the OLDER one — the
        // rule `match` already stated, now applied to the records themselves rather
        // than only to the observation being placed.
        #expect(ledger.devices().count == 1, "the colliding records did not join")
        #expect(ledger.firstSeen(for: [facts], in: Self.network)[IPv4Address("10.10.20.77")!]
                == day(0),
                "the merge kept the younger record's history")
        // The newest observation still wins the device, so a join never rolls an
        // address backwards to whatever the older record last saw.
        #expect(ledger.devices().first?.device.primaryAddress.description == "10.10.20.77")
    }

    // ── Reconciliation ──────────────────────────────────────────────────────────
    //
    // The case this exists for, from a real history file: a Mac whose private Wi-Fi
    // address rotated was recorded twice. A discovery-only scan saw it with no naming
    // stage, so its only key was the new MAC and nothing matched; a later full scan saw
    // it with its mDNS name, matched the original record, and absorbed the new MAC into
    // that record's join set. From then on the device oscillated by scan mode — full
    // scans resolving to one row, discovery-only scans to the other — and the device
    // list showed one machine twice.
    //
    // The comment above `resolve` had claimed all along that "a missed merge is
    // recoverable, since the next observation carrying a shared key joins the two
    // records". Nothing joined them. These are the tests that make that sentence true.

    /// A device carrying a name and a MAC, which is what a full scan produces.
    private func named(
        ip: String, mac: String, name: String, at: Timestamp
    ) -> Device {
        Device(
            observing: HostFacts(
                ip: IPv4Address(ip)!, mac: MACAddress(mac),
                allNames: [NameCandidate(value: name, source: .mdns, rank: 1)]
            ),
            in: Self.network, firstSeen: at, lastSeen: at
        )
    }

    @Test("A rotated MAC recorded twice is joined by the name both records carry")
    func rotationJoinsTheSplitRecords() {
        // Exactly the shape found in the real file: an older record keyed by the MAC the
        // device used to have and carrying its mDNS name, and a younger one keyed by the
        // MAC it has now and carrying nothing else, because the scan that minted it had
        // no naming stage to give it anything else.
        let old = HostIdentifier.fromMAC(MACAddress("52:A1:8A:E0:7A:8A")!)
        let new = HostIdentifier.fromMAC(MACAddress("D6:0A:97:FE:72:9C")!)
        let name = HostIdentifier.mdnsInstance("jc's macbook pro")
        var ledger = HistoryLedger(
            records: [
                old: HistoryLedger.Record(
                    device: named(ip: "10.10.20.88", mac: "52:A1:8A:E0:7A:8A",
                                  name: "JC's MacBook Pro", at: day(0)),
                    firstSeen: day(0), lastRunID: UUID(),
                    identifiers: [old, name], ordinal: 1
                ),
                new: HistoryLedger.Record(
                    device: device(ip: "10.10.20.131", mac: "D6:0A:97:FE:72:9C", at: day(9)),
                    firstSeen: day(9), lastRunID: UUID(),
                    identifiers: [new], ordinal: 7
                ),
            ],
            log: [], latestRun: report([], at: day(10)).run
        )

        // The full scan that proves it: one device, both the name and the current MAC.
        ledger.fold(report(
            [named(ip: "10.10.20.131", mac: "D6:0A:97:FE:72:9C",
                   name: "JC's MacBook Pro", at: day(11))],
            at: day(11)
        ))

        #expect(ledger.devices().count == 1, "the split records did not join")
        // Asserted on the record rather than on `devices()`, which returns the device
        // and its presence and deliberately not the identity machinery behind it.
        let survivor = ledger.records[old]
        #expect(survivor != nil, "the older record was the one absorbed")
        #expect(survivor?.firstSeen == day(0), "the join lost the earlier history")
        #expect(survivor?.ordinal == 1, "the younger record survived instead of the older")
        // Both MACs stay in the join set, so an observation carrying either still lands
        // on this device rather than minting a third record.
        #expect(survivor?.identifiers.contains(old) == true)
        #expect(survivor?.identifiers.contains(new) == true)
        #expect(survivor?.device.primaryAddress.description == "10.10.20.131",
                "the join rolled the address back to what the older record last saw")
    }

    @Test("A merge says so, once per device rather than once per pair")
    func mergeIsAnnounced() {
        let name = HostIdentifier.mdnsInstance("living-room")
        let a = colliding(ip: "10.10.20.20", mac: "AA:BB:CC:00:00:01",
                          ordinal: 1, firstSeen: day(0), sharing: name)
        let b = colliding(ip: "10.10.20.21", mac: "AA:BB:CC:00:00:02",
                          ordinal: 2, firstSeen: day(1), sharing: name)
        let c = colliding(ip: "10.10.20.22", mac: "AA:BB:CC:00:00:03",
                          ordinal: 3, firstSeen: day(2), sharing: name)
        var ledger = HistoryLedger(
            records: [a.0: a.1, b.0: b.1, c.0: c.1], log: [],
            latestRun: report([], at: day(20)).run
        )
        let fold = ledger.fold(report([claimant(at: day(21))], at: day(21)))

        #expect(ledger.devices().count == 1, "three records for one device did not join")
        #expect(fold.mergedRecords == 1, "the store was not told a record was removed")
        let merges = fold.events.filter { $0.kind == .merged }
        #expect(merges.count == 1, "a three-way join announced itself more than once")
        #expect(merges.first?.detail.contains("three devices") == true,
                "the event did not say how many records were joined")

        // And nothing was reported as having vanished. A record absorbed into its
        // survivor has not disappeared from the network; saying so would raise the
        // alarm this product exists to raise honestly.
        #expect(!fold.events.contains { $0.kind == .disappeared },
                "a merged record was reported as a device that left")
    }

    @Test("Records that share only an address are left alone")
    func leasesDoNotJoin() {
        // The guard, at ledger level. Two devices that held one address at different
        // times both carry that lease key for good — one of them with a burned-in MAC
        // and one with a randomized one, which cannot be the same machine. Joining on
        // that evidence is the collapse `resolve` defers ipLease to avoid, and a
        // wrong merge is the one thing here that cannot be undone.
        let lease = HostIdentifier.ipLease(IPv4Address("10.10.20.117")!, in: Self.network)
        let universal = HostIdentifier.fromMAC(MACAddress("20:1C:3A:91:9E:54")!)
        let randomized = HostIdentifier.fromMAC(MACAddress("BE:C4:1B:56:9B:16")!)
        var ledger = HistoryLedger(
            records: [
                universal: HistoryLedger.Record(
                    device: device(ip: "10.10.20.117", mac: "20:1C:3A:91:9E:54", at: day(0)),
                    firstSeen: day(0), lastRunID: UUID(),
                    identifiers: [universal, lease], ordinal: 1
                ),
                randomized: HistoryLedger.Record(
                    device: device(ip: "10.10.20.118", mac: "BE:C4:1B:56:9B:16", at: day(5)),
                    firstSeen: day(5), lastRunID: UUID(),
                    identifiers: [randomized, lease], ordinal: 2
                ),
            ],
            log: [], latestRun: report([], at: day(10)).run
        )
        let fold = ledger.fold(report(
            [device(ip: "10.10.20.117", mac: "20:1C:3A:91:9E:54", at: day(11))], at: day(11)
        ))

        #expect(ledger.devices().count == 2, "two devices merged on a shared DHCP lease")
        #expect(fold.mergedRecords == 0)
    }

    @Test("A policy set after the ledger exists applies at the next fold")
    func policyCanChange() {
        var ledger = HistoryLedger()
        let old = device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1", at: day(0))
        let second = device(ip: "10.10.20.3", mac: "C8:69:CD:7F:33:E2", at: day(1))
        ledger.fold(report([old], at: day(0)))
        ledger.fold(report([old, second], at: day(1)))
        #expect(ledger.events().count == 1)

        // A person opens Settings and chooses thirty days. Nothing is pruned yet —
        // pruning happens when history changes — and the next scan applies it.
        ledger.retention = .days(30)
        #expect(ledger.events().count == 1, "changing the setting rewrote history by itself")
        ledger.fold(report([old, second], at: day(100)))
        #expect(ledger.events().isEmpty, "the new policy was not applied to the next fold")
    }
}
