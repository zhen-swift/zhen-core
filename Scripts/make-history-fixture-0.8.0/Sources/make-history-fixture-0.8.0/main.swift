// A history store 0.8.0 wrote on top of one 0.7.0 wrote, for the migration gate (G2).
//
// `<in> <out>` copies the 0.7.0 fixture and folds five more days into it with this build's
// own `LogHistoryStore`, each host carrying a first-contact time, cold or warm:
//
//   day 6  discovery-only, cold cache: five hosts         (first samples; nothing changes)
//   day 7  discovery-only, warm: five hosts               (warm samples, never in P97)
//   day 8  discovery-only, cold: five hosts               (the printer slowest, as .12 is)
//   day 9  discovery-only, cold: five hosts, and a compaction, so the samples are written
//          by the snapshot as well as by the append
//   day 10 discovery-only, cold: five hosts
//   day 11 discovery-only, cold: the TV gone              (disappeared)
//
// Twenty-four cold samples in all: more than `ReachSettings.minimumSamples`, so a plan
// built from this file is not a first scan. The scans are synthetic, for the reason the
// 0.6.0 generator gives: the file is committed to a public repository.
import Foundation
import ZhenCore

let network = IPv4Network("10.10.20.0/24")!
// 2026-10-01T00:00:00Z, and a day per step, as the 0.7.0 generator counts them.
func day(_ number: Int) -> Timestamp {
    Timestamp(millisecondsSinceEpoch: 1_790_812_800_000 + Int64(number) * 86_400_000)
}

func host(_ ip: String, _ mac: String, name: String? = nil, contact: Double, cold: Bool) -> HostFacts {
    HostFacts(
        ip: IPv4Address(ip)!, mac: MACAddress(mac),
        allNames: name.map { [NameCandidate(value: $0, source: .mdns, rank: 1)] } ?? [],
        discoveredVia: [.probeReply],
        firstContact: .milliseconds(contact), firstContactCold: cold
    )
}

func run(_ hosts: [HostFacts], day number: Int, store: LogHistoryStore) async {
    let at = day(number)
    let firstSeen = await store.firstSeen(for: hosts, in: network)
    let devices = hosts.map {
        Device(observing: $0, in: network, firstSeen: firstSeen[$0.ip] ?? at, lastSeen: at)
    }
    let report = ScanReport(
        run: ScanRun(
            id: UUID(), startedAt: at, finishedAt: at, target: network, interface: "en0",
            engine: EngineDescriptor(name: "fixture", kind: .unprivileged, capabilities: []),
            outcome: .complete, mode: .discoveryOnly, timing: Timing()
        ),
        devices: devices
    )
    _ = await store.record(report)
}

/// Five hosts with the given first-contact times, in the order router, NAS, phone, TV, printer.
func network(_ times: [Double?], cold: Bool) -> [HostFacts] {
    let all: [(String, String, String?)] = [
        ("10.10.20.1", "20:1C:3A:00:00:01", nil),
        ("10.10.20.10", "20:1C:3A:00:00:10", "Storage"),
        ("10.10.20.42", "DA:00:00:00:00:03", "Pixel"),
        ("10.10.20.50", "20:1C:3A:00:00:50", "Living Room TV"),
        ("10.10.20.60", "20:1C:3A:00:00:60", "Printer"),
    ]
    return zip(all, times).compactMap { entry, time in
        time.map { host(entry.0, entry.1, name: entry.2, contact: $0, cold: cold) }
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: make-history-fixture-0.8.0 <0.7.0 history> <out>\n".utf8))
    exit(64)
}
let input = URL(fileURLWithPath: arguments[0])
let output = URL(fileURLWithPath: arguments[1])
try? FileManager.default.removeItem(at: output)
try? FileManager.default.removeItem(at: output.appendingPathExtension("lock"))
try FileManager.default.copyItem(at: input, to: output)

let store = LogHistoryStore(url: output)
await run(network([212.0, 230.5, 640.0, 455.25, 981.0], cold: true), day: 6, store: store)
await run(network([1.5, 2.25, 38.0, 4.0, 3.75], cold: false), day: 7, store: store)
await run(network([205.5, 228.0, 702.75, 461.0, 1_012.5], cold: true), day: 8, store: store)
// A threshold of one line makes this fold a compaction.
let compacting = LogHistoryStore(url: output, compactionThreshold: 1)
await run(network([219.0, 233.25, 588.5, 449.0, 1_034.0], cold: true), day: 9, store: compacting)
let last = LogHistoryStore(url: output)
await run(network([214.5, 231.0, 611.25, 470.5, 1_003.0], cold: true), day: 10, store: last)
await run(network([208.0, 226.5, 655.0, nil, 996.25], cold: true), day: 11, store: last)
try? FileManager.default.removeItem(at: output.appendingPathExtension("lock"))
print("wrote \(output.path) with this checkout of zhen-core (ZhenVersion \(ZhenVersion.current))")
