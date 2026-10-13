// A history store written by zhen-core 0.6.0, for the 0.7.0 migration gate.
//
// Every line in the output is written by 0.6.0's `LogHistoryStore` — the fold, the append
// and the compaction are its own. The scans are synthetic, because a real capture names
// real devices on a real network and this file is committed to a public repository; the
// identifiers are invented and the addresses are the documentation range the tests use.
//
// What it stages, so the gate has every shape 0.6.0 could write:
//
//   day 0  a deep scan: four devices, ports on two          (first run: no events)
//   day 1  discovery-only: the TV gone, the phone moved,    (disappeared, ipChanged,
//          the NAS renamed                                    renamed)
//   day 2  a deep scan: the TV back, a printer new, a port  (appeared ×2)
//          closed, the phone on a rotated MAC, named
//          — then one line a later build wrote, by hand
//   day 3  discovery-only: the phone on a third MAC, with   (appeared — a split record)
//          no name to recognise it by
//   day 4  a full scan: the phone, named, on that MAC       (merged — and 0.6.0 compacts,
//                                                            carrying the later line through)
//   day 5  a deep scan, appended after the snapshot
import Foundation
import ZhenCore

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: make-history-fixture <output.ndjson>\n".utf8))
    exit(64)
}
let output = URL(fileURLWithPath: CommandLine.arguments[1])
try? FileManager.default.removeItem(at: output)
try? FileManager.default.removeItem(at: output.appendingPathExtension("lock"))

let network = IPv4Network("10.10.20.0/24")!
// 2026-09-01T00:00:00Z, and a day per step.
func day(_ number: Int) -> Timestamp {
    Timestamp(millisecondsSinceEpoch: 1_788_220_800_000 + Int64(number) * 86_400_000)
}

func host(
    _ ip: String, _ mac: String, name: String? = nil, ports: [(UInt16, PortState)] = []
) -> HostFacts {
    HostFacts(
        ip: IPv4Address(ip)!, mac: MACAddress(mac),
        allNames: name.map { [NameCandidate(value: $0, source: .mdns, rank: 1)] } ?? [],
        ports: ports.map { PortObservation(port: $0.0, state: $0.1) }
    )
}

func run(_ hosts: [HostFacts], day number: Int, mode: ScanMode, store: LogHistoryStore) async {
    let at = day(number)
    let firstSeen = await store.firstSeen(for: hosts, in: network)
    let devices = hosts.map {
        Device(observing: $0, in: network, firstSeen: firstSeen[$0.ip] ?? at, lastSeen: at)
    }
    let report = ScanReport(
        run: ScanRun(
            id: UUID(), startedAt: at, finishedAt: at, target: network, interface: "en0",
            engine: EngineDescriptor(name: "fixture", kind: .unprivileged, capabilities: []),
            outcome: .complete, mode: mode, timing: Timing()
        ),
        devices: devices
    )
    _ = await store.record(report)
}

let router = "20:1C:3A:00:00:01"
let nas = "20:1C:3A:00:00:10"
let tv = "20:1C:3A:00:00:50"
let printer = "20:1C:3A:00:00:60"

let store = LogHistoryStore(url: output)
await run([
    host("10.10.20.1", router, ports: [(53, .open), (80, .open), (443, .closed)]),
    host("10.10.20.10", nas, name: "Storage", ports: [(22, .open), (445, .open)]),
    host("10.10.20.40", "DA:00:00:00:00:01", name: "Pixel"),
    host("10.10.20.50", tv, name: "Living Room TV"),
], day: 0, mode: .full, store: store)
await run([
    host("10.10.20.1", router),
    host("10.10.20.10", nas, name: "Archive"),
    host("10.10.20.41", "DA:00:00:00:00:01", name: "Pixel"),
], day: 1, mode: .discoveryOnly, store: store)
await run([
    host("10.10.20.1", router, ports: [(53, .open), (80, .open), (443, .closed)]),
    host("10.10.20.10", nas, name: "Archive", ports: [(22, .closed), (445, .open)]),
    host("10.10.20.41", "DA:00:00:00:00:02", name: "Pixel"),
    host("10.10.20.50", tv, name: "Living Room TV"),
    host("10.10.20.60", printer, name: "Printer"),
], day: 2, mode: .full, store: store)

// A line a later build wrote. 0.6.0 cannot decode it, and keeps it verbatim.
let later = #"{"v":2,"type":"annotation","annotation":{"note":"written by a later build"}}"#
let handle = try FileHandle(forWritingTo: output)
try handle.seekToEnd()
try handle.write(contentsOf: Data((later + "\n").utf8))
try handle.close()

await run([
    host("10.10.20.1", router),
    host("10.10.20.10", nas, name: "Archive"),
    host("10.10.20.42", "DA:00:00:00:00:03"),
    host("10.10.20.50", tv, name: "Living Room TV"),
    host("10.10.20.60", printer, name: "Printer"),
], day: 3, mode: .discoveryOnly, store: store)
await run([
    host("10.10.20.1", router),
    host("10.10.20.10", nas, name: "Archive"),
    host("10.10.20.42", "DA:00:00:00:00:03", name: "Pixel"),
    host("10.10.20.50", tv, name: "Living Room TV"),
    host("10.10.20.60", printer, name: "Printer"),
], day: 4, mode: .full, store: store)
await run([
    host("10.10.20.1", router, ports: [(53, .open), (80, .open), (443, .closed)]),
    host("10.10.20.10", nas, name: "Archive", ports: [(22, .closed), (445, .open)]),
    host("10.10.20.42", "DA:00:00:00:00:03", name: "Pixel"),
    host("10.10.20.50", tv, name: "Living Room TV", ports: [(7000, .open)]),
    host("10.10.20.60", printer, name: "Printer", ports: [(631, .open), (9100, .open)]),
], day: 5, mode: .full, store: store)

try? FileManager.default.removeItem(at: output.appendingPathExtension("lock"))
print("wrote \(output.path) with zhen-core \(ZhenVersion.current)")
