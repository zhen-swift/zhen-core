import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// Which table a run gets, and the fact that nobody typed the number.
//
// Stage 3 shipped `longFormThreshold = 9`: `PORTS-rendering.md`'s arithmetic — a port
// column is five wide plus a two-space gutter, so eight ports is 56 columns and fits 80
// beside a 15-column address — typed in by hand. Stage 4's gate is that the threshold
// be DERIVED from measured column width against the detected terminal width.
//
// The derivation is only worth anything if it agrees with what is drawn, so the tests
// below compare the DECISION against the RENDERED OUTPUT rather than against each
// other. A rule that says the matrix fits while the matrix overflows is the failure
// this replaces, one level up.

private func report(tcp: [UInt16], hosts: Int = 3) -> ScanReport {
    let network = IPv4Network("10.10.20.0/24")!
    let stamp = Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)
    let facts = (0..<hosts).map { index in
        HostFacts(
            ip: IPv4Address("10.10.20.\(index + 1)")!,
            mac: MACAddress("78:20:51:5E:07:28"), ttl: 64,
            rtt: RTTSample(measured: .microseconds(412)),
            ports: tcp.map {
                PortObservation(port: $0, proto: .tcp,
                                state: $0 % 7 == 0 ? .open : .filtered)
            },
            discoveredVia: [.probeReply])
    }
    return ScanReport(
        run: ScanRun(
            id: UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!,
            startedAt: stamp, finishedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_240),
            target: network, interface: "en0",
            engine: EngineDescriptor(name: "darwin-unprivileged", kind: .unprivileged,
                                     capabilities: [.icmpSweep, .connectScan]),
            outcome: .complete,
            timing: Timing(stages: [StageTiming(stage: .discovery, elapsedMillis: 240)],
                           counters: ProbeCounterSnapshot(probesSent: 1, repliesSeen: 1,
                                                          peakConcurrency: 1, inFlight: 0))),
        devices: facts.map { Device(observing: $0, in: network, lastSeen: stamp) },
        degradations: [])
}

private func rendered(_ report: ScanReport, width: Int,
                      preference: PortView.Preference = .auto) -> String {
    Out.capturing {
        TextRenderer(quiet: true, color: false, progressColor: false,
                     width: width, portsView: preference).finish(report)
    }.out
}

private func widestLine(_ text: String) -> Int {
    text.split(separator: "\n").map(\.count).max() ?? 0
}

/// Which table was drawn.
///
/// By the section heading, NOT by the glyphs. `PortCell.filtered.glyph` is U+00B7, the
/// middle dot — and so is the separator in the long form's own footer, `5 open · 0
/// closed`. Testing for the glyph reported every long form as a matrix, and the gate
/// below passed 100 matrix renderings and zero long forms without noticing.
private func isMatrix(_ text: String) -> Bool {
    !text.contains(PortLongForm.title)
}

@Suite("The threshold is derived, and it agrees with what is drawn")
struct DerivedThresholdTests {
    /// The largest port count whose matrix still fits, found by asking rather than told.
    private func largestFittingPortCount(width: Int) -> Int {
        var largest = 0
        for count in 1...40 {
            let ports = (1...count).map { UInt16($0 * 10) }
            guard let matrix = PortMatrix(report(tcp: ports).devices) else { continue }
            if PortView.matrixFits(matrix, width: width) { largest = count }
        }
        return largest
    }

    @Test("At 80 columns the derivation lands where the document's arithmetic said")
    func eightyColumns() {
        // Not asserted as 8. The document DERIVES 8 from column arithmetic; this
        // recomputes it from the real columns and reports what it got. If the address
        // or name column grows, this number moves and that is correct — what would be
        // wrong is a literal that did not move with it.
        let largest = largestFittingPortCount(width: 80)
        #expect(largest >= 4 && largest <= 12,
                Comment(rawValue: "80 columns fits \(largest) port columns, which is far "
                        + "from the 8 the rendering document's arithmetic gives — one of "
                        + "the two is wrong"))
        print("derived: 80 columns fits \(largest) port columns")
    }

    @Test("A wider terminal fits more, which is the whole point of deriving it")
    func widerFitsMore() {
        let narrow = largestFittingPortCount(width: 80)
        let wide = largestFittingPortCount(width: 200)
        #expect(wide > narrow,
                Comment(rawValue: "200 columns fits \(wide) and 80 fits \(narrow) — the "
                        + "threshold is not responding to the width at all, which is what "
                        + "the hand-typed constant did"))
        print("derived: 200 columns fits \(wide) port columns")
    }

    /// **The gate.** The decision and the drawing must agree.
    @Test("Whenever auto picks the matrix, the matrix actually fits the terminal")
    func theMatrixItPicksAlwaysFits() {
        var checkedMatrix = 0, checkedLong = 0
        for width in [60, 80, 100, 140, 200] {
            for count in 1...20 {
                let ports = (1...count).map { UInt16($0 * 10) }
                let text = rendered(report(tcp: ports), width: width)
                if isMatrix(text) {
                    checkedMatrix += 1
                    #expect(widestLine(text) <= width,
                            Comment(rawValue: "auto chose a matrix for \(count) ports at "
                                    + "\(width) columns and it drew \(widestLine(text)) wide"))
                } else {
                    checkedLong += 1
                }
            }
        }
        #expect(checkedMatrix > 0, "no width and port count produced a matrix at all")
        #expect(checkedLong > 0, "no width and port count produced a long form at all")
        print("checked \(checkedMatrix) matrix renderings and \(checkedLong) long forms")
    }

    @Test("The long form also stays inside the terminal, once the service column is capped")
    func longFormFitsToo() {
        // Stage 3 left the SERVICE column unbounded and recorded it as stage 4's job.
        let long = [PortObservation(port: 70, proto: .tcp, state: .open,
                                    service: ServiceIdentity(
                                        name: "http",
                                        product: String(repeating: "VeryLongProductName", count: 4),
                                        version: "1.2.3.4.5", evidence: .banner),
                                    rtt: RTTSample(measured: .microseconds(4210)))]
        let network = IPv4Network("10.10.20.0/24")!
        let facts = HostFacts(ip: IPv4Address("10.10.20.1")!, ports: long,
                              discoveredVia: [.probeReply])
        var document = report(tcp: (1...12).map { UInt16($0 * 10) }, hosts: 1)
        document.devices = [Device(observing: facts, in: network,
                                   lastSeen: Timestamp(millisecondsSinceEpoch: 1))]
        // Fitting is required at every width; truncation only where there is not room.
        // Demanding the ellipsis everywhere was this test's own bug — at 140 columns the
        // 91-character service fits, and cutting it there would be damage, not a cap.
        for width in [80, 100, 140, 200] {
            let text = rendered(document, width: width, preference: .long)
            #expect(widestLine(text) <= width,
                    Comment(rawValue: "a 91-character service drew \(widestLine(text)) "
                            + "columns into a \(width)-column terminal"))
        }
        for width in [80, 100] {
            let text = rendered(document, width: width, preference: .long)
            #expect(text.contains("\u{2026}"),
                    Comment(rawValue: "no room at \(width) columns and nothing was cut"))
        }
        // And the full string is still in the artifact, which is why cutting is safe.
        #expect(rendered(document, width: 200, preference: .long)
            .contains("VeryLongProductNameVeryLongProductNameVeryLongProductNameVeryLongProductName"),
                "the service was truncated even where it fits")
    }
}

@Suite("The override is an override")
struct PortsViewOverrideTests {
    @Test("matrix and long force their table whatever the width says")
    func forcing() {
        // Three ports at 200 columns would be a matrix; twenty at 80 would be a long
        // form. Both get overruled.
        let few = report(tcp: [10, 20, 30])
        let many = report(tcp: (1...20).map { UInt16($0 * 10) })
        #expect(!isMatrix(rendered(few, width: 200, preference: .long)),
                "--ports-view long still drew a matrix")
        #expect(isMatrix(rendered(many, width: 80, preference: .matrix)),
                "--ports-view matrix still drew a long form")
    }

    @Test("Forcing a matrix that does not fit is allowed, and is the user's business")
    func forcingCanOverflow() {
        // The override exists precisely so a person can overrule the derivation. It
        // would be wrong to silently ignore them — recorded here so the overflow is a
        // decision rather than a surprise.
        let many = report(tcp: (1...20).map { UInt16($0 * 10) })
        let text = rendered(many, width: 80, preference: .matrix)
        #expect(widestLine(text) > 80,
                "a 20-port matrix at 80 columns did not overflow, so this proves nothing")
        #expect(isMatrix(text))
    }

    @Test("auto is the default, so an unset flag derives")
    func autoIsDefault() throws {
        // Parsed rather than default-initialised: reading an `@Option` off an unparsed
        // `ParsableArguments` traps in ArgumentParser, which is a crash rather than a
        // failure and takes the whole suite with it.
        let parsed = try Scan.parse([])
        #expect(parsed.options.portsView == .auto)
        #expect(try Scan.parse(["--ports-view", "long"]).options.portsView == .long)
        #expect(try Scan.parse(["--ports-view", "matrix"]).options.portsView == .matrix)
    }
}
