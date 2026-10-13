import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// The port matrix, stage 2 of `Docs/plans/PORTS-rendering.md`.
//
// This is the suite for the defect found on 2026-09-24: `scan --deep` ran the port
// scan, wrote the results onto every host, and printed a table that did not include
// them. So the first thing checked is the plainest — that a port scanned appears in
// the text output at all.

/// A report whose hosts between them produce all four cell states.
private func portedReport(
    probeLastHost: Bool = true,
    ports: [UInt16] = [22, 80, 443]
) -> ScanReport {
    let network = IPv4Network("10.10.20.0/24")!
    let stamp = Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)

    func observations(_ states: [PortState]) -> [PortObservation] {
        zip(ports, states).map { port, state in
            PortObservation(port: port, proto: .tcp, state: state,
                            service: state == .open
                                ? ServiceIdentity(name: "http", evidence: .banner)
                                : nil,
                            rtt: state == .open ? RTTSample(measured: .microseconds(4210)) : nil)
        }
    }

    var facts = [
        // Every state on one host, so the three probed glyphs cannot be confused with
        // one host being wholly one thing.
        HostFacts(ip: IPv4Address("10.10.20.1")!, mac: MACAddress("78:20:51:5E:07:28"),
                  ttl: 64, rtt: RTTSample(measured: .microseconds(412)),
                  ports: observations([.filtered, .open, .closed]),
                  discoveredVia: [.probeReply]),
        HostFacts(ip: IPv4Address("10.10.20.103")!, mac: MACAddress("C8:69:CD:5E:01:E1"),
                  allNames: [NameCandidate(value: "Sala de estar principal", source: .mdns)],
                  ttl: 64, rtt: RTTSample(measured: .microseconds(51680)),
                  ports: observations([.closed, .closed, .open]),
                  discoveredVia: [.probeReply]),
    ]
    // The fourth state: a host the port stage never reached. Routine, not exotic —
    // discovery can find a host after the stage has taken its slice of the budget.
    facts.append(
        HostFacts(ip: IPv4Address("10.10.20.124")!, mac: MACAddress("D6:0A:97:5E:06:9C"),
                  ports: probeLastHost ? observations([.filtered, .filtered, .filtered]) : [],
                  discoveredVia: [.neighborTable])
    )

    return ScanReport(
        run: ScanRun(
            id: UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!,
            startedAt: stamp, finishedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_240),
            target: network, interface: "en0",
            engine: EngineDescriptor(name: "darwin-unprivileged", kind: .unprivileged,
                                     capabilities: [.icmpSweep, .connectScan]),
            outcome: .complete,
            timing: Timing(
                stages: [StageTiming(stage: .discovery, elapsedMillis: 240,
                                     probesSent: 254, repliesSeen: 3)],
                counters: ProbeCounterSnapshot(probesSent: 254, repliesSeen: 3,
                                               peakConcurrency: 512, inFlight: 0))
        ),
        devices: facts.map { Device(observing: $0, in: network, lastSeen: stamp) },
        degradations: []
    )
}

private func renderText(_ report: ScanReport, color: Bool = false, width: Int = 80) -> String {
    Out.capturing {
        TextRenderer(quiet: true, color: color, progressColor: false, width: width)
            .finish(report)
    }.out
}

@Suite("The defect: a scanned port reaches the text output")
struct PortsAreRenderedTests {
    @Test("A run that scanned ports prints them")
    func portsAppear() {
        let text = renderText(portedReport())
        // The regression itself. Before stage 2 this table was six columns — ADDRESS,
        // NAME, MODEL, HARDWARE, RTT, TTL — and none of them was a port.
        for port in ["22", "80", "443"] {
            #expect(text.contains(port),
                    Comment(rawValue: "port \(port) was scanned and does not appear in:\n\(text)"))
        }
    }

    @Test("A run that scanned nothing is untouched")
    func withoutPortsTheDeviceTableIsUnchanged() {
        // The control. If the matrix replaced the device table unconditionally, an
        // ordinary `zhen scan` would lose its MODEL and HARDWARE columns.
        let text = renderText(sampleReport())
        #expect(text.contains("HARDWARE") && text.contains("MODEL"),
                Comment(rawValue: "a run with no ports lost the device table:\n\(text)"))
        #expect(!text.contains(PortCell.open.glyph), "a run with no ports drew a port matrix")
    }
}

@Suite("Four states, and none of them collapse")
struct PortCellStateTests {
    @Test("All four glyphs are distinct, which is what makes --no-color work")
    func glyphsAreDistinct() {
        let glyphs = [PortCell.open, .closed, .filtered, .notProbed].map(\.glyph)
        #expect(Set(glyphs).count == 4,
                Comment(rawValue: "two states share a glyph: \(glyphs)"))
        // Every glyph is one column wide, or the matrix does not line up.
        for glyph in glyphs {
            #expect(glyph.count == 1, Comment(rawValue: "\(glyph) is \(glyph.count) characters"))
        }
    }

    @Test("A host that was never probed is not drawn as one that returned silence")
    func notProbedIsNotFiltered() {
        // The error a matrix invites: every cell looks answered. This is the same class
        // of collapse as open-versus-filtered, one level up.
        let text = renderText(portedReport(probeLastHost: false))
        #expect(text.contains(PortCell.notProbed.glyph),
                Comment(rawValue: "a host with no port observations drew no 'not probed' "
                        + "glyph:\n\(text)"))
        let unprobedRow = text.split(separator: "\n").first { $0.contains("10.10.20.124") }
        #expect(unprobedRow?.contains(PortCell.notProbed.glyph) == true,
                Comment(rawValue: "the unprobed host's row was \(unprobedRow ?? "missing")"))
        #expect(unprobedRow?.contains(PortCell.filtered.glyph) == false,
                Comment(rawValue: "the unprobed host was drawn as filtered: \(unprobedRow ?? "")"))
    }

    @Test("With colour off, all four states are still present and distinguishable")
    func readableWithoutColor() {
        let text = renderText(portedReport(probeLastHost: false), color: false)
        #expect(!text.contains("\u{1B}["), "escapes reached a --no-color rendering")
        for cell in [PortCell.open, .closed, .filtered, .notProbed] {
            #expect(text.contains(cell.glyph),
                    Comment(rawValue: "state \(cell) is absent with colour off:\n\(text)"))
        }
    }

    @Test("Colour reinforces the glyph and is never the only difference")
    func colorOnlyReinforces() {
        // Stripping every escape from the coloured rendering must give back exactly the
        // uncoloured one. If it does not, some distinction lives in the colour alone.
        let colored = renderText(portedReport(probeLastHost: false), color: true)
        let plain = renderText(portedReport(probeLastHost: false), color: false)
        let stripped = colored.replacingOccurrences(
            of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
        #expect(stripped == plain,
                Comment(rawValue: "colour changed the text, not just its presentation.\n"
                        + "stripped: \(stripped)\nplain:    \(plain)"))
        #expect(colored != plain, "colour was requested and no escapes were emitted")
    }
}

@Suite("The matrix lines up")
struct PortMatrixAlignmentTests {
    /// The trap named in the handoff: pad the plain cell, then wrap it in escapes.
    /// Padding a styled string counts the escape sequence as characters.
    @Test("Colour does not move a column")
    func stylingDoesNotShiftColumns() {
        func glyphColumns(_ text: String) -> [[Int]] {
            text.split(separator: "\n")
                .filter { $0.contains("10.10.20.") }
                .map { line in
                    let stripped = line.replacingOccurrences(
                        of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
                    return stripped.enumerated()
                        .filter { "\u{25CF}\u{25CB}\u{00B7}\u{2013}".contains($0.element) }
                        .map(\.offset)
                }
        }
        let plain = glyphColumns(renderText(portedReport(), color: false))
        let colored = glyphColumns(renderText(portedReport(), color: true))
        #expect(!plain.isEmpty, "no glyph rows were found, so nothing was compared")
        #expect(plain == colored,
                Comment(rawValue: "escapes shifted the table. plain \(plain), coloured \(colored)"))
    }

    @Test("Every row puts its glyphs in the same columns")
    func rowsAgreeWithEachOther() {
        let text = renderText(portedReport())
        let rows = text.split(separator: "\n").filter { $0.contains("10.10.20.") }
        let columns = rows.map { line in
            line.enumerated()
                .filter { "\u{25CF}\u{25CB}\u{00B7}\u{2013}".contains($0.element) }
                .map(\.offset)
        }
        #expect(columns.count == 3, Comment(rawValue: "expected 3 host rows, got \(columns.count)"))
        #expect(Set(columns).count == 1,
                Comment(rawValue: "rows disagree about where the columns are: \(columns)"))
    }

    @Test("No line carries trailing whitespace into a file")
    func noTrailingWhitespace() {
        // Every port column is padded, the last one included, so the line is trimmed
        // rather than left ragged. This is what says the trim actually happens.
        let text = renderText(portedReport())
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            #expect(!line.hasSuffix(" "),
                    Comment(rawValue: "trailing space on: \(String(line).debugDescription)"))
        }
    }
}

@Suite("The text matrix reconciles with the artifact")
struct PortMatrixReconciliationTests {
    @Test("Every open port in the JSON is an open glyph in the text, and no others are")
    func textAgreesWithJSON() throws {
        let report = portedReport(probeLastHost: false)
        let text = renderText(report)

        // From the artifact: which (host, port) pairs are open.
        var openFromJSON: Set<String> = []
        for device in report.devices {
            for observation in device.ports where observation.state == .open {
                openFromJSON.insert("\(device.primaryAddress)/\(observation.port)")
            }
        }

        // From the text: read the header for the port order, then each row's glyphs.
        let lines = text.split(separator: "\n").map(String.init)
        let header = try #require(lines.first { $0.contains("ADDRESS") })
        let portOrder = header.split(separator: " ").compactMap { UInt16($0) }
        var openFromText: Set<String> = []
        for line in lines where line.contains("10.10.20.") {
            let address = try #require(line.split(separator: " ").first).description
            let glyphs = line.filter { "\u{25CF}\u{25CB}\u{00B7}\u{2013}".contains($0) }
            for (index, glyph) in glyphs.enumerated()
            where String(glyph) == PortCell.open.glyph && index < portOrder.count {
                openFromText.insert("\(address)/\(portOrder[index])")
            }
        }

        #expect(!openFromJSON.isEmpty, "the fixture has no open ports, so this compared nothing")
        #expect(openFromText == openFromJSON,
                Comment(rawValue: "text says \(openFromText.sorted()), "
                        + "artifact says \(openFromJSON.sorted())"))
    }
}

@Suite("The fifth state, and the key that explains it")
struct OpenFilteredTests {
    private func report(states: [PortState]) -> ScanReport {
        let network = IPv4Network("10.10.20.0/24")!
        let stamp = Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)
        let observations = states.enumerated().map { index, state in
            PortObservation(port: UInt16(50 + index), proto: .udp, state: state)
        }
        let facts = HostFacts(ip: IPv4Address("10.10.20.1")!, ports: observations,
                              discoveredVia: [.probeReply])
        return ScanReport(
            run: ScanRun(
                id: UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!,
                startedAt: stamp, finishedAt: stamp,
                target: network, interface: "en0",
                engine: EngineDescriptor(name: "darwin-unprivileged", kind: .unprivileged,
                                         capabilities: [.connectScan]),
                outcome: .complete,
                timing: Timing(stages: [StageTiming(stage: .deepScan, elapsedMillis: 1)],
                               counters: ProbeCounterSnapshot(probesSent: 1, repliesSeen: 0,
                                                              peakConcurrency: 1, inFlight: 0))),
            devices: [Device(observing: facts, in: network, lastSeen: stamp)],
            degradations: [])
    }

    private func rendered(_ report: ScanReport, width: Int = 80) -> String {
        Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false, width: width)
                .finish(report)
        }.out
    }

    @Test("All five glyphs are distinct and one character wide")
    func fiveDistinctGlyphs() {
        let cells: [PortCell] = [.open, .closed, .filtered, .openFiltered, .notProbed]
        let glyphs = cells.map(\.glyph)
        #expect(Set(glyphs).count == 5, Comment(rawValue: "two states share a glyph: \(glyphs)"))
        for glyph in glyphs { #expect(glyph.count == 1) }
    }

    @Test("Silence on UDP is drawn as neither open nor filtered")
    func openFilteredIsItsOwnMark() {
        // The whole reason the state exists. Rounding it either way is a decision, and
        // the renderer must not make it on the reader's behalf.
        let text = rendered(report(states: [.openFiltered, .open, .filtered]))
        #expect(text.contains(PortCell.openFiltered.glyph))
        #expect(PortCell.openFiltered.glyph != PortCell.open.glyph)
        #expect(PortCell.openFiltered.glyph != PortCell.filtered.glyph)
    }

    @Test("It proves nothing about the host being alive")
    func itIsNotEvidence() {
        // `provesHostAlive` is what discovery reads. An ambiguous result cannot be
        // evidence of reachability — that is the collapse the state exists to avoid.
        #expect(PortState.openFiltered.provesHostAlive == false)
        #expect(PortState.open.provesHostAlive)
        #expect(PortState.closed.provesHostAlive)
    }

    /// **The key wraps rather than overflowing, and the gate is what found that.**
    ///
    /// Five entries is 66 characters — wider than a 60-column terminal that the matrix
    /// itself may well fit. The table fitted and its own key did not.
    @Test("The key fits the terminal, at every width, by wrapping")
    func theLegendWraps() {
        for width in [40, 60, 66, 80, 200] {
            let lines = PortMatrix.legend(width: width)
            for line in lines {
                #expect(line.count <= max(width, PortMatrix.legendEntries.map(\.count).max() ?? 0),
                        Comment(rawValue: "at \(width) columns the key drew \(line.count): \(line)"))
            }
            // Every state keeps an entry. Dropping one to fit leaves a glyph on screen
            // with nothing explaining it, which is worse than two lines.
            let joined = lines.joined(separator: " ")
            for entry in PortMatrix.legendEntries {
                #expect(joined.contains(entry),
                        Comment(rawValue: "'\(entry)' vanished from the key at \(width)"))
            }
        }
        #expect(PortMatrix.legend(width: 200).count == 1, "a wide terminal split the key")
        #expect(PortMatrix.legend(width: 40).count > 1, "a narrow terminal did not wrap it")
    }

    @Test("The long form lists an ambiguous port and says it is ambiguous")
    func theLongFormNamesTheAmbiguity() {
        // Dropping it to the footer would bury the only result a UDP scan usually
        // produces; showing it as open would over-report. It gets a row whose SERVICE
        // cell says what is actually known.
        let form = PortLongForm([(address: .v4(IPv4Address("10.10.20.1")!),
                                  observations: [PortObservation(port: 53, proto: .udp,
                                                                 state: .openFiltered)])])
        #expect(form.rows.count == 1, "an ambiguous port produced no row")
        #expect(form.rows.first?.service == PortLongForm.ambiguous,
                Comment(rawValue: "the row does not say it is ambiguous: \(form.rows)"))
        #expect(form.rows.first?.port == "53/udp")
        #expect(form.counts.openFiltered == 1)
        #expect(form.footer.contains("1 open or filtered"))
    }

    @Test("A TCP-only run never mentions it")
    func tcpRunsAreUnchanged() {
        let form = PortLongForm([(address: .v4(IPv4Address("10.10.20.1")!),
                                  observations: [PortObservation(port: 80, proto: .tcp,
                                                                 state: .open)])])
        #expect(!form.footer.contains("open or filtered"),
                Comment(rawValue: "a TCP run mentioned UDP ambiguity: \(form.footer)"))
    }
}
