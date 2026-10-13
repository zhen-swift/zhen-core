import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// The long form, stage 3 of `Docs/plans/PORTS-rendering.md`.
//
// ── Why none of this reuses PortMatrixTests' fixture ──────────────────────────
//
// `portedReport(ports:)` looks like it takes an arbitrary port list and does not:
// `observations(_:)` zips that list against a THREE-element state array, so asking it
// for nine ports still yields three observations per host. A long-form test built on it
// would render a matrix and pass for the wrong reason.
//
// That file's fixture must also stay at three ports. Its `line.contains("10.10.20.")`
// filters assume exactly three such lines, and a long form under the device table would
// add more.

/// A run of `tcp.count + udp.count` port observations on each of `hosts` hosts.
///
/// Every state is decided by a rule rather than by chance, because a fixture that varies
/// cannot be byte-compared — the lesson `RedirectedWidthTests` already records.
private func portsReport(
    hosts: Int = 9,
    tcp: [UInt16],
    udp: [UInt16] = [],
    unprobedHosts: Int = 0,
    allFiltered: Bool = false,
    longService: Bool = false
) -> ScanReport {
    let network = IPv4Network("10.10.20.0/24")!
    let stamp = Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)

    func state(_ port: UInt16, _ host: Int) -> PortState {
        if allFiltered { return .filtered }
        if (Int(port) + host) % 11 == 0 { return .open }
        if Int(port) % 3 == 0 { return .closed }
        return .filtered
    }
    // Deliberately absent on some open ports. An open port with neither a service nor a
    // round trip is the row that would otherwise end its line in the column separator.
    func service(_ port: UInt16) -> ServiceIdentity? {
        guard port % 2 == 0 else { return nil }
        return ServiceIdentity(
            name: "http",
            product: longService ? String(repeating: "LongProductName", count: 4) : "nginx",
            version: "1.24", evidence: .banner)
    }
    func rtt(_ port: UInt16) -> RTTSample? {
        port % 5 == 0 ? nil : RTTSample(measured: .microseconds(4210))
    }

    var facts: [HostFacts] = []
    for index in 0..<hosts {
        let address = IPv4Address("10.10.20.\(index + 1)")!
        let observations =
            tcp.map { PortObservation(port: $0, proto: .tcp, state: state($0, index),
                                      service: service($0), rtt: rtt($0)) }
            + udp.map { PortObservation(port: $0, proto: .udp, state: state($0, index),
                                        service: nil, rtt: rtt($0)) }
        facts.append(
            HostFacts(ip: address, mac: MACAddress("78:20:51:5E:07:\(String(format: "%02X", index))"),
                      ttl: 64, rtt: RTTSample(measured: .microseconds(412)),
                      ports: observations, discoveredVia: [.probeReply])
        )
    }
    // Hosts the port stage never reached: an empty `ports` array, exactly what the live
    // path produces for them.
    for offset in 0..<unprobedHosts {
        facts.append(
            HostFacts(ip: IPv4Address("10.10.20.\(200 + offset)")!,
                      mac: MACAddress("D6:0A:97:5E:06:9C"),
                      ports: [], discoveredVia: [.neighborTable])
        )
    }

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
                                     probesSent: 254, repliesSeen: hosts)],
                counters: ProbeCounterSnapshot(probesSent: 254, repliesSeen: hosts,
                                               peakConcurrency: 512, inFlight: 0))
        ),
        devices: facts.map { Device(observing: $0, in: network, lastSeen: stamp) },
        degradations: []
    )
}

/// 99 TCP ports plus 53/udp: 100 distinct (port, proto) pairs per host.
private let hundredPorts: [UInt16] = Array(1...99).map(UInt16.init)

private func renderText(_ report: ScanReport, color: Bool = false, width: Int = 80,
                        preference: PortView.Preference = .auto) -> String {
    Out.capturing {
        TextRenderer(quiet: true, color: color, progressColor: false, width: width,
                     portsView: preference).finish(report)
    }.out
}

@Suite("The gate: 100 ports across 9 hosts")
struct LongFormGateTests {
    @Test("Exactly the open ports get rows, and nothing else does")
    func rowsAreExactlyTheOpenPorts() {
        let report = portsReport(tcp: hundredPorts, udp: [53])
        let form = PortLongForm(report.devices)

        var fromReport: Set<String> = []
        for device in report.devices {
            for observation in device.ports where observation.state == .open {
                fromReport.insert("\(device.primaryAddress) \(observation.port)/\(observation.proto.rawValue)")
            }
        }
        let fromForm = Set(form.rows.map { "\($0.host) \($0.port)" })

        #expect(fromReport.count > 0, "the fixture has no open ports, so this compared nothing")
        #expect(fromForm == fromReport,
                Comment(rawValue: "rows \(fromForm.sorted().prefix(5))… "
                        + "vs open ports \(fromReport.sorted().prefix(5))…"))
        // Set equality rather than substring presence: a closed port's number turns up
        // inside another row's RTT digits sooner or later.
        #expect(form.rows.count == fromReport.count, "a port produced two rows")
    }

    @Test("The footer's totals are the same run's artifact, added up")
    func footerReconcilesWithJSON() throws {
        let report = portsReport(tcp: hundredPorts, udp: [53], unprobedHosts: 2)
        let text = renderText(report)

        // Through the ARTIFACT, not the in-memory report. Counting the same `[Device]`
        // the renderer counted proves only that the renderer agrees with itself;
        // decoding what `--json` actually emitted is what makes this a reconciliation.
        let json = Out.capturing { JSONRenderer(quiet: true, color: false).finish(report) }.out
        let decoded = try ScanReport.decoded(from: Data(json.utf8))

        var open = 0, closed = 0, filtered = 0, unprobed = 0
        for device in decoded.devices {
            if device.ports.isEmpty { unprobed += 1; continue }
            for observation in device.ports {
                switch observation.state {
                case .open: open += 1
                case .closed: closed += 1
                case .filtered: filtered += 1
                // The fixture is TCP, so this is zero — but the switch is exhaustive on
                // purpose, so a fourth state cannot be silently excluded from a
                // reconciliation whose whole job is that the numbers add up.
                case .openFiltered: break
                }
            }
        }
        #expect(open + closed + filtered == 900,
                Comment(rawValue: "the fixture is \(open + closed + filtered) observations, "
                        + "not the gate's 100 x 9"))

        let footer = try #require(
            text.split(separator: "\n").map(String.init).last { $0.contains(" open \u{00B7} ") })
        #expect(footer.split(separator: " ").compactMap { Int($0) } == [open, closed, filtered, unprobed],
                Comment(rawValue: "footer \(footer.trimmingCharacters(in: .whitespaces)), "
                        + "artifact \(open)/\(closed)/\(filtered), \(unprobed) unprobed"))
    }

    @Test("Nine hundred observations do not become nine hundred lines")
    func closedAndFilteredAreCountedNotPrinted() {
        let report = portsReport(tcp: hundredPorts, udp: [53])
        let form = PortLongForm(report.devices)
        let text = renderText(report)
        let lines = text.split(separator: "\n").count

        #expect(form.counts.closed + form.counts.filtered > 800,
                "the fixture is mostly open, so this proves nothing about collapsing")
        #expect(lines < 100,
                Comment(rawValue: "\(lines) lines for \(form.rows.count) open ports out of 900 "
                        + "observations — the closed and filtered ones are being printed"))
    }
}

@Suite("Which table a run gets")
struct PortViewSelectionTests {
    @Test("The choice follows the width, because stage 4 derives it")
    func theThresholdIsDerived() {
        // This test used to assert 8 ports is a matrix and 9 a long form. That was
        // stage 3's hand-typed `longFormThreshold = 9`, and it was named "provisional"
        // because stage 4 replaces the constant with a derivation from the table's own
        // measured columns. It does, so the fixed numbers are gone: what is asserted
        // now is that the same port set can go either way depending on the width, which
        // the constant could never do.
        let ports = Array(1...12).map(UInt16.init)
        let narrow = renderText(portsReport(tcp: ports), width: 60)
        let wide = renderText(portsReport(tcp: ports), width: 200)
        #expect(narrow.contains(PortLongForm.title),
                Comment(rawValue: "twelve ports at 60 columns drew a matrix:\n\(narrow)"))
        #expect(!wide.contains(PortLongForm.title),
                Comment(rawValue: "twelve ports at 200 columns drew a long form:\n\(wide)"))
    }

    @Test("A port set counts transports separately")
    func transportsCountSeparately() {
        // Five over TCP and the same five over UDP is a set of ten, not of five, so it
        // crosses the threshold. Pins the (port, proto) keying `PortView` inherits.
        let ports: [UInt16] = [22, 53, 80, 443, 5353]
        let text = renderText(portsReport(tcp: ports, udp: ports), width: 60)
        #expect(text.contains(PortLongForm.title),
                Comment(rawValue: "ten (port, proto) pairs rendered as a matrix:\n\(text)"))
    }

    @Test("The matrix still replaces the device table")
    func matrixStillReplaces() {
        // The stage 2 anti-regression, kept in the suite that could break it.
        let text = renderText(portsReport(tcp: Array(1...8).map(UInt16.init)), width: 200)
        #expect(!text.contains("HARDWARE"),
                Comment(rawValue: "the matrix stopped replacing the device table:\n\(text)"))
    }

    @Test("The long form follows the device table rather than replacing it")
    func deviceTableSurvives() throws {
        let text = renderText(portsReport(tcp: hundredPorts))
        #expect(text.contains("HARDWARE") && text.contains("MODEL"),
                "the device table was replaced by the long form")
        #expect(text.contains(PortLongForm.title), "the long form is missing")
        // Order matters: the device table is where the HOST column's addresses get
        // their names back, so it has to be above. Asserted unconditionally — wrapping
        // this in `if let` would let it silently never run.
        let table = text.range(of: "HARDWARE")
        let section = text.range(of: PortLongForm.title)
        #expect(table != nil && section != nil, "one of the two tables is missing")
        if let table, let section {
            #expect(table.lowerBound < section.lowerBound,
                    "the long form was printed above the device table")
        }
    }

    @Test("A run with no ports is untouched")
    func noPortsIsUnchanged() {
        let text = renderText(sampleReport())
        #expect(text.contains("HARDWARE"))
        #expect(!text.contains(PortLongForm.title))
        #expect(!text.contains(PortCell.open.glyph))
    }
}

@Suite("The long form's shape")
struct LongFormRenderingTests {
    @Test("The address is printed once per host and blanked on its repeats")
    func addressIsBlankedOnRepeats() {
        let report = portsReport(hosts: 2, tcp: hundredPorts)
        let form = PortLongForm(report.devices)
        let text = renderText(report)
        let body = text.components(separatedBy: PortLongForm.title).last ?? ""
        let printed = body.split(separator: "\n")
            .compactMap { line -> String? in
                let first = line.split(separator: " ", omittingEmptySubsequences: true).first
                return first.map(String.init).flatMap { $0.contains("10.10.20.") ? $0 : nil }
            }
        let distinct = Set(form.rows.map(\.host))
        #expect(form.rows.count > distinct.count,
                "the fixture has one row per host, so blanking cannot be observed")
        #expect(printed.count == distinct.count,
                Comment(rawValue: "\(printed.count) addresses printed for \(distinct.count) hosts "
                        + "over \(form.rows.count) rows — repeats were not blanked"))
        #expect(Set(printed) == distinct, "a host's address never appeared")
    }

    @Test("No line carries trailing whitespace into a file")
    func noTrailingWhitespace() {
        // Includes open ports with neither a service nor an RTT — the rows that would
        // otherwise end in the column separator, because `line` joins it before an empty
        // final cell.
        let report = portsReport(tcp: hundredPorts, udp: [53], unprobedHosts: 1)
        let form = PortLongForm(report.devices)
        #expect(form.rows.contains { $0.service == PortLongForm.unknown
                                     && $0.rtt == PortLongForm.unknown },
                "no row is missing both service and RTT, so the separator case is untested")
        for line in renderText(report).split(separator: "\n", omittingEmptySubsequences: false) {
            #expect(!line.hasSuffix(" "),
                    Comment(rawValue: "trailing space on: \(String(line).debugDescription)"))
        }
    }

    @Test("Colour reinforces and is never the only difference")
    func colorOnlyReinforces() {
        // Unguarded on this path until now: `CLITests.paddingIsIndependentOfStyling`
        // renders a report with no ports and never reaches the long form.
        let report = portsReport(tcp: hundredPorts)
        let colored = renderText(report, color: true)
        let plain = renderText(report, color: false)
        let stripped = colored.replacingOccurrences(
            of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
        #expect(stripped == plain, "colour changed the text, not just its presentation")
        #expect(colored != plain, "colour was requested and no escapes were emitted")
    }

    @Test("Every row puts its port in the same column, styled or not")
    func columnsDoNotMove() {
        // Found by regex on the PORT cell rather than by whitespace runs: a service
        // string like `http nginx 1.24` contains spaces and would register as three
        // column starts.
        func portColumns(_ text: String) -> [Int] {
            let body = text.components(separatedBy: PortLongForm.title).last ?? ""
            return body.split(separator: "\n").compactMap { line -> Int? in
                let plain = String(line).replacingOccurrences(
                    of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
                guard let range = plain.range(of: "[0-9]+/(tcp|udp)", options: .regularExpression)
                else { return nil }
                return plain.distance(from: plain.startIndex, to: range.lowerBound)
            }
        }
        let report = portsReport(tcp: hundredPorts)
        let plain = portColumns(renderText(report, color: false))
        let colored = portColumns(renderText(report, color: true))
        #expect(plain.count > 5, "too few rows to compare")
        #expect(Set(plain).count == 1,
                Comment(rawValue: "rows disagree about the PORT column: \(Set(plain).sorted())"))
        #expect(plain == colored, "escapes shifted the table")
    }

    @Test("The long form now consumes the terminal width, and stays inside it")
    func longFormRespectsWidth() {
        // Stage 3 asserted the opposite and said so: "the stage 3 counterpart of
        // nothingConsumesWidthYet, and the one stage 4 is expected to invert". Stage 4
        // caps the SERVICE column against the width, so it is inverted here rather than
        // deleted — the prediction was made in writing and this is it coming true.
        // A service long enough for the cap to bite. The ordinary fixture's
        // `http nginx 1.24` is fifteen characters and fits every width, so it would
        // render identically at all three and this test would fail for lack of a long
        // string rather than for lack of a cap.
        let report = portsReport(tcp: hundredPorts, longService: true)
        let widths = [60, 80, 200]
        let renderings = widths.map { renderText(report, width: $0) }
        #expect(Set(renderings).count == widths.count,
                Comment(rawValue: "\(Set(renderings).count) distinct renderings across "
                        + "\(widths.count) widths — the width is not reaching the table"))
        for (width, text) in zip(widths, renderings) {
            let widest = text.split(separator: "\n").map(\.count).max() ?? 0
            #expect(widest <= width,
                    Comment(rawValue: "at \(width) columns the table drew \(widest) wide"))
        }
    }
}

@Suite("The footer states what the rows cannot")
struct LongFormFooterTests {
    @Test("A run with nothing open still reports, without an empty table")
    func noOpenPortsStillReports() {
        let report = portsReport(tcp: hundredPorts, allFiltered: true)
        let text = renderText(report)
        #expect(text.contains(PortLongForm.title))
        #expect(text.contains("0 open"))
        // A column header over no rows reads as a table that failed to draw. Matched
        // by line prefix rather than by a literal run of spaces, whose width moves with
        // the fixture.
        let headerLines = text.split(separator: "\n").filter { $0.hasPrefix("HOST") }
        #expect(headerLines.isEmpty,
                Comment(rawValue: "a header was drawn over no rows: \(headerLines)"))
    }

    @Test("Hosts that were never probed are counted, and only when there are some")
    func hostsNotProbedIsConditional() {
        let none = renderText(portsReport(tcp: hundredPorts))
        #expect(!none.contains("not probed"),
                "an ordinary run claimed hosts were not probed")
        let one = renderText(portsReport(tcp: hundredPorts, unprobedHosts: 1))
        #expect(one.contains("1 host not probed"),
                Comment(rawValue: "singular form missing from:\n\(one)"))
        let several = renderText(portsReport(tcp: hundredPorts, unprobedHosts: 3))
        #expect(several.contains("3 hosts not probed"))
    }

    @Test("A footer wider than its own table does not crash")
    func narrowTableDoesNotTrap() {
        // `String(repeating:count:)` traps on a negative count, and a one-host run with
        // one open port has a table narrower than its footer. Reachable from an ordinary
        // command line, so it is a test rather than a defensive `max`.
        // Forced, because nine ports now FIT a matrix at this width — stage 4 derives
        // the choice, so the old fixed threshold no longer puts this on the long form.
        let report = portsReport(hosts: 1, tcp: Array(1...9).map(UInt16.init))
        let text = renderText(report, preference: .long)
        #expect(text.contains(" open \u{00B7} "), "the footer did not render")
    }
}

@Suite("A service reads as one string")
struct ServiceDisplayTests {
    @Test("Name, product and version join; a missing part is simply absent")
    func displayText() {
        #expect(ServiceIdentity(name: "http", evidence: .banner).displayText == "http")
        #expect(ServiceIdentity(name: "http", product: "nginx", evidence: .banner)
            .displayText == "http nginx")
        #expect(ServiceIdentity(name: "http", product: "nginx", version: "1.24",
                                evidence: .banner).displayText == "http nginx 1.24")
        // Odd-looking and honest: suppressing the version would discard evidence.
        #expect(ServiceIdentity(name: "http", version: "1.24", evidence: .banner)
            .displayText == "http 1.24")
        #expect(ServiceIdentity(name: "", product: "nginx", evidence: .banner)
            .displayText == "nginx")
    }

    @Test("The evidence is not the identification")
    func bannerAndSubjectAreExcluded() {
        let identity = ServiceIdentity(
            name: "https", product: "nginx", version: "1.24",
            banner: "Server: nginx/1.24 (Ubuntu)", tlsSubject: "Example Networks",
            evidence: .tlsCertificate)
        #expect(identity.displayText == "https nginx 1.24")
        #expect(!identity.displayText.contains("Ubuntu"))
        #expect(!identity.displayText.contains("Example Networks"))
    }

    @Test("An open port with no service reads as unknown, not as empty")
    func absentServiceRendersAsEmDash() {
        let report = portsReport(hosts: 1, tcp: Array(1...9).map(UInt16.init))
        let form = PortLongForm(report.devices)
        #expect(form.rows.allSatisfy { !$0.service.isEmpty },
                "an empty service cell would end its line in the column separator")
    }
}

@Suite("A host cut short is counted, not silently dropped")
struct PartiallyProbedHostTests {
    /// Raised at stage 3 as a hole in this view and closed here.
    ///
    /// A host given 40 of 100 ports before the budget expired contributes 40
    /// observations and is not "not probed". Its missing 60 used to vanish: the three
    /// counts came to less than `probed hosts x port set` and nothing said why. The
    /// matrix renders that case correctly, as dashes, and the long form could not
    /// represent it at all — so the four-state argument `PortMatrix.swift` spends
    /// twenty lines on was partly lost above eight ports.
    private func cutShort(full: Int, short: Int) -> PortLongForm {
        let all = (1...full).map { UInt16($0) }
        let complete = all.map { PortObservation(port: $0, proto: .tcp, state: .filtered) }
        let partial = all.prefix(short).map {
            PortObservation(port: $0, proto: .tcp, state: .filtered)
        }
        return PortLongForm([
            (address: .v4(IPv4Address("10.10.20.1")!), observations: complete),
            (address: .v4(IPv4Address("10.10.20.2")!), observations: Array(partial)),
        ])
    }

    @Test("The observations a cut-short host never made are named")
    func theGapIsNamed() {
        let form = cutShort(full: 100, short: 40)
        #expect(form.counts.hostsPartlyProbed == 1)
        #expect(form.counts.missingObservations == 60)
        #expect(form.footer.contains("60 not reached on 1 host"),
                Comment(rawValue: "the gap is missing from: \(form.footer)"))
    }

    @Test("The three counts plus the gap add up to hosts times ports")
    func thefooterReconcilesAgain() {
        // The property the gap restores. Before it, a reader adding the first three
        // and comparing against the port set found a shortfall with no explanation.
        let form = cutShort(full: 100, short: 40)
        let counted = form.counts.open + form.counts.closed + form.counts.filtered
        #expect(counted + form.counts.missingObservations == 200,
                Comment(rawValue: "\(counted) observed plus \(form.counts.missingObservations) "
                        + "missing is not 2 hosts x 100 ports"))
    }

    @Test("An ordinary complete run says nothing about it")
    func completeRunsAreSilent() {
        // The clause must not become noise on every scan, which is the same reason
        // `hosts not probed` is conditional.
        let form = cutShort(full: 100, short: 100)
        #expect(form.counts.hostsPartlyProbed == 0)
        #expect(!form.footer.contains("not reached"),
                Comment(rawValue: "a complete run claimed a gap: \(form.footer)"))
    }

    @Test("A host with nothing at all is still 'not probed', not 'cut short'")
    func emptyIsNotPartial() {
        // The two are different facts: one stage never reached the host, the other
        // reached it and ran out. Collapsing them would be the same mistake one level
        // down.
        let form = PortLongForm([
            (address: .v4(IPv4Address("10.10.20.1")!),
             observations: (1...10).map { PortObservation(port: UInt16($0), proto: .tcp,
                                                          state: .filtered) }),
            (address: .v4(IPv4Address("10.10.20.2")!), observations: []),
        ])
        #expect(form.counts.hostsNotProbed == 1)
        #expect(form.counts.hostsPartlyProbed == 0,
                "an unprobed host was also counted as cut short")
        #expect(form.footer.contains("1 host not probed"))
        #expect(!form.footer.contains("not reached"))
    }
}
