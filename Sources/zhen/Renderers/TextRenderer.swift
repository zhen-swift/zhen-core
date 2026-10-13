// TextRenderer.swift — the device table, for a person.
//
// A rendering of the same `ScanReport` the machine modes emit. The everyday user sees
// what the thing is, whether it is here, and how fast it answered; the engineering
// quantity is not removed, it is placed — RTT and TTL are columns, and identity
// stability is left for the JSON and the app's detail view.

import Foundation
import ZhenCore

nonisolated struct TextRenderer: Renderer {
    var quiet: Bool
    /// Whether the table on stdout may carry escapes. Decided by stdout's own state.
    var color: Bool
    /// How many columns the table may use.
    ///
    /// Resolved once, at construction, rather than read per table: a window resized
    /// mid-scan would otherwise print a header at one width and rows at another.
    ///
    /// Nothing reads it yet. Stage 1 of `PORTS-rendering.md` is the detection, and the
    /// port matrix in stage 2 is the first thing to consume it — declared here now so
    /// the renderer is a function of `(report, width)` and the stage 1 gate can compare
    /// two widths on a FIXED report. Two live scans cannot be compared: the RTT column
    /// is sized to its widest value, so a run that saw 23.70ms and one that saw 9.12ms
    /// differ by a character for reasons that have nothing to do with the window.
    var width: Int
    /// Which port table to draw, when a person has an opinion.
    var portsView: PortView.Preference = .auto
    private let progress: Progress
    private let found = Counter()

    init(quiet: Bool, color: Bool, progressColor: Bool, width: Int = Terminal.stdoutWidth,
         portsView: PortView.Preference = .auto) {
        self.quiet = quiet
        self.color = color
        self.width = width
        self.portsView = portsView
        self.progress = Progress(quiet: quiet, color: progressColor)
    }

    nonisolated final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var state = (hosts: 0, completed: 0, total: 0)
        var hosts: Int { lock.withLock { state.hosts } }
        var completed: Int { lock.withLock { state.completed } }
        var total: Int { lock.withLock { state.total } }
        func addHost() { lock.withLock { state.hosts += 1 } }
        func progress(_ completed: Int, _ total: Int) {
            lock.withLock { state.completed = completed; state.total = total }
        }
    }

    func handle(_ event: ProbeEvent) {
        switch event {
        case .hostFound:
            found.addHost()
            progress.draw(.discovery, completed: found.completed, total: found.total, found: found.hosts)
        case .stageProgress(let stage, let completed, let total):
            found.progress(completed, total)
            progress.draw(stage, completed: completed, total: total, found: found.hosts)
        case .degraded(let degradation):
            progress.degradation(degradation)
        default:
            break
        }
    }

    func finish(_ report: ScanReport) {
        progress.clear()

        guard !report.devices.isEmpty else {
            Out.stdout("No devices answered on \(report.run.target).\n")
            summary(report)
            return
        }

        // Three outcomes, and the difference between the second and the third is the
        // shape of this whole function. The MATRIX REPLACES the device table: a person
        // reading a port matrix is not reading MAC addresses, and six columns plus one
        // per port overflows any terminal. The LONG FORM FOLLOWS it, because it is a
        // second table — about ports rather than about hosts — and the device table
        // above it is where its HOST column's addresses get their names back.
        switch PortView(report.devices, width: width, preference: portsView) {
        case .matrix(let matrix):
            renderMatrix(matrix)
        case .longForm(let form):
            renderDeviceTable(report.devices)
            renderLongForm(form)
        case .none:
            renderDeviceTable(report.devices)
        }
        summary(report)
    }

    /// The six columns an ordinary `zhen scan` prints.
    ///
    /// Unchanged from what it was, and a method now because two of the three port
    /// outcomes want it and one does not. It used to be inline in `finish`, which meant
    /// its rows and widths were computed and then thrown away on every run that scanned
    /// ports.
    private func renderDeviceTable(_ devices: [Device]) {
        // Cells are built plain, padded to their own visible width, and only then
        // wrapped in escapes. Padding the styled string is what misaligned the table:
        // an escape sequence has a length in characters and no width on screen, so a
        // dimmed em-dash counted as nine columns and pushed everything after it left.
        let rows = devices.map { device -> [String] in
            [
                device.primaryAddress.description,
                device.displayName ?? "\u{2014}",
                // The model earns a column of its own rather than being folded into the
                // name. `AppleTV5,3` answers a different question from
                // "Sala de estar principal" — what it IS versus what it is CALLED — and
                // a device routinely has one without the other: the gateway on this
                // network has a model and no name at all.
                device.displayModel ?? "\u{2014}",
                device.mac?.description ?? "\u{2014}",
                device.rtt.map { String(format: "%.2fms", $0.millis) } ?? "\u{2014}",
                device.ttl.map(String.init) ?? "\u{2014}",
            ]
        }
        let headings = ["ADDRESS", "NAME", "MODEL", "HARDWARE", "RTT", "TTL"]
        var widths = headings.map(\.count)
        for row in rows {
            for (index, cell) in row.enumerated() { widths[index] = max(widths[index], cell.count) }
        }

        Out.stdout(style(line(headings, widths), .bold) + "\n")
        for row in rows { Out.stdout(line(row, widths) + "\n") }
    }

    /// Draws one row per open port, under the device table. See `PortLongForm`.
    private func renderLongForm(_ form: PortLongForm) {
        let headings = PortLongForm.headings
        // The address is printed once per host and blanked on its repeats, so the table
        // reads as one block per host. The cost is that a line no longer stands alone:
        // `grep 10.10.20.1` returns only that host's first port, and sorting the output
        // separates a port from its address. `--json` is the machine-readable path and
        // is unaffected.
        var lastHost = ""
        var cells = form.rows.map { row -> [String] in
            let host = row.host == lastHost ? "" : row.host
            lastHost = row.host
            return [host, row.port, row.service, row.rtt]
        }
        // Widths from the MODEL's rows, not the blanked cells: the column has to be as
        // wide as the widest address it holds, and every repeat of the widest one is
        // blank.
        var widths = headings.map(\.count)
        widths[0] = max(widths[0], form.rows.map(\.host.count).max() ?? 0)
        for row in cells {
            for (index, cell) in row.enumerated() where index > 0 {
                widths[index] = max(widths[index], cell.count)
            }
        }
        // The SERVICE column is the only one whose content has no bound. A banner-derived
        // product can be dozens of characters — stage 3 recorded that nothing stopped it
        // blowing the table out, and deferred the fix to here because capping needs the
        // width this stage finally reads.
        //
        // Truncated with an ellipsis rather than wrapped: a row that becomes two rows
        // stops being one fact per line, and the full string is in `--json` regardless.
        let fixed = widths[0] + widths[1] + widths[3] + 2 * 3
        let roomForService = max(PortLongForm.minimumServiceWidth, width - fixed)
        if widths[2] > roomForService {
            widths[2] = roomForService
            cells = cells.map { row in
                var row = row
                row[2] = PortLongForm.truncate(row[2], to: roomForService)
                return row
            }
        }

        Out.stdout("\n" + style(PortLongForm.title, .bold) + "\n")
        // A column header over no rows reads as a table that failed to draw. When
        // nothing was open the footer IS the answer — `0 open · 900 closed · 0 filtered`
        // is a complete statement — so the header is omitted and the footer is not
        // indented, because there is no table for it to be aligned under.
        guard !cells.isEmpty else {
            Out.stdout(style(form.footer, .dim) + "\n")
            return
        }
        Out.stdout(style(line(headings, widths), .bold) + "\n")
        // Rows are plain. Every row here is open by construction, so colouring them
        // green would be a green table rather than a reinforcement of any distinction —
        // the opposite of the rule the matrix follows.
        for row in cells { Out.stdout(line(row, widths) + "\n") }

        // Right-aligned to the TABLE's width, not the terminal's: stage 3 does not
        // consult `width`, which is the state `TerminalWidthTests` and the pty branch of
        // `verify-terminal-width.sh` both record as correct through this stage.
        //
        // `max(0, …)` is required rather than defensive. A one-host run with one open
        // port has a table narrower than `1 open · 0 closed · 0 filtered`, and
        // `String(repeating:count:)` traps on a negative count — a crash reachable from
        // an ordinary command line.
        let table = widths.reduce(0, +) + 2 * (widths.count - 1)
        let indent = max(0, table - form.footer.count)
        Out.stdout(String(repeating: " ", count: indent) + style(form.footer, .dim) + "\n")
    }

    /// Draws one column per port and one row per host.
    ///
    /// `PORTS-rendering.md` argues against the obvious alternative, a single `PORTS`
    /// column reading `22,443`: it collapses three states into one, so a firewalled host
    /// and a dead host become the same empty cell. `Ports.swift` spends its file header
    /// keeping those apart and the renderer must not put them back together.
    private func renderMatrix(_ matrix: PortMatrix) {
        let headings = ["ADDRESS", "NAME"] + matrix.ports.map { "\($0.port)" }
        var widths = headings.enumerated().map { index, heading in
            index < 2 ? heading.count : max(PortMatrix.columnWidth, heading.count)
        }
        let rows = matrix.rows.map { row in
            [row.address, row.name] + row.cells.map { $0.glyph }
        }
        for row in rows {
            for (index, cell) in row.enumerated() where index < 2 {
                widths[index] = max(widths[index], cell.count)
            }
        }

        // **Every port column is padded, the last one included**, and the finished line
        // is trimmed instead. The device table can leave its last column ragged because
        // a ragged right edge of free text costs nothing; a matrix cannot, because the
        // final port's glyph has to sit under the final port's number. Exempting it is
        // what made the first render of this table lean.
        //
        // Trailing space is still kept out of a redirected file — it is removed from the
        // assembled line rather than never added.
        Out.stdout(style(matrixLine(headings, widths, centreFrom: 2), .bold) + "\n")
        for (row, model) in zip(rows, matrix.rows) {
            // Plain first, padded to visible width, styled last. Padding a STYLED string
            // is what misaligned this table before: an escape sequence has a length in
            // characters and no width on screen, so a dimmed glyph counted as nine
            // columns and pushed everything after it left.
            let cells = row.enumerated().map { index, cell -> String in
                guard index >= 2 else { return pad(cell, widths[index]) }
                let last = index == row.count - 1
                return style(centre(cell, widths[index], trailing: !last),
                             model.cells[index - 2].emphasis)
            }
            Out.stdout(cells.joined(separator: "  ") + "\n")
        }
        Out.stdout("\n")
        for line in PortMatrix.legend(width: width) {
            Out.stdout(style(line, .dim) + "\n")
        }
    }

    /// Joins padded cells. The last column is not padded, so no trailing whitespace
    /// reaches a file.
    private func line(_ cells: [String], _ widths: [Int]) -> String {
        cells.enumerated().map { index, cell in
            index == cells.count - 1 ? cell : pad(cell, widths[index])
        }.joined(separator: "  ")
    }

    /// Like `line`, but centres from `centreFrom` on. See `renderMatrix`.
    private func matrixLine(_ cells: [String], _ widths: [Int], centreFrom: Int) -> String {
        cells.enumerated().map { index, cell in
            guard index >= centreFrom else { return pad(cell, widths[index]) }
            return centre(cell, widths[index], trailing: index != cells.count - 1)
        }.joined(separator: "  ")
    }

    enum Style { case bold, dim, plain, open }

    /// Wraps text in escapes, but only when stdout is a terminal.
    ///
    /// The guard is the point: escapes must never reach stdout when it is a pipe or a
    /// file, because the artifact is what stdout carries and an artifact full of
    /// `\u{1B}[2m` is not one.
    private func style(_ text: String, _ kind: Style) -> String {
        guard color, kind != .plain else { return text }
        let code: String
        switch kind {
        case .bold: code = "1"
        case .dim: code = "2"
        // Green REINFORCES the filled glyph; it never carries the meaning alone. Same
        // rule as the paper's figures and the app's status dots — the table has to be
        // readable under `--no-color`, which the study harness uses, and by a
        // colourblind reader.
        case .open: code = "32"
        case .plain: return text
        }
        return "\u{1B}[\(code)m\(text)\u{1B}[0m"
    }

    private func summary(_ report: ScanReport) {
        let timing = report.run.timing
        var line = "\(report.devices.count) device\(report.devices.count == 1 ? "" : "s")"
        line += " · \(String(format: "%.0f", timing.totalElapsedMillis))ms"
        line += " · \(timing.probesSent) probes, \(timing.repliesSeen) replies"
        if timing.effectiveProbesPerSecond > 0 {
            line += " · \(String(format: "%.0f", timing.effectiveProbesPerSecond)) probes/s"
        }
        // The completeness of a run is stated, not implied. A clean summary over a
        // partial scan is a lie of omission.
        if !report.run.outcome.isComplete {
            line += " · PARTIAL (\(report.run.outcome.rawValue))"
        }
        if report.degradations.contains(where: { !$0.recoverable }) {
            line += " · DEGRADED"
        }
        Out.stdout(style(line, .dim) + "\n")
    }

    private func pad(_ text: String, _ width: Int) -> String {
        text.count >= width ? text : text + String(repeating: " ", count: width - text.count)
    }

    /// Centres a cell in its column, leaning left when the slack is odd.
    ///
    /// - Parameter trailing: whether to add the right-hand half of the padding. The
    ///   final column omits it, which is how the matrix aligns without leaving trailing
    ///   whitespace in a redirected file.
    ///
    ///   Trimming the finished line instead does not work once colour is on: the
    ///   padding then sits INSIDE the escape wrapper, the line ends in `\u{1B}[0m`
    ///   rather than a space, and the trim silently does nothing. That difference is
    ///   what `colorOnlyReinforces` caught — the coloured rendering and the plain one
    ///   stopped being the same text.
    private func centre(_ text: String, _ width: Int, trailing: Bool = true) -> String {
        guard text.count < width else { return text }
        let slack = width - text.count
        let left = slack / 2
        return String(repeating: " ", count: left) + text
            + (trailing ? String(repeating: " ", count: slack - left) : "")
    }
}
