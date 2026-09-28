// PortsRenderer.swift — what `zhen ports` prints.
//
// It reuses `PortLongForm` rather than growing a second table, because the question is
// the same one — which ports on which hosts are open, and what is running there — and
// two tables that answer it differently is how a tool starts contradicting itself.
//
// The matrix is deliberately NOT offered here. `zhen ports` is for hosts you already
// have, and the matrix answers "which of these hosts", which is a question you have
// already answered by typing the addresses.

import Foundation
import ZhenCore

/// The `--json` shape: the observations, by host, and nothing invented.
///
/// **Not a new artifact schema.** It is `PortObservation` — already `Codable`, already
/// the shape `ScanReport` carries — in a container that names the host. A reader that
/// can parse a scan's ports can parse this.
nonisolated struct PortScanDocument: Codable {
    nonisolated struct Host: Codable {
        var ip: String
        var ports: [PortObservation]
    }
    var hosts: [Host]
    var outcome: String
    var elapsedMillis: Double

    enum CodingKeys: String, CodingKey {
        case hosts, outcome
        case elapsedMillis = "elapsed_millis"
    }
}

nonisolated struct PortsRenderer {
    var json: Bool
    var quiet: Bool
    var color: Bool

    func finish(_ result: PortScanResult, targets: [IPAddress], spec: PortSpec) {
        // Ordered by the address the user gave, not by whatever the dictionary yields.
        // A run whose output reorders itself between invocations cannot be diffed.
        let hosts = targets.map { (address: $0, observations: result.ports[$0] ?? []) }

        for degradation in result.degradations where !quiet {
            Out.stderr("! \(degradation.stage.rawValue.capitalized): \(degradation.reason)\n")
        }

        guard !json else {
            let document = PortScanDocument(
                hosts: hosts.map { .init(ip: $0.address.description, ports: $0.observations) },
                outcome: result.outcome.rawValue,
                elapsedMillis: result.timing.totalElapsedMillis
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(document), let text = String(data: data, encoding: .utf8) {
                Out.stdout(text + "\n")
            }
            return
        }

        let form = PortLongForm(hosts)
        renderTable(form, targets: targets, spec: spec, result: result)
    }

    private func renderTable(
        _ form: PortLongForm, targets: [IPAddress], spec: PortSpec, result: PortScanResult
    ) {
        let headings = PortLongForm.headings
        var lastHost = ""
        let cells = form.rows.map { row -> [String] in
            let host = row.host == lastHost ? "" : row.host
            lastHost = row.host
            return [host, row.port, row.service, row.rtt]
        }
        var widths = headings.map(\.count)
        widths[0] = max(widths[0], form.rows.map(\.host.count).max() ?? 0)
        for row in cells {
            for (index, cell) in row.enumerated() where index > 0 {
                widths[index] = max(widths[index], cell.count)
            }
        }

        Out.stdout(style(PortLongForm.title, .bold) + "\n")
        if cells.isEmpty {
            Out.stdout(style(form.footer, .dim) + "\n")
        } else {
            Out.stdout(style(line(headings, widths), .bold) + "\n")
            for row in cells { Out.stdout(line(row, widths) + "\n") }
            let table = widths.reduce(0, +) + 2 * (widths.count - 1)
            let indent = max(0, table - form.footer.count)
            Out.stdout(String(repeating: " ", count: indent) + style(form.footer, .dim) + "\n")
        }

        // The summary states the shape of what was asked, because `zhen ports` has no
        // device table above it to say how many hosts were involved.
        var summary = "\(targets.count) host\(targets.count == 1 ? "" : "s")"
            + " · \(spec.probeCount) port\(spec.probeCount == 1 ? "" : "s")"
            + " · \(String(format: "%.0f", result.timing.totalElapsedMillis))ms"
        if result.outcome != .complete {
            summary += " · PARTIAL (\(result.outcome.rawValue))"
        }
        Out.stdout(style(summary, .dim) + "\n")
    }

    /// Pads every column but the last, so no line carries trailing whitespace.
    private func line(_ cells: [String], _ widths: [Int]) -> String {
        cells.enumerated().map { index, cell in
            index == cells.count - 1
                ? cell
                : cell + String(repeating: " ", count: max(0, widths[index] - cell.count))
        }.joined(separator: "  ")
    }

    private enum Style { case bold, dim }

    /// Escapes only when stdout is a terminal, for the same reason the scan renderer
    /// guards them: the artifact is what stdout carries.
    private func style(_ text: String, _ kind: Style) -> String {
        guard color else { return text }
        return "\u{1B}[\(kind == .bold ? "1" : "2")m\(text)\u{1B}[0m"
    }
}
