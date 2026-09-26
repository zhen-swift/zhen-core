// PortMatrix.swift — one column per port, one row per host.
//
// Stage 2 of `Docs/PORTS-rendering.md`, and the thing that closes the defect found on
// 2026-09-24: `zhen scan --deep --ports 22,80,443` ran the port scan, wrote the results
// onto every host in `ScanPipeline`, and then printed six hardcoded columns that did
// not include any of them. The data reached the artifact and was discarded at print
// time. `--json` had it all along.
//
// ── Four states, not three ────────────────────────────────────────────────────
//
// `PortState` has three cases. This table needs four, and the fourth is the one a
// matrix invites you to forget: **a host that was never port-scanned at all.**
// Discovery can find a host after the port stage has taken its slice of the budget, and
// a partial run skips the stage entirely, so an empty `ports` array is a routine
// result rather than an edge case.
//
// Every cell in a matrix looks answered. Drawing "never asked" and "asked, heard
// silence" the same way is the same class of error as collapsing open and filtered into
// a comma list — the error `Ports.swift` spends its file header arguing against — one
// level up. So `notProbed` is its own glyph.

import Foundation
import ZhenCore

/// A host's answer for one port, including never having been asked.
nonisolated enum PortCell: Equatable {
    case open
    case closed
    case filtered
    /// Silence from UDP: open or filtered, and the two cannot be separated.
    case openFiltered
    /// The host was not port-scanned, so nothing is known about this port.
    case notProbed

    init(_ state: PortState) {
        switch state {
        case .open: self = .open
        case .closed: self = .closed
        case .filtered: self = .filtered
        case .openFiltered: self = .openFiltered
        }
    }

    /// The mark. **Shape carries the meaning; colour only reinforces it.**
    var glyph: String {
        switch self {
        case .open: "\u{25CF}"      // ● filled — something is listening
        case .closed: "\u{25CB}"    // ○ hollow — refused, so the host is alive
        case .filtered: "\u{00B7}"  // · a dot — silence, which says nothing
        // ◐ half filled — half of open, which is exactly what is known. Shape carries
        // it: a reader who cannot see colour still sees that this is neither the solid
        // mark nor the bare dot.
        case .openFiltered: "\u{25D0}"
        case .notProbed: "\u{2013}" // – a dash — never asked
        }
    }

    /// How the glyph is emphasised. Never the sole carrier of the distinction.
    var emphasis: TextRenderer.Style {
        switch self {
        case .open: .open
        case .closed: .plain
        case .openFiltered: .plain
        case .filtered, .notProbed: .dim
        }
    }
}

/// The whole table: which ports were scanned, and what each host said about each.
nonisolated struct PortMatrix {
    /// One host's row.
    struct Row {
        var address: String
        var name: String
        var cells: [PortCell]
    }

    /// The ports, in the order they are drawn.
    var ports: [PortObservation]
    /// The hosts, in the order the device table would have drawn them.
    var rows: [Row]

    /// A port column's minimum width, from `PORTS-rendering.md`'s width section.
    ///
    /// Five plus the two-space gutter the table already joins with is seven per port,
    /// which is where that document's "8 ports is 56 columns" comes from.
    static let columnWidth = 5

    /// The key, printed under the table. Four entries because there are four states.
    /// The key, one entry per state.
    ///
    /// Five since UDP arrived, and five entries is 66 characters — **wider than a
    /// 60-column terminal, which the matrix itself may well fit.** The gate that checks
    /// every chosen matrix against the width it was chosen for caught that: the table
    /// fitted and its own key did not.
    ///
    /// So it wraps rather than being counted against the table. Dropping entries to fit
    /// would leave a glyph on screen with nothing explaining it, which is worse than
    /// two lines.
    static let legendEntries = [
        "\(PortCell.open.glyph) open",
        "\(PortCell.closed.glyph) closed",
        "\(PortCell.filtered.glyph) filtered",
        "\(PortCell.openFiltered.glyph) open or filtered",
        "\(PortCell.notProbed.glyph) not probed",
    ]

    /// The key, laid out for a terminal this wide.
    static func legend(width: Int) -> [String] {
        var lines: [String] = []
        var current = ""
        for entry in legendEntries {
            let candidate = current.isEmpty ? entry : current + "   " + entry
            if candidate.count <= width || current.isEmpty {
                current = candidate
            } else {
                lines.append(current)
                current = entry
            }
        }
        if !current.isEmpty { lines.append(current) }
        return lines
    }

    /// Builds a matrix, or `nil` when no host in the run was port-scanned.
    ///
    /// `nil` is what keeps an ordinary `zhen scan` looking exactly as it did. The device
    /// table is only replaced when there is something to replace it with.
    init?(_ devices: [Device]) {
        // The union, not the first host's list. Hosts can disagree: one scanned before
        // the budget ran out has every port, one scanned after has none, and a future
        // per-host spec could differ outright. Taking the first host's ports would
        // silently drop a column that another host has an answer for.
        var seen: [PortKey: PortObservation] = [:]
        var order: [PortKey] = []
        for device in devices {
            for observation in device.ports {
                let key = PortKey(port: observation.port, proto: observation.proto)
                if seen[key] == nil { order.append(key) }
                seen[key] = observation
            }
        }
        guard !order.isEmpty else { return nil }
        order.sort { ($0.port, $0.proto.rawValue) < ($1.port, $1.proto.rawValue) }
        self.ports = order.compactMap { seen[$0] }

        // One row per address that was probed, so a port answering on v4 and silent on
        // v6 shows as two rows rather than one cell holding whichever came first. A
        // single-address device — every device before IPv6 discovery — is one row, as
        // it always was.
        self.rows = devices.flatMap { device in
            device.portsByAddress.map { host in (device, host.address, host.observations) }
        }.map { device, address, observations in
            let answers = Dictionary(
                observations.map { (PortKey(port: $0.port, proto: $0.proto), $0) },
                uniquingKeysWith: { first, _ in first }
            )
            return Row(
                address: address.description,
                name: device.displayName ?? "\u{2014}",
                // `notProbed` when this host has no answer for this port — which is
                // every port of a host the stage never reached.
                cells: order.map { key in
                    answers[key].map { PortCell($0.state) } ?? .notProbed
                }
            )
        }
    }

    /// A port is identified by its number AND its transport. 53/tcp and 53/udp are two
    /// different questions with two different answers.
    struct PortKey: Hashable {
        var port: UInt16
        var proto: TransportProtocol
    }
}
