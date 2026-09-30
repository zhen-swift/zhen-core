// PortView.swift — which port table, if any.
//
// Stage 3 of `Docs/plans/PORTS-rendering.md`, and the seam stage 4 replaces.
//
// The two tables differ in KIND, not only in shape, and this is the one place that
// knows it. The matrix REPLACES the device table — a person reading a port matrix is
// not reading MAC addresses, and six columns plus one per port overflows any terminal.
// The long form FOLLOWS it: it is a second table, about ports rather than about hosts,
// and the device table above it is where its HOST column's addresses get their names.

import ArgumentParser
import Foundation
import ZhenCore

/// The port rendering a report calls for.
nonisolated enum PortView {
    /// No host in the run was port-scanned. The device table, exactly as it was.
    case none
    /// Few enough ports to give each one a column. Replaces the device table.
    case matrix(PortMatrix)
    /// Too many for columns: one row per open port, following the device table.
    case longForm(PortLongForm)

    /// Which table a person asked for, when they asked.
    ///
    /// The override exists because the threshold is a judgement and somebody will want
    /// twelve ports as a matrix on a wide terminal. If it turns out people set this
    /// routinely, the automatic rule is wrong and gets fixed rather than documented
    /// around.
    enum Preference: String, CaseIterable, Sendable, ExpressibleByArgument {
        case auto, matrix, long
    }

    /// Whether a matrix of these columns fits a terminal this wide.
    ///
    /// **Derived from the table's own measured columns, not from a constant.** Stage 3
    /// shipped `longFormThreshold = 9`, which was `PORTS-rendering.md`'s arithmetic —
    /// a port column is five wide plus a two-space gutter, so eight ports is 56 columns
    /// and fits 80 beside a 15-column address — typed in by hand. That number is wrong
    /// on a 200-column terminal, wrong again on a 60-column one, and wrong a third time
    /// the moment an address or a device name is longer than the example's.
    ///
    /// This asks the columns instead. The widths are the same ones `renderMatrix`
    /// computes, so the decision and the drawing cannot disagree about what fits.
    static func matrixFits(_ matrix: PortMatrix, width: Int) -> Bool {
        matrixWidth(matrix) <= width
    }

    /// The width the matrix will actually occupy, column by column.
    static func matrixWidth(_ matrix: PortMatrix) -> Int {
        let address = max("ADDRESS".count, matrix.rows.map(\.address.count).max() ?? 0)
        let name = max("NAME".count, matrix.rows.map(\.name.count).max() ?? 0)
        let ports = matrix.ports.map { max(PortMatrix.columnWidth, "\($0.port)".count) }
        // Two spaces between every pair of columns, and there are `ports.count + 2`
        // columns in total.
        let gutters = 2 * (ports.count + 1)
        return address + name + ports.reduce(0, +) + gutters
    }

    /// Chooses from the devices, the width available, and what was asked for.
    init(_ devices: [Device], width: Int = Terminal.fallbackWidth,
         preference: Preference = .auto) {
        guard let matrix = PortMatrix(devices) else {
            self = .none
            return
        }
        switch preference {
        case .matrix:
            self = .matrix(matrix)
        case .long:
            self = .longForm(PortLongForm(devices))
        case .auto:
            self = Self.matrixFits(matrix, width: width)
                ? .matrix(matrix)
                : .longForm(PortLongForm(devices))
        }
    }
}
