// GlobalOptions.swift — flags shared by every subcommand.

import ArgumentParser
import Foundation
import ZhenCore

/// How output should be produced.
nonisolated enum OutputMode: String, Sendable {
    /// Human-readable text, the default on a terminal.
    case text
    /// One `ScanReport` on completion, for a caller that wants the artifact.
    case json
    /// One event per line as it happens, for a caller that wants to stream.
    case ndjson
}

/// Flags every command accepts.
struct GlobalOptions: ParsableArguments {
    @Option(name: .long, help: "Network to scan, in CIDR form. Defaults to the primary interface's network.")
    var cidr: String?

    /// Which port table to draw. An override, not the primary interface.
    ///
    /// `auto` derives the choice from the terminal's width and the table's own columns,
    /// which is the right answer nearly always. This exists because the derivation is a
    /// judgement and somebody will want twelve ports as a matrix on a wide screen.
    @Option(name: .long, help: "Port table: matrix, long, or auto.")
    var portsView: PortView.Preference = .auto

    @Option(name: .long, help: "Interface to scan from. Defaults to the one the default route uses.")
    var iface: String?

    @Option(name: .long, help: "Total budget for the scan, e.g. 5s, 500ms, 2m.")
    var deadline: String = "20s"

    @Option(name: .long, help: "Probes in flight. Derived from the descriptor limit when omitted.")
    var concurrency: Int?

    @Flag(name: .long, help: "Emit one ScanReport as JSON on stdout.")
    var json = false

    @Flag(name: .long, help: "Emit one event per line as JSON on stdout.")
    var ndjson = false

    @Flag(name: .long, help: "Suppress the progress display on stderr.")
    var quiet = false

    @Flag(name: .long, help: "Disable ANSI colour.")
    var noColor = false

    /// Which renderer to use.
    ///
    /// `--json` and `--ndjson` are not interchangeable and cannot be combined: one
    /// emits a document at the end, the other a stream as it happens, and a caller
    /// asking for both has not decided what it wants.
    nonisolated func outputMode() throws(ScanSetupError) -> OutputMode {
        switch (json, ndjson) {
        case (true, true):
            throw .badArgument("--json and --ndjson are different output shapes; choose one.")
        case (true, false): return .json
        case (false, true): return .ndjson
        case (false, false): return .text
        }
    }

    /// Whether the artifact on stdout may carry colour.
    ///
    /// Decided by stdout's own state. Reading stderr's, as the first version did, put
    /// escape sequences into `zhen scan > out.txt` — run from a terminal, where
    /// stderr is a tty and stdout is a file — so the saved table was full of `\u{1B}[`
    /// and the column padding, computed from the unstyled string, no longer matched the
    /// styled one that was emitted.
    nonisolated var colorOnStdout: Bool {
        if noColor || Terminal.colorDisabledByEnvironment { return false }
        return Terminal.stdoutIsTTY
    }

    /// Whether the progress display on stderr may carry colour.
    nonisolated var colorOnStderr: Bool {
        if noColor || Terminal.colorDisabledByEnvironment { return false }
        return Terminal.stderrIsTTY
    }

    /// Parses the deadline.
    nonisolated func parsedDeadline() throws(ScanSetupError) -> Duration {
        guard let duration = Duration(humanReadable: deadline) else {
            throw .badArgument("'\(deadline)' is not a duration. Try 5s, 500ms or 2m.")
        }
        guard duration > .zero else {
            throw .badArgument("A deadline of \(deadline) leaves no time to scan anything.")
        }
        return duration
    }

    /// Parses the target network, if one was named.
    nonisolated func parsedNetwork() throws(ScanSetupError) -> IPv4Network? {
        guard let cidr else { return nil }
        guard let network = IPv4Network(cidr) else {
            throw .badArgument("'\(cidr)' is not a network in CIDR form. Try 10.10.20.0/24.")
        }
        return network
    }
}

nonisolated extension Duration {
    /// Builds a duration from a nanosecond count, refusing values `Int64` cannot hold.
    ///
    /// `Int64(someDouble)` traps when the double is out of range, so `--deadline 1e9h`
    /// crashed the process with a fatal error instead of reporting a usage error. A
    /// number a user typed is input, and input that cannot be used is exit 64.
    init?(nanoseconds: Double) {
        guard nanoseconds.isFinite, nanoseconds >= 0,
              nanoseconds < Double(Int64.max)
        else { return nil }
        self = .nanoseconds(Int64(nanoseconds))
    }

    /// Parses `500ms`, `5s`, `2m`, `1h`, or a bare number of seconds.
    ///
    /// Written here rather than taken from a dependency because it is fifteen lines and
    /// `swift-argument-parser` is meant to stay the only external package in the repo.
    init?(humanReadable text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard !trimmed.isEmpty else { return nil }
        let units: [(suffix: String, nanos: Double)] = [
            ("ms", 1_000_000), ("s", 1_000_000_000), ("m", 60_000_000_000), ("h", 3_600_000_000_000),
        ]
        for unit in units where trimmed.hasSuffix(unit.suffix) {
            let number = String(trimmed.dropLast(unit.suffix.count))
            guard let value = Double(number), let duration = Duration(nanoseconds: value * unit.nanos)
            else { return nil }
            self = duration
            return
        }
        guard let seconds = Double(trimmed),
              let duration = Duration(nanoseconds: seconds * 1_000_000_000)
        else { return nil }
        self = duration
    }
}


/// `PortScanType` lives in `ZhenCore`, which has no business importing ArgumentParser.
/// The conformance that makes it a command-line value belongs here instead.
///
/// Not `@retroactive`: that marked a conformance across a *package* boundary, and since
/// the reorganisation `ZhenCore` is in this package, where the compiler rejects it.
extension PortScanType: ExpressibleByArgument {}
