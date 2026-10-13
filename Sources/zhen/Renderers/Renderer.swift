// Renderer.swift — three presentations of one model.
//
// The human mode is a rendering of the same `ScanReport` the machine modes emit, never
// a separate code path. A second path drifts: the text output starts saying something
// the JSON does not, nobody notices because nobody diffs them, and the tool ends up
// with two different opinions about what it found.
//
// **JSON to stdout, progress to stderr, always.** `zhen scan --json > out.json`
// has to produce a valid document while the user still watches a progress display.
// That is not a preference; it is the difference between a tool that composes in a
// pipeline and one that does not.

import Foundation
import ZhenCore

/// Where bytes go.
///
/// Indirected through replaceable sinks rather than writing to the file handles
/// directly, so the stdout/stderr split is a property a test can assert rather than
/// one a reviewer has to take on trust. "JSON on stdout, progress on stderr" is the
/// difference between a tool that composes in a pipeline and one that does not, and it
/// is exactly the kind of rule that decays silently.
nonisolated enum Out {
    /// Redirectable destinations. A lock rather than a bare global because the
    /// renderers write from whichever task is draining the stream.
    private final class Sinks: @unchecked Sendable {
        let lock = NSLock()
        var out: @Sendable (String) -> Void = { FileHandle.standardOutput.write(Data($0.utf8)) }
        var err: @Sendable (String) -> Void = { FileHandle.standardError.write(Data($0.utf8)) }
    }
    private static let sinks = Sinks()

    /// The artifact: JSON, NDJSON, or the human-readable device table.
    static func stdout(_ text: String) {
        let sink = sinks.lock.withLock { sinks.out }
        sink(text)
    }

    /// Progress, degradations and diagnostics. Never the artifact.
    static func stderr(_ text: String) {
        let sink = sinks.lock.withLock { sinks.err }
        sink(text)
    }

    /// Runs `body` with both streams captured, and returns what each received.
    ///
    /// Test support, and the only reason the indirection exists.
    static func capturing<T>(_ body: () throws -> T) rethrows -> (value: T, out: String, err: String) {
        let buffer = Buffer()
        let previous = sinks.lock.withLock { (sinks.out, sinks.err) }
        sinks.lock.withLock {
            sinks.out = { buffer.appendOut($0) }
            sinks.err = { buffer.appendErr($0) }
        }
        defer { sinks.lock.withLock { (sinks.out, sinks.err) = previous } }
        let value = try body()
        return (value, buffer.out, buffer.err)
    }

    /// Accumulates captured output. A class so the sink closures can be `@Sendable`
    /// without capturing a mutable local.
    private final class Buffer: @unchecked Sendable {
        private let lock = NSLock()
        private var stdoutText = ""
        private var stderrText = ""
        var out: String { lock.withLock { stdoutText } }
        var err: String { lock.withLock { stderrText } }
        func appendOut(_ text: String) { lock.withLock { stdoutText += text } }
        func appendErr(_ text: String) { lock.withLock { stderrText += text } }
    }
}

/// Consumes a scan's events and produces output.
nonisolated protocol Renderer: Sendable {
    /// Called for each event as it happens.
    func handle(_ event: ProbeEvent)
    /// Called once with the finished artifact.
    func finish(_ report: ScanReport)
}

nonisolated enum Renderers {
    /// Picks a renderer for the requested mode.
    static func make(mode: OutputMode, options: GlobalOptions) -> any Renderer {
        // Two colour decisions, because the two streams are different destinations and
        // can disagree — `zhen scan > out.txt` from a terminal has a tty on stderr
        // and a file on stdout.
        let stdout = options.colorOnStdout
        let stderr = options.colorOnStderr
        switch mode {
        case .json: return JSONRenderer(quiet: options.quiet, color: stderr)
        case .ndjson: return NDJSONRenderer(quiet: options.quiet, color: stderr)
        case .text: return TextRenderer(quiet: options.quiet, color: stdout, progressColor: stderr,
                                        portsView: options.portsView)
        }
    }
}

/// The progress display, shared by all three modes.
///
/// Always on stderr, so it survives a redirected stdout. Redraws are coalesced on a
/// timer rather than emitted per event: a terminal renders perhaps sixty frames a
/// second while the scanner produces thousands of events, and writing one line per
/// event makes the scan slower than the network.
nonisolated struct Progress: Sendable {
    var quiet: Bool
    var color: Bool
    private static let minimumRedrawInterval = Duration.milliseconds(80)

    /// Guards the redraw cadence. A value type holding a class so the renderer can stay
    /// a struct without losing the timestamp between calls.
    final class Clock: @unchecked Sendable {
        var last: MonotonicInstant?
        var lastLength = 0
    }
    var clock = Clock()

    func draw(_ stage: Stage, completed: Int, total: Int, found: Int, force: Bool = false) {
        guard !quiet, Terminal.stderrIsTTY else { return }
        let now = MonotonicInstant.now
        if !force, let last = clock.last, now.duration(since: last) < Self.minimumRedrawInterval {
            return
        }
        clock.last = now
        let percent = total > 0 ? Int(Double(completed) / Double(total) * 100) : 0
        let width = 24
        let filled = total > 0 ? completed * width / max(total, 1) : 0
        let bar = String(repeating: "█", count: min(filled, width))
            + String(repeating: "░", count: width - min(filled, width))
        let dim = color ? "\u{1B}[2m" : ""
        let reset = color ? "\u{1B}[0m" : ""
        let line = "\r\(dim)\(stage.label)\(reset) \(bar) \(percent)%  \(found) found"
        clock.lastLength = line.count
        Out.stderr(line)
    }

    /// Clears the progress line so the summary does not land on top of it.
    func clear() {
        guard !quiet, Terminal.stderrIsTTY, clock.lastLength > 0 else { return }
        Out.stderr("\r" + String(repeating: " ", count: clock.lastLength + 8) + "\r")
        clock.lastLength = 0
    }

    /// Reports a degradation. Never swallowed, never only logged — the artifact carries
    /// it too, and this is the copy a person reads while the scan is still running.
    func degradation(_ degradation: Degradation) {
        guard !quiet else { return }
        clear()
        let mark = color ? "\u{1B}[33m!\u{1B}[0m" : "!"
        Out.stderr("\(mark) \(degradation.stage.label): \(degradation.reason)\n")
    }
}
