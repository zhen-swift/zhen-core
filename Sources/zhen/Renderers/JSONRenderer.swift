// JSONRenderer.swift — one document at the end, for a caller that wants the artifact.
//
// Encoded with core's canonical encoder: sorted keys so two identical scans produce
// byte-identical documents and a real change is what a diff shows, and unescaped
// slashes so a CIDR reads as `10.10.20.0/24` rather than `10.10.20.0\/24`.
//
// The document goes to stdout and the progress display keeps running on stderr, so
// `zhen scan --json > out.json` is both a valid file and a visible scan.

import Foundation
import ZhenCore

nonisolated struct JSONRenderer: Renderer {
    var quiet: Bool
    var color: Bool
    private let progress: Progress
    private let state = Counter()

    init(quiet: Bool, color: Bool) {
        self.quiet = quiet
        self.color = color
        self.progress = Progress(quiet: quiet, color: color)
    }

    final class Counter: @unchecked Sendable {
        var hosts = 0
    }

    func handle(_ event: ProbeEvent) {
        switch event {
        case .hostFound:
            state.hosts += 1
            progress.draw(.discovery, completed: 0, total: 0, found: state.hosts)
        case .stageProgress(let stage, let completed, let total):
            progress.draw(stage, completed: completed, total: total, found: state.hosts)
        case .degraded(let degradation):
            progress.degradation(degradation)
        default:
            break
        }
    }

    func finish(_ report: ScanReport) {
        progress.clear()
        do {
            var text = String(decoding: try report.encoded(), as: UTF8.self)
            text.append("\n")
            Out.stdout(text)
        } catch {
            // Encoding a value type built entirely from other value types should not be
            // able to fail, but a crash here would destroy a scan that already
            // succeeded, so it degrades to a diagnostic on stderr and an empty stdout
            // the caller can detect.
            Out.stderr("The report could not be encoded: \(error)\n")
        }
    }
}
