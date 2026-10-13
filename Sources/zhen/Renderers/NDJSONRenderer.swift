// NDJSONRenderer.swift — one event per line, as it happens.
//
// A different shape from `--json`, not a formatting variant of it: this is for a caller
// that wants to react to hosts as they answer rather than wait for a document. Both
// carry the same schema, because `ProbeEvent` is part of the model rather than an
// ad-hoc rendering — which is the only reason the two modes cannot drift.
//
// Each line is a complete JSON value terminated by a newline, so a consumer can read it
// with `while read line`. The final line is the report itself, tagged, so a stream
// consumer still gets the artifact without having to run the scan twice.

import Foundation
import ZhenCore

nonisolated struct NDJSONRenderer: Renderer {
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
        let encoder = ScanReport.makeEncoder()
    }

    func handle(_ event: ProbeEvent) {
        // Every event is emitted, including the ones the progress display also shows.
        // A stream consumer should not have to infer that a stage started because a
        // host appeared.
        if case .hostFound = event { state.hosts += 1 }
        if case .degraded(let degradation) = event { progress.degradation(degradation) }
        if case .stageProgress(let stage, let completed, let total) = event {
            progress.draw(stage, completed: completed, total: total, found: state.hosts)
        }
        emit(Line.event(event))
    }

    func finish(_ report: ScanReport) {
        progress.clear()
        emit(Line.report(report))
    }

    private func emit(_ line: Line) {
        guard let data = try? state.encoder.encode(line) else { return }
        Out.stdout(String(decoding: data, as: UTF8.self) + "\n")
    }

    /// One NDJSON line: either a live event or the final report.
    ///
    /// Tagged rather than relying on shape, so a consumer switches on a field instead of
    /// guessing from which keys are present.
    private enum Line: Encodable {
        case event(ProbeEvent)
        case report(ScanReport)

        enum CodingKeys: String, CodingKey {
            case kind
            case schema
            case event
            case report
        }

        func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            // The schema version is on every line. A consumer reading a stream may
            // never see the final report — it might be piped into `head` — and still
            // needs to know it understands what it is reading.
            try container.encode(ScanReport.schemaVersion, forKey: .schema)
            switch self {
            case .event(let event):
                try container.encode("event", forKey: .kind)
                try container.encode(event, forKey: .event)
            case .report(let report):
                try container.encode("report", forKey: .kind)
                try container.encode(report, forKey: .report)
            }
        }
    }
}
