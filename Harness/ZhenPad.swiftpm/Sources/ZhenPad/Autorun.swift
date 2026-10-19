// Autorun.swift — the harness without a person: probe, scan once, write the results.
//
// Launched with `-autorun`, the app runs every probe and one 30-second scan with no port
// stage, on screen — the tabs switch as it goes, so a recording of the simulator shows
// the run — then writes `probe.txt` and `report.json` into its Documents directory and
// `done` last. A script reads them with `xcrun simctl get_app_container … data` on a
// simulator, or from the Files app on a device. Nothing here is needed to use the app by
// hand.

import Foundation
import ZhenCore

enum Autorun {
    static var isRequested: Bool { ProcessInfo.processInfo.arguments.contains("-autorun") }

    static func run(_ harness: Harness) async {
        let documents = URL.documentsDirectory
        harness.tab = .probe
        await harness.runProbes()
        write(ProbeView.text(harness.probeResults), to: documents.appending(path: "probe.txt"))
        // Long enough to read the table before the tab changes.
        try? await Task.sleep(for: .seconds(4))

        harness.tab = .scan
        let session = harness.session
        await session.scan(budget: .seconds(30), ports: .off)
        switch session.phase {
        case .finished(let report):
            write(report.prettyJSON, to: documents.appending(path: "report.json"))
        case .failed(let message):
            write(message, to: documents.appending(path: "report-error.txt"))
        case .idle, .scanning:
            break
        }
        write("", to: documents.appending(path: "done"))
    }

    private static func write(_ text: String, to url: URL) {
        try? Data(text.utf8).write(to: url, options: .atomic)
    }
}
