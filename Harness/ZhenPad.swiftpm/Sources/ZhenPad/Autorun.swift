// Autorun.swift — the harness without a person: probe, scan once, write the results.
//
// Launched with `-autorun`, the app runs every probe and one 30-second scan with no port
// stage, then writes `probe.txt` and `report.json` into its Documents directory and
// `done` last. A script reads them with `xcrun simctl get_app_container … data` on a
// simulator, or from the Files app on a device. Nothing here is needed to use the app by
// hand.

import Foundation
import ZhenCore

enum Autorun {
    static var isRequested: Bool { ProcessInfo.processInfo.arguments.contains("-autorun") }

    static func run() async {
        let documents = URL.documentsDirectory
        let probes = await CapabilityProbe.runAll()
        write(ProbeView.text(probes), to: documents.appending(path: "probe.txt"))

        let session = ScanSession()
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
