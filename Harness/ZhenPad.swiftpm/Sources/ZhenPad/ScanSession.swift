// ScanSession.swift — one scan at a time, through the same adapter the Mac app uses.
//
// The list shown after a scan comes from the returned report, never from the progress
// events: the progress channel may drop events by design (see `ScanRunner.swift`), so it
// only drives the live counter.

import Foundation
import Observation
import ZhenCore
import ZhenScan

@Observable
final class ScanSession {
    enum Phase {
        case idle
        case scanning
        case finished(ScanReport)
        case failed(String)
    }

    private(set) var phase: Phase = .idle
    /// Hosts reported live while the sweep runs. Display only.
    private(set) var liveHosts = 0
    /// The interface the runner resolved, once it has.
    private(set) var interfaceSummary: String?
    /// The capabilities the engine claims, from its descriptor.
    private(set) var capabilities: String?

    private let store = InMemoryHistoryStore()
    private var runner: ScanRunner?

    /// Runs one scan of the primary interface's network.
    func scan(budget: Duration, ports: PortStage) async {
        phase = .scanning
        liveHosts = 0
        do {
            let runner: ScanRunner
            if let existing = self.runner {
                runner = existing
            } else {
                runner = try await ScanRunner(store: store, capture: .directOnly)
                self.runner = runner
            }
            interfaceSummary = "\(runner.interface.name) \(runner.interface.address) — \(runner.interface.network)"
            capabilities = runner.descriptor.capabilities.names.joined(separator: ", ")

            let (events, sink, finish) = ProbeStream.sinking(buffering: .progress)
            let counter = Task { [weak self] in
                for await event in events {
                    if case .hostFound = event { self?.liveHosts += 1 }
                }
            }
            let completed = await runner.run(budget: budget, ports: ports, progress: sink)
            finish()
            await counter.value
            phase = .finished(completed.report)
        } catch {
            phase = .failed(String(describing: error))
        }
    }
}

extension ScanReport {
    /// The canonical JSON, pretty-printed for reading on the device.
    var prettyJSON: String {
        let encoder = ScanReport.makeEncoder()
        encoder.outputFormatting.insert(.prettyPrinted)
        guard let data = try? encoder.encode(self) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}
