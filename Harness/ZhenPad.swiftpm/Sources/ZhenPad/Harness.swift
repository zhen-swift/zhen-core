// Harness.swift — the app's state, shared by the tabs and by `-autorun`.
//
// One object, so an unattended run is the same run a person would watch: `-autorun`
// drives these methods and the tabs show what they do.

import Foundation
import Observation

@Observable
final class Harness {
    enum Tab: Hashable { case probe, scan }

    var tab: Tab = .probe
    private(set) var probeResults: [ProbeResult] = []
    private(set) var probing = false
    let session = ScanSession()

    func runProbes() async {
        probing = true
        probeResults = await CapabilityProbe.runAll()
        probing = false
    }
}
