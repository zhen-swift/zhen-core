// ZhenPadApp.swift — two tabs: what the sandbox allows, and a scan. `-autorun` runs both
// unattended; see Autorun.swift.

import SwiftUI

@main
struct ZhenPadApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                Tab("Probe", systemImage: "stethoscope") {
                    NavigationStack { ProbeView() }
                }
                Tab("Scan", systemImage: "dot.radiowaves.left.and.right") {
                    NavigationStack { ScanView() }
                }
            }
            .task {
                if Autorun.isRequested { await Autorun.run() }
            }
        }
    }
}
