// ZhenPadApp.swift — two tabs: what the sandbox allows, and a scan. `-autorun` runs both
// unattended; see Autorun.swift.

import SwiftUI

@main
struct ZhenPadApp: App {
    @State private var harness = Harness()

    var body: some Scene {
        WindowGroup {
            @Bindable var harness = harness
            TabView(selection: $harness.tab) {
                Tab("Probe", systemImage: "stethoscope", value: Harness.Tab.probe) {
                    NavigationStack { ProbeView() }
                }
                Tab("Scan", systemImage: "dot.radiowaves.left.and.right", value: Harness.Tab.scan) {
                    NavigationStack { ScanView() }
                }
            }
            .environment(harness)
            .task {
                if Autorun.isRequested { await Autorun.run(harness) }
            }
        }
    }
}
