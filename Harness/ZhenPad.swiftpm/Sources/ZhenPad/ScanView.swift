// ScanView.swift — run a scan, read what came back, share the report.

import SwiftUI
import UIKit
import ZhenCore

struct ScanView: View {
    @Environment(Harness.self) private var harness
    private var session: ScanSession { harness.session }
    @State private var withPorts = false

    var body: some View {
        List {
            Section {
                Toggle("Scan ports of every host found", isOn: $withPorts)
                Button(isScanning ? "Scanning… \(session.liveHosts) found" : "Scan this network") {
                    Task {
                        // Foreground only: iPadOS suspends a backgrounded app mid-sweep, so
                        // the screen stays on for the length of a scan.
                        UIApplication.shared.isIdleTimerDisabled = true
                        await session.scan(budget: .seconds(withPorts ? 120 : 30),
                                           ports: withPorts ? .everyHost : .off)
                        UIApplication.shared.isIdleTimerDisabled = false
                    }
                }
                .disabled(isScanning)
            } footer: {
                if let interface = session.interfaceSummary {
                    Text("\(interface)\nEngine: \(session.capabilities ?? "")")
                }
            }

            switch session.phase {
            case .idle, .scanning:
                EmptyView()
            case .failed(let message):
                Section("Could not scan") { Text(message) }
            case .finished(let report):
                Section("Run") {
                    LabeledContent("Outcome", value: "\(report.run.outcome)")
                    LabeledContent("Devices", value: "\(report.devices.count)")
                    LabeledContent("Capabilities used",
                                   value: report.run.engine.capabilities.names.joined(separator: ", "))
                }
                if !report.degradations.isEmpty {
                    Section("Degradations") {
                        ForEach(Array(report.degradations.enumerated()), id: \.offset) { _, degradation in
                            Text(degradation.reason).font(.footnote)
                        }
                    }
                }
                Section("Devices") {
                    ForEach(report.devices, id: \.primaryAddress) { device in
                        VStack(alignment: .leading) {
                            Text(device.displayName ?? "Unnamed").font(.headline)
                            Text(verbatim: "\(device.primaryAddress)").font(.body.monospaced())
                            if !device.ports.isEmpty {
                                Text("\(device.ports.count) port observations")
                                    .font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Scan")
        .toolbar {
            if case .finished(let report) = session.phase {
                ShareLink(item: report.prettyJSON) { Label("Share report", systemImage: "square.and.arrow.up") }
            }
        }
    }

    private var isScanning: Bool {
        if case .scanning = session.phase { true } else { false }
    }
}
