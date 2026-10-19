// ProbeView.swift — the capability probes as a table, and as text to share.

import SwiftUI

struct ProbeView: View {
    @State private var results: [ProbeResult] = []
    @State private var running = false

    var body: some View {
        List {
            Section {
                Button(running ? "Probing…" : "Run the probes") {
                    Task {
                        running = true
                        results = await CapabilityProbe.runAll()
                        running = false
                    }
                }
                .disabled(running)
            } footer: {
                Text("Only a device run counts: the simulator uses the Mac's kernel and sandbox. The SSDP probe sends one multicast datagram on this network.")
            }

            if !results.isEmpty {
                Section("Results") {
                    ForEach(results) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            Label(result.name, systemImage: result.asAssumed
                                  ? "checkmark.circle" : "exclamationmark.triangle")
                                .font(.headline)
                                .foregroundStyle(result.asAssumed ? Color.primary : Color.orange)
                            Text(result.outcome).font(.body.monospaced())
                            Text(result.assumption).font(.footnote).foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
        .navigationTitle("Capability probe")
        .toolbar {
            if !results.isEmpty {
                ShareLink(item: Self.text(results)) { Label("Share", systemImage: "square.and.arrow.up") }
            }
        }
    }

    /// The results as plain text, for pasting into a PR.
    static func text(_ results: [ProbeResult]) -> String {
        results.map { "- \($0.asAssumed ? "as assumed" : "SURPRISE"): \($0.name) — \($0.outcome)" }
            .joined(separator: "\n")
    }
}
