// ProbeView.swift — the capability probes as a table, and as text to share.

import SwiftUI

struct ProbeView: View {
    @Environment(Harness.self) private var harness

    var body: some View {
        List {
            Section {
                Button(harness.probing ? "Probing…" : "Run the probes") {
                    Task { await harness.runProbes() }
                }
                .disabled(harness.probing)
            } footer: {
                Text("Only a device run counts: the simulator uses the Mac's kernel and sandbox. The SSDP probe sends one multicast datagram on this network.")
            }

            if !harness.probeResults.isEmpty {
                Section("Results") {
                    ForEach(harness.probeResults) { result in
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
            if !harness.probeResults.isEmpty {
                ShareLink(item: Self.text(harness.probeResults)) { Label("Share", systemImage: "square.and.arrow.up") }
            }
        }
    }

    /// The results as plain text, for pasting into a PR.
    static func text(_ results: [ProbeResult]) -> String {
        results.map { "- \($0.asAssumed ? "as assumed" : "SURPRISE"): \($0.name) — \($0.outcome)" }
            .joined(separator: "\n")
    }
}
