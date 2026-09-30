// PortLongForm.swift — one row per OPEN port, under the device table.
//
// Stage 3 of `Docs/plans/PORTS-rendering.md`. The matrix answers *which hosts*; this answers
// *what is running*, and it is the only view where service identity appears at all.
//
// ── Only open ports get rows ──────────────────────────────────────────────────
//
// 100 ports across 9 hosts is 900 observations, and on a real network 891 of them say
// "nothing here". Printing them buries the nine lines the person opened the terminal
// for. Closed and filtered are COUNTED in the footer instead, which keeps `Ports.swift`'s
// three-valued distinction intact without stating it 900 times.
//
// ── The fourth state, once more ───────────────────────────────────────────────
//
// `PortMatrix` needed a fourth glyph for a host that was never port-scanned. A list of
// open ports has nowhere to put one: an unprobed host contributes no rows AND no
// observations, so it would vanish from a footer that counts only observations. The
// footer therefore changes unit for one clause and counts HOSTS — `· 3 hosts not
// probed` — present only when it is nonzero, because `0 hosts not probed` on every
// ordinary run is noise that trains the reader to skip the line that matters.
//
// **This does not close the gap completely, and the ledger says so.** A host that was
// given 40 of 100 ports before the budget expired contributes 40 observations and is
// not counted here as unprobed. Its missing 60 simply vanish. The matrix renders that
// case correctly, as dashes; this view cannot.
//
// ── No STATE column ───────────────────────────────────────────────────────────
//
// A deliberate deviation from the rendering document's long-form section, which draws
// one. Every row here is `open` by construction, so the column is a constant repeated
// once per line, and it costs eight columns of a table that has to hold a service
// string. The section heading and the footer's leading `N open` carry it — which is why
// the heading stays OPEN PORTS rather than shortening to PORTS, and why the footer
// keeps leading with the open count.

import Foundation
import ZhenCore

nonisolated struct PortLongForm {
    /// One open port on one host, already text.
    ///
    /// `host` always carries the full address. Printing it once per host and blanking
    /// the repeats is the renderer's job, so the model stays assertable and the
    /// presentation choice stays reversible.
    struct Row: Equatable {
        var host: String
        var port: String
        var service: String
        var rtt: String
    }

    /// What the run saw, in the two different units the footer states.
    ///
    /// Three OBSERVATION counts and one HOST count. The unit change is deliberate and
    /// is the whole reason the last clause says "hosts" out loud.
    struct Counts: Equatable {
        var open = 0
        var closed = 0
        var filtered = 0
        /// UDP ports that said nothing, which means open or filtered.
        var openFiltered = 0
        var hostsNotProbed = 0
        /// Hosts that were probed, but not for every port in the set.
        ///
        /// Raised at stage 3 as a hole and left open there: a host given 40 of 100
        /// ports before the budget expired contributes 40 observations and is not
        /// "not probed", so its missing 60 simply vanished and the three counts came to
        /// less than `probed hosts x port set` with nothing saying why. The matrix
        /// renders that case correctly, as dashes; the long form could not represent it
        /// at all.
        var hostsPartlyProbed = 0
        /// The observations those hosts never got to make.
        var missingObservations = 0
    }

    var rows: [Row]
    var counts: Counts

    /// The section heading. Not "PORTS": see the note on the dropped STATE column.
    static let title = "OPEN PORTS"
    /// Column headings, in `Row`'s field order.
    static let headings = ["HOST", "PORT", "SERVICE", "RTT"]
    /// Nothing known — the device table's existing idiom for an absent cell.
    static let unknown = "\u{2014}"

    /// What an unanswered UDP port's SERVICE cell says.
    static let ambiguous = "open or filtered \u{2014} no reply"

    /// The narrowest the SERVICE column is allowed to get.
    ///
    /// Below this the column holds an ellipsis and little else, at which point dropping
    /// it entirely would be more honest than pretending to show it. Stage 8's compact
    /// work is where that decision belongs; this is the floor until then.
    static let minimumServiceWidth = 12

    /// Shortens to `width`, ending in an ellipsis, so a long banner cannot widen the
    /// table past the terminal. The full string stays in the artifact.
    static func truncate(_ text: String, to width: Int) -> String {
        guard text.count > width, width > 1 else { return text }
        return String(text.prefix(width - 1)) + "\u{2026}"
    }

    /// From a scan's devices.
    init(_ devices: [Device]) {
        self.init(devices.flatMap(\.portsByAddress))
    }

    /// From bare address-and-observation pairs.
    ///
    /// `zhen ports` has no `Device` to hand — it never ran discovery, which is the
    /// entire point of it — so the model takes the two things it actually reads rather
    /// than making the caller manufacture a `Device` with empty naming in it.
    init(_ hosts: [(address: IPAddress, observations: [PortObservation])]) {
        var rows: [Row] = []
        var counts = Counts()
        // The port set is the widest any host was asked about. A host with fewer
        // observations than this was cut short — there is no other way to be missing
        // one, since every host is handed the same spec.
        let fullSet = hosts.map(\.observations.count).max() ?? 0
        for host in hosts {
            // A host with no observations at all is this view's version of the matrix's
            // dash. It produces no rows and no observation counts, so counting it here
            // is the only thing that stops it disappearing from the text entirely.
            guard !host.observations.isEmpty else {
                counts.hostsNotProbed += 1
                continue
            }
            // An exhaustive switch rather than three filters: a fourth `PortState`
            // should break the build here, not silently produce a footer that does not
            // add up.
            for observation in host.observations {
                switch observation.state {
                case .open: counts.open += 1
                case .closed: counts.closed += 1
                case .filtered: counts.filtered += 1
                case .openFiltered: counts.openFiltered += 1
                }
            }
            if host.observations.count < fullSet {
                counts.hostsPartlyProbed += 1
                counts.missingObservations += fullSet - host.observations.count
            }
            // Service identity is read from the DEVICE, never from `PortMatrix.ports`.
            // That array keeps whichever host was seen last for each port number, which
            // is right for a column heading and would attribute one host's nginx to
            // another host's port here.
            //
            // Ordered the way the matrix orders its columns, so a reader moving between
            // the two views is not re-reading a differently sorted table.
            // Open AND open-or-filtered. An unanswered UDP port is the finding on that
            // transport — dropping it to the footer would bury the only result a UDP
            // scan usually produces — but it is a CANDIDATE rather than a confirmation,
            // and its SERVICE cell says so rather than showing an em dash that reads
            // like a service nobody identified.
            let open = host.observations
                .filter { $0.state == .open || $0.state == .openFiltered }
                .sorted {
                ($0.port, $0.proto.rawValue) < ($1.port, $1.proto.rawValue)
            }
            rows += open.map { observation in
                let service = observation.state == .openFiltered
                    ? (observation.service?.displayText ?? Self.ambiguous)
                    : (observation.service?.displayText ?? "")
                return Row(
                    // The ADDRESS, not the name. The device table is directly above and
                    // already holds the address-to-name mapping; repeating a
                    // 23-character name on ten rows would spend the width the STATE
                    // column just freed on something the reader can already see.
                    host: host.address.description,
                    // 53/tcp and 53/udp are two questions with two answers, exactly as
                    // `PortMatrix.PortKey` has it.
                    port: "\(observation.port)/\(observation.proto.rawValue)",
                    service: service.isEmpty ? Self.unknown : service,
                    // The repository's only RTT format, verbatim from the device table.
                    //
                    // The em-dash matters structurally as well as visually: `line(_:_:)`
                    // still joins its two-space separator before an empty final cell, so
                    // an open port whose probe recorded no round trip would end its line
                    // in whitespace. Substituting here removes the case; trimming the
                    // assembled line would not, because once colour is on the padding
                    // sits inside the escape wrapper and the trim silently does nothing.
                    rtt: observation.rtt.map { String(format: "%.2fms", $0.millis) }
                        ?? Self.unknown
                )
            }
        }
        self.rows = rows
        self.counts = counts
    }

    /// The counted line, and the thing that has to reconcile with `--json`.
    ///
    /// `open + closed + filtered` is every `PortObservation` in the report, and
    /// `hostsNotProbed` is every device whose `ports` array is empty. Nothing is
    /// rounded, bucketed or deduplicated between those numbers and the artifact.
    ///
    /// The hosts clause comes last so a reader — or the reconciliation test — can take
    /// the first three integers positionally and treat the fourth as optional.
    var footer: String {
        var text = "\(counts.open) open \u{00B7} \(counts.closed) closed "
            + "\u{00B7} \(counts.filtered) filtered"
        // Only when there are some, for the same reason the hosts clause is
        // conditional: a zero on every TCP scan trains the reader to skip the line.
        if counts.openFiltered > 0 {
            text += " \u{00B7} \(counts.openFiltered) open or filtered"
        }
        if counts.hostsNotProbed > 0 {
            text += " \u{00B7} \(counts.hostsNotProbed) host"
                + (counts.hostsNotProbed == 1 ? "" : "s") + " not probed"
        }
        // Stated in OBSERVATIONS, because that is the unit the three counts above are
        // in and the gap is exactly what they are short by. A reader adding up the
        // first three and comparing against hosts times ports now finds the difference
        // named rather than missing.
        if counts.missingObservations > 0 {
            text += " \u{00B7} \(counts.missingObservations) not reached on "
                + "\(counts.hostsPartlyProbed) host"
                + (counts.hostsPartlyProbed == 1 ? "" : "s")
        }
        return text
    }
}

nonisolated extension ServiceIdentity {
    /// Name, product and version joined by spaces — `http nginx 1.24`.
    ///
    /// A missing part is simply absent rather than a placeholder. `http nginx` and
    /// `http` are both complete answers to "what is this"; padding them out to three
    /// fields would invent a precision the evidence did not carry, which is the mistake
    /// `ServiceEvidence` exists to make unrepresentable one level down.
    ///
    /// `banner` and `tlsSubject` are deliberately excluded. They are the EVIDENCE for
    /// this identification rather than the identification itself, they are already in
    /// the artifact for a reader who disagrees with our parse, and a raw `Server:`
    /// header is a string of arbitrary length carrying what the parse already extracted.
    ///
    /// **Here and not in `ZhenCore`, because the app has the same value and
    /// deliberately does not join it.** The app's presentation layer puts `name` in one
    /// field, `product` in a second and drops `version`, laying them out as two lines of
    /// a card rather than one string. `Device.displayName` and `displayModel` do live in
    /// core, and the difference is the line worth holding: those are SELECTIONS — which
    /// name candidate wins — a question about the data. This is FORMATTING for one
    /// column of one table, and a helper in core would be a table-column decision made
    /// in a module that has no table.
    var displayText: String {
        // `name` is non-optional, but nothing in the type stops it being empty, and
        // `[name, product, version]` infers as `[String?]` so `compactMap` only removes
        // the nils. The filter is what removes an empty name.
        [name, product, version]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }
}
