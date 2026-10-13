// HistoryRendering.swift — one place that decides how history looks.
//
// The scan renderers exist so the human table and the JSON document are two views of
// one `ScanReport` rather than two opinions about it. Same rule here, for the same
// reason: three commands reading the same store must not each invent their own idea of
// what a stored device looks like, or `hosts --json` and `export` will disagree about a
// device and nobody will notice, because nobody diffs them.

import Foundation
import ZhenCore

nonisolated enum HistoryRendering {
    // ── Matching ────────────────────────────────────────────────────────────────

    /// Whether a query names this device.
    ///
    /// Address, MAC or a case-insensitive fragment of the name. Deliberately permissive
    /// on the way in and strict about ambiguity on the way out: the caller reports a
    /// query matching several devices rather than picking one, so being generous here
    /// costs a clear error rather than a wrong answer.
    static func matches(_ device: Device, query: String) -> Bool {
        let needle = query.lowercased()
        if device.addresses.contains(where: { $0.description == query }) { return true }
        if let mac = device.mac, mac.description.lowercased() == needle { return true }
        if let name = device.displayName, name.lowercased().contains(needle) { return true }
        return false
    }

    /// Whether an event is about this device.
    ///
    /// Events carry a subject and an address in their prose rather than a device id, so
    /// this matches on those. **Two known limits, both of them under-matching**, which is
    /// the direction to err: an event that is not shown is a gap, and an event belonging
    /// to another device is a lie.
    ///
    /// A device whose address changed has older events naming the address it used to
    /// have, and those are not found. And an unnamed device's events are found only by
    /// address, because "Unidentified device" is the subject of every unnamed device's
    /// events — matching on it was the first version of this function and it showed the
    /// whole network's history under whichever unnamed device was asked about, which on
    /// a discovery-only scan is all of them.
    ///
    /// The real fix is a device identifier on `DerivedEvent`. That is a change to a core
    /// type and to both stores, and it is worth doing rather than worth doing quietly in
    /// passing.
    static func event(_ event: DerivedEvent, concerns device: Device) -> Bool {
        if let name = device.displayName, event.subject == name { return true }
        return device.addresses.contains { event.detail.contains($0.description) }
    }

    // ── Tables ──────────────────────────────────────────────────────────────────

    static func table(devices: [StoredDevice]) -> String {
        guard !devices.isEmpty else {
            return "No devices in history yet. Run a scan first.\n"
        }
        let rows = devices.map { stored -> [String] in
            [
                stored.isPresent ? "●" : "○",
                stored.device.primaryAddress.description,
                stored.device.displayName ?? "Unidentified device",
                stored.device.mac?.description ?? "—",
                relative(stored.device.lastSeen),
            ]
        }
        return render(
            headers: ["", "ADDRESS", "NAME", "MAC", "LAST SEEN"],
            rows: rows,
            footer: summary(devices)
        )
    }

    static func table(events: [DerivedEvent], filtered: Bool = false) -> String {
        guard !events.isEmpty else {
            return filtered
                ? "No events in that window.\n"
                : "No events yet. Events are differences between runs, "
                    + "so the first scan makes none.\n"
        }
        let rows = events.map { [relative($0.at), $0.kind.rawValue, $0.subject, $0.detail] }
        return render(headers: ["WHEN", "WHAT", "DEVICE", ""], rows: rows, footer: nil)
    }

    static func detail(device stored: StoredDevice, events: [DerivedEvent]) -> String {
        var out = ""
        let device = stored.device
        out += "\(device.displayName ?? "Unidentified device")\n"
        if device.addresses.count == 1 {
            out += "  address     \(device.primaryAddress)\n"
        } else {
            out += "  addresses   \(device.addresses.sorted().map(\.description).joined(separator: ", "))\n"
        }
        out += "  mac         \(device.mac?.description ?? "—")\n"
        out += "  first seen  \(absolute(device.firstSeen))\n"
        out += "  last seen   \(absolute(device.lastSeen)) (\(relative(device.lastSeen)))\n"
        out += "  present     \(stored.isPresent ? "yes, in the most recent scan" : "no")\n"
        if events.isEmpty {
            out += "\nNothing has happened to it since it was first seen.\n"
        } else {
            out += "\n"
            out += render(
                headers: ["WHEN", "WHAT", ""],
                rows: events.map { [relative($0.at), $0.kind.rawValue, $0.detail] },
                footer: nil
            )
        }
        return out
    }

    // ── JSON ────────────────────────────────────────────────────────────────────

    static func json(devices: [StoredDevice]) -> String {
        encode(["devices": devices.map(payload(for:))])
    }

    static func json(events: [DerivedEvent]) -> String {
        encode(["events": events.map(payload(for:))])
    }

    static func json(device: StoredDevice, events: [DerivedEvent]) -> String {
        encode(["device": payload(for: device), "events": events.map(payload(for:))])
    }

    static func json(
        devices: [StoredDevice], events: [DerivedEvent], latestRun: ScanRun?
    ) -> String {
        var root: [String: Any] = [
            "devices": devices.map(payload(for:)),
            "events": events.map(payload(for:)),
        ]
        if let latestRun, let encoded = try? JSONEncoder().encode(latestRun),
           let object = try? JSONSerialization.jsonObject(with: encoded) {
            root["latest_run"] = object
        }
        return encode(root)
    }

    /// The stored device, as JSON.
    ///
    /// `Device` is `Codable` against the artifact's format, so it is re-encoded through
    /// that rather than described again here — the same reason the stores carry it
    /// rather than mirroring it. `present` is added alongside because presence is a fact
    /// about a run and deliberately not a field on the device.
    private static func payload(for stored: StoredDevice) -> [String: Any] {
        var object: [String: Any] = [:]
        if let encoded = try? JSONEncoder().encode(stored.device),
           let decoded = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any] {
            object = decoded
        }
        object["present"] = stored.isPresent
        return object
    }

    private static func payload(for event: DerivedEvent) -> [String: Any] {
        [
            "id": event.id.uuidString,
            "at_millis": event.at.millisecondsSinceEpoch,
            "kind": event.kind.rawValue,
            "subject": event.subject,
            "detail": event.detail,
            "run_id": event.runID.uuidString,
        ]
    }

    private static func encode(_ root: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: root, options: [.sortedKeys, .withoutEscapingSlashes]
        ), let text = String(data: data, encoding: .utf8) else { return "{}\n" }
        return text + "\n"
    }

    // ── Shared bits ─────────────────────────────────────────────────────────────

    private static func summary(_ devices: [StoredDevice]) -> String {
        let present = devices.filter(\.isPresent).count
        let absent = devices.count - present
        if absent == 0 { return "\(devices.count) devices, all present in the last scan" }
        return "\(devices.count) devices — \(present) present, \(absent) not seen in the last scan"
    }

    private static func render(headers: [String], rows: [[String]], footer: String?) -> String {
        let widths = (0..<headers.count).map { column in
            max(headers[column].count, rows.map { $0[column].count }.max() ?? 0)
        }
        func line(_ cells: [String]) -> String {
            cells.enumerated()
                .map { index, cell in
                    index == cells.count - 1 ? cell : cell.padding(
                        toLength: widths[index], withPad: " ", startingAt: 0
                    )
                }
                .joined(separator: "  ")
                .trimmedTrailingSpaces()
        }
        var out = line(headers) + "\n"
        for row in rows { out += line(row) + "\n" }
        if let footer { out += "\n" + footer + "\n" }
        return out
    }

    private static func absolute(_ timestamp: Timestamp) -> String {
        let date = Date(timeIntervalSince1970: Double(timestamp.millisecondsSinceEpoch) / 1000)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    /// Coarse on purpose. "3 hours ago" is what a person wants from a history listing,
    /// and a precise interval would invite reading a scan's timing out of it, which is
    /// what the artifact is for.
    private static func relative(_ timestamp: Timestamp) -> String {
        let elapsed = Timestamp.now.millisecondsSinceEpoch - timestamp.millisecondsSinceEpoch
        let seconds = elapsed / 1000
        switch seconds {
        case ..<0: return "just now"
        case 0..<60: return "\(seconds)s ago"
        case 60..<3_600: return "\(seconds / 60)m ago"
        case 3_600..<86_400: return "\(seconds / 3_600)h ago"
        default: return "\(seconds / 86_400)d ago"
        }
    }
}

private nonisolated extension String {
    /// Trailing only. Trimming both ends ate the leading pad of the status column's
    /// empty header cell, which shifted every heading one place left of the data it
    /// named — right up until a row happened to start with a wide glyph.
    func trimmedTrailingSpaces() -> String {
        var text = self
        while text.hasSuffix(" ") { text.removeLast() }
        return text
    }
}
