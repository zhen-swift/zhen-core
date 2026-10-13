// ReportCoding.swift — one canonical encoder, so two runs of the same scan diff.
//
// Every consumer serializing a ScanReport with its own JSONEncoder would produce
// documents that differ in ways that have nothing to do with the scan: key order is
// unspecified, and Foundation escapes forward slashes by default, so a CIDR comes out
// as "10.10.20.0\/24" — valid JSON, unreadable, and unpleasant to grep.
//
// Both matter more here than they would elsewhere. This project's claim is speed, and
// the way a speed claim is checked is by diffing two artifacts; a diff full of
// reordered keys is not a diff. `--json` output that a user is expected to read with
// their eyes should not have backslashes in the addresses.
//
// So core supplies the encoder rather than documenting a convention and hoping.

// Foundation is used here for exactly two things: UUID, and the single wall-clock
// reading behind `Timestamp.now`. Both are available in swift-corelibs-foundation, so
// this import does not compromise the Linux requirement — and it is a plain import
// rather than a conditional, which keeps `grep -r "#if" Sources/` returning nothing.
import Foundation

extension ScanReport {
    /// The encoder every consumer should use.
    ///
    /// - `.sortedKeys` makes output deterministic, so two runs that found the same
    ///   thing produce byte-identical documents and a real change stands out.
    /// - `.withoutEscapingSlashes` keeps `10.10.20.0/24` readable. Foundation escapes
    ///   `/` by default — a legacy of embedding JSON in HTML `<script>` tags, which is
    ///   not what is happening here.
    /// - `.prettyPrinted` is deliberately NOT set: the default artifact is one
    ///   document for a machine, and NDJSON requires one line per record. A human
    ///   reading it has `jq`.
    public static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    /// The matching decoder. Trivially configured today, and named so that a future
    /// decoding decision has one place to land.
    public static func makeDecoder() -> JSONDecoder {
        JSONDecoder()
    }

    /// Encodes this report canonically.
    public func encoded() throws -> Data {
        try Self.makeEncoder().encode(self)
    }

    /// Decodes a report and checks its schema before returning it.
    ///
    /// Decoding alone is not enough. A document from a newer build overlaps enough to
    /// decode while meaning something different, so the version check is the guard and
    /// it belongs on the path everybody takes rather than in a doc comment everybody
    /// skips.
    public static func decoded(from data: Data) throws -> ScanReport {
        let report = try makeDecoder().decode(ScanReport.self, from: data)
        try report.validateSchema()
        return report
    }
}
