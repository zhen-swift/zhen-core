// MACSighting.swift — one hardware address a device has presented, and when.
//
// ── Why this is history, and not a field on `Device` ────────────────────────────────
//
// `Device` carries the last thing observed about a device, which is why it has no
// liveness flag: presence is a fact about a run, kept beside the record rather than in
// it. The hardware addresses a device USED to present are the same kind of fact — history,
// not observation — so they live with history, on the ledger's record, by the same
// argument. A `Device` decoded from a scan artifact has one MAC because one was seen.
//
// ── Why it exists at all ────────────────────────────────────────────────────────────
//
// A device with private Wi-Fi addressing rotates its MAC. The ledger has always followed
// it across the rotation — a Bonjour name or a DHCP hostname is the bridge — and kept only
// the newest address, so "this phone has been three hardware addresses since March" was
// known for a moment at each fold and then thrown away. The app's identity card wanted
// exactly that sentence: one row per MAC, a date range, and why it joined.

import Foundation

/// One hardware address a device has presented, and the span it was seen over.
public struct MACSighting: Sendable, Hashable {
    /// How an address came to belong to the record.
    public enum Link: Sendable, Hashable {
        /// The address the record began with, or the earliest the ledger can know about.
        case original
        /// A new address on an observation that matched the record by another
        /// identifier — a rotation, recognised by what did not rotate.
        case rotation(by: HostIdentifierKind)
        /// An address from a record that reconciliation joined into this one, and the
        /// kind of identifier the two shared.
        case merge(by: HostIdentifierKind)
    }

    /// The address.
    public var mac: MACAddress
    /// The first time the ledger saw this record present it.
    public var firstSeen: Timestamp
    /// The most recent time it did.
    public var lastSeen: Timestamp
    /// How it joined the record.
    public var link: Link

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(mac: MACAddress, firstSeen: Timestamp, lastSeen: Timestamp, link: Link) {
        self.mac = mac
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.link = link
    }
}
