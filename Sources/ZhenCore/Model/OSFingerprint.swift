// OSFingerprint.swift — what a stack's own TCP behaviour says about it.
//
// ── This is not `OSHint`, and the difference is the whole point ─────────────────
//
// `OSHint` reads one field. A TTL of 64 means Linux, macOS, iOS, Android or most
// embedded stacks, and that is genuinely useful and genuinely weak — it separates three
// broad families and nothing finer. It ships, it is honestly named, and it is derived
// from a packet we were sending anyway.
//
// This is stack fingerprinting: a SYN carrying a full option block, and the SYN-ACK's
// window, its options, the order the peer put them in, its window scale and whether it
// echoed timestamps. Those together separate stacks that share a TTL, which is what a
// hint cannot do.
//
// ── Why the evidence travels with the verdict ──────────────────────────────────
//
// A fingerprint is a *match against a table*, and a table is a claim about the world
// that ages. A signature written today against Linux 6.x is wrong about Linux 9.x, and
// a scanner that reported only `"linux"` would give its user no way to find that out.
//
// So `TCPStackFeatures` is carried alongside the match, always, matched or not. A
// reader who disagrees can see the window, the options and their order and judge for
// themselves; an unmatched host reports its features with no name attached, which is a
// useful observation rather than a gap; and a future signature can be checked against
// archived reports instead of needing the network back.
//
// `Study/THEORY.md` ranks this below fused identity for good reason: on a consumer LAN,
// `AppleTV5,3` out of a Bonjour TXT record beats any fingerprint guess. This is
// supplementary evidence for `Identification` and never the basis of a claim on its own.

/// How sure a fingerprint match is.
public enum FingerprintConfidence: String, Sendable, Hashable, CaseIterable, Codable {
    /// Every field in the signature matched, including the option order.
    case exact = "exact"
    /// The distinguishing fields matched and something minor did not — a window size
    /// a tuned host has changed, or padding a middlebox rewrote.
    case probable = "probable"
    /// Features were observed and no signature claims them.
    case unmatched = "unmatched"
}

/// The TCP and IP behaviour observed from one SYN-ACK.
///
/// Every field here is read off the wire. Nothing is inferred except `initialTTL`,
/// which is documented where it is computed.
public struct TCPStackFeatures: Sendable, Hashable, Codable {
    /// The TTL the packet arrived with, already decremented by every hop it crossed.
    public var observedTTL: UInt8
    /// The TTL the sender most likely started from: the next power-of-two-ish boundary
    /// at or above what arrived. On a local segment nothing decrements it, so the two
    /// are usually equal; this is what makes the field comparable across topologies.
    public var initialTTL: UInt8
    /// Whether Don't Fragment was set.
    public var dontFragment: Bool
    /// The advertised receive window, before scaling.
    public var window: UInt16
    /// The maximum segment size the peer announced, where it announced one.
    public var maximumSegmentSize: UInt16?
    /// The window scale shift the peer asked for, where it asked.
    public var windowScale: UInt8?
    /// Whether the peer permitted selective acknowledgement.
    public var sackPermitted: Bool
    /// Whether the peer echoed TCP timestamps.
    public var timestamps: Bool
    /// The option kinds in the order the peer placed them — "2-4-8-1-3" for the usual
    /// Linux ordering. The order separates stacks that offer identical option sets,
    /// which several do.
    public var optionOrder: String

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        observedTTL: UInt8,
        initialTTL: UInt8,
        dontFragment: Bool,
        window: UInt16,
        maximumSegmentSize: UInt16? = nil,
        windowScale: UInt8? = nil,
        sackPermitted: Bool = false,
        timestamps: Bool = false,
        optionOrder: String = ""
    ) {
        self.observedTTL = observedTTL
        self.initialTTL = initialTTL
        self.dontFragment = dontFragment
        self.window = window
        self.maximumSegmentSize = maximumSegmentSize
        self.windowScale = windowScale
        self.sackPermitted = sackPermitted
        self.timestamps = timestamps
        self.optionOrder = optionOrder
    }

    /// The initial TTL a sender most plausibly used.
    ///
    /// Stacks start at 64, 128 or 255 and every hop decrements by one. Rounding up to
    /// the next of those three recovers the origin for anything within a sane hop count
    /// and is exactly what `OSHint` does with its bands — the difference is that this
    /// keeps the raw value too, so a reader can see how far away the host was.
    public static func inferInitialTTL(from observed: UInt8) -> UInt8 {
        switch observed {
        case 0...64: 64
        case 65...128: 128
        default: 255
        }
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case observedTTL = "observed_ttl"
        case initialTTL = "initial_ttl"
        case dontFragment = "dont_fragment"
        case window
        case maximumSegmentSize = "mss"
        case windowScale = "window_scale"
        case sackPermitted = "sack_permitted"
        case timestamps
        case optionOrder = "option_order"
    }
}

/// A stack fingerprint: what was observed, and what it looks like.
public struct OSFingerprint: Sendable, Hashable, Codable {
    /// The signature's name, where one matched — "Linux", "macOS or iOS", "Windows".
    ///
    /// Deliberately a family rather than a version. The features below separate stack
    /// lineages reliably and versions within a lineage barely at all, and a scanner
    /// that printed "Linux 6.5" off a window size would be inventing precision.
    public var family: String?
    /// How sure the match is.
    public var confidence: FingerprintConfidence
    /// What was actually seen. Present whether or not anything matched.
    public var features: TCPStackFeatures

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(family: String?, confidence: FingerprintConfidence, features: TCPStackFeatures) {
        self.family = family
        self.confidence = confidence
        self.features = features
    }

    /// Wire keys, spelled out.
    public enum CodingKeys: String, CodingKey {
        case family
        case confidence
        case features
    }
}

/// One entry in the signature table.
public struct StackSignature: Sendable, Hashable {
    /// What to call a host that matches.
    public var family: String
    /// The initial TTL this stack starts from.
    public var initialTTL: UInt8
    /// Acceptable window values. Empty means the window does not distinguish this one.
    public var windows: Set<UInt16>
    /// The window scale, where the stack always uses the same one.
    public var windowScale: UInt8?
    /// Whether it permits SACK.
    public var sackPermitted: Bool
    /// Whether it echoes timestamps.
    public var timestamps: Bool
    /// The option order it emits, where that is stable.
    public var optionOrder: String?

    /// Creates a signature.
    public init(
        family: String, initialTTL: UInt8, windows: Set<UInt16> = [],
        windowScale: UInt8? = nil, sackPermitted: Bool, timestamps: Bool,
        optionOrder: String? = nil
    ) {
        self.family = family
        self.initialTTL = initialTTL
        self.windows = windows
        self.windowScale = windowScale
        self.sackPermitted = sackPermitted
        self.timestamps = timestamps
        self.optionOrder = optionOrder
    }
}

/// The signature table, and the matcher over it.
///
/// **Small and honest about being small.** This is not nmap's database of thousands of
/// signatures gathered over twenty years; it is a handful of stack lineages that a home
/// network actually contains, each written from what the lineage does rather than from
/// one observed host. A host that matches none of them reports its features unmatched,
/// which is the correct outcome and the one that makes the table extensible: the
/// evidence is in the artifact, so a new signature can be written against reports
/// already collected.
public enum StackSignatures {
    /// The table, in the order it is searched.
    ///
    /// Each entry is a lineage, not a release. Option order is the strongest single
    /// discriminator and window is the weakest — a host with a tuned `tcp_rmem` moves
    /// its window and changes nothing else — which is why a window mismatch alone
    /// downgrades a match to `.probable` rather than rejecting it.
    public static let table: [StackSignature] = [
        // Linux: MSS, SACK, timestamps, NOP, window scale.
        //
        // The option ORDER is the signature. The window scale is not: measured against
        // 10.10.20.0/24 it was 6 on a TP-Link router and 5 on a camera, both plainly
        // Linux by their option order, because the scale follows the receive buffer and
        // therefore the device's memory rather than its lineage.
        StackSignature(
            family: "Linux", initialTTL: 64, windows: [64240, 65160, 29200, 28960, 5840],
            windowScale: 7, sackPermitted: true, timestamps: true, optionOrder: "2-4-8-1-3"
        ),
        // Darwin — macOS, iOS, iPadOS, tvOS. MSS, NOP, window scale, NOP, NOP,
        // timestamps, SACK. The doubled NOP padding before the timestamps is the
        // distinctive part and it is stable across the family; the scale, again, is not
        // — an Apple TV on this network answers with 5 where a Mac answers with 6.
        StackSignature(
            family: "macOS or iOS", initialTTL: 64, windows: [65535],
            windowScale: 6, sackPermitted: true, timestamps: true, optionOrder: "2-1-3-1-1-8-4"
        ),
        // Windows 10 and later: MSS, NOP, window scale, NOP, NOP, SACK. No timestamps,
        // which is the field that separates it from Darwin at a glance.
        StackSignature(
            family: "Windows", initialTTL: 128, windows: [64240, 8192, 65535],
            windowScale: 8, sackPermitted: true, timestamps: false, optionOrder: "2-1-3-1-1-4"
        ),
        // Embedded and appliance stacks — routers, cameras, printers. TTL 64 with no
        // window scaling and no timestamps is the shape of a small stack, and this
        // entry deliberately does not name a vendor it cannot see.
        StackSignature(
            family: "embedded", initialTTL: 64, windows: [],
            windowScale: nil, sackPermitted: false, timestamps: false, optionOrder: nil
        ),
        // Network gear that starts at 255. Rare on a consumer segment and unambiguous
        // when it appears.
        StackSignature(
            family: "network device", initialTTL: 255, windows: [],
            windowScale: nil, sackPermitted: false, timestamps: false, optionOrder: nil
        ),
    ]

    /// Matches observed features against the table.
    ///
    /// The distinguishing fields are the initial TTL, whether timestamps and SACK were
    /// echoed, and the option order. A disagreement in any of those rejects the
    /// signature outright, because each is a property of the stack's source.
    ///
    /// **The window and the window scale only downgrade**, and the second of those was
    /// a correction the network forced. Both were hard gates first, and every host on
    /// the development segment came back `unmatched`: a TP-Link router and a camera
    /// emitting Linux's exact option order at window scales 6 and 5, and an Apple
    /// device emitting Darwin's exact order at 5 rather than 6. The scale follows the
    /// receive buffer, so it tracks how much memory a device has rather than what it
    /// runs — and rejecting on it meant the table matched nothing real.
    ///
    /// A host that agrees on every structural field and differs on a size is a tuned or
    /// a small host, not a different operating system, and `.probable` is what says so.
    public static func match(_ features: TCPStackFeatures) -> OSFingerprint {
        for signature in table {
            guard signature.initialTTL == features.initialTTL else { continue }
            guard signature.timestamps == features.timestamps else { continue }
            guard signature.sackPermitted == features.sackPermitted else { continue }
            if let order = signature.optionOrder, order != features.optionOrder { continue }

            let windowAgrees = signature.windows.isEmpty
                || signature.windows.contains(features.window)
            let scaleAgrees = signature.windowScale == nil
                || signature.windowScale == features.windowScale
            return OSFingerprint(
                family: signature.family,
                confidence: windowAgrees && scaleAgrees ? .exact : .probable,
                features: features
            )
        }
        return OSFingerprint(family: nil, confidence: .unmatched, features: features)
    }
}
