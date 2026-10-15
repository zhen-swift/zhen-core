// DiscoverySource.swift — how a host came to be reported, beside the fact that it was.
//
// ── Why this type exists ───────────────────────────────────────────────────────
//
// A discovery engine reports a list of hosts. Until this type, that list was flat: a
// host that answered an echo request and a host the kernel merely remembered were the
// same shape in the artifact, and nothing a reader could inspect told them apart.
//
// That cost a measurement study a real day. Comparing `hosts_found` against the echo
// replies in a packet capture showed a disagreement in 431 of 485 runs, and there was
// no way to settle from the artifact whether the scanner was inventing hosts, the
// capture was missing frames, or the neighbour table was legitimately contributing
// hosts that never answered. It turned out to be the third, plus two counting
// mistakes — but establishing that took the raw pcaps, because the artifact could not
// answer it.
//
// An engine that says "I found eleven hosts" and cannot say how it found any of them
// is asking to be trusted. The whole point of carrying evidence beside a verdict is
// that a reader does not have to.
//
// ── Why a set rather than one value ────────────────────────────────────────────
//
// These are not alternatives. A host can answer an ICMP echo *and* sit in the
// neighbour table *and* answer an ARP request, and when the composite engine unions a
// privileged and an unprivileged run, that is exactly what happens. Recording only the
// strongest would throw away the agreement between two independent engines, which is
// the most informative thing the composition produces.

/// How a host came to be in a discovery result.
///
/// Every case is a distinct kind of evidence, and the difference between them is the
/// difference between "this host spoke to us" and "the kernel says it exists".
public enum DiscoverySource: String, Sendable, Hashable, Codable, CaseIterable, Comparable {
    /// It answered a probe this scan sent — an ICMP echo request.
    ///
    /// The strongest evidence available without privileges: the host was reachable and
    /// responsive during the scan window.
    case probeReply = "probe_reply"

    /// It answered an ARP request this scan put on the wire itself.
    ///
    /// Layer 2, so it cannot be firewalled the way ICMP can. Needs a capture device.
    case arpReply = "arp_reply"

    /// Its neighbour entry went from absent or incomplete to complete WHILE this scan
    /// was running, and it never answered a probe.
    ///
    /// Evidence from this run, not memory. Unprivileged, the wire is gated by kernel ARP:
    /// a transmission to an address with no complete entry is an ARP trigger, not an
    /// echo, and a host that answers that ARP and then ignores the echo — or answers the
    /// echo too late — has still put a reply on the wire during this scan. Study 1 called
    /// that `neighbor_table` and could not tell it from an entry inherited from an hour
    /// ago; this is the half that was observed now.
    ///
    /// Added in 0.8.0 (schema 4). Under `--no-neighbor-watch` the sweep does not look,
    /// and every table-only host is `neighbor_table` as it was in study 1.
    case neighborResolved = "neighbor_resolved"

    /// The kernel's neighbour table listed it before the scan started, and it never
    /// answered a probe.
    ///
    /// **Inherited, since 0.8.0.** Through 0.7.0 this also covered an entry the scan's
    /// own probes caused to resolve; that is `neighborResolved` now, and this means only
    /// what the kernel already knew.
    ///
    /// Real evidence and weaker evidence, and the distinction matters in both
    /// directions. A host that ignores ICMP is genuinely present and genuinely found
    /// this way — dropping it would report the network as emptier than it is. But a
    /// neighbour entry can also outlive the host that created it, so a reader
    /// reconciling against a packet capture will find nothing on the wire for this one
    /// and should not conclude the scanner lied.
    case neighborTable = "neighbor_table"

    /// This machine's own address on the scanned segment.
    ///
    /// **It will not appear in a packet capture, and that is not a fault in the
    /// capture.** A probe a host sends to its own address is answered inside the
    /// kernel and never reaches the wire, so `tcpdump` on the interface sees neither
    /// the request nor the reply. Verified: three pings to this machine's own address,
    /// three replies received, zero frames captured on the interface.
    ///
    /// The address is reported because it is a real host on the segment. It is marked
    /// because anyone checking the artifact against a capture would otherwise be
    /// hunting a phantom that is really just the scanner looking at itself.
    case localInterface = "local_interface"

    /// Ordered strongest evidence first, which is also the order they encode in.
    ///
    /// A stable order keeps the artifact byte-comparable across runs, the same reason
    /// `allNames` and `ports` are sorted.
    public static func < (lhs: DiscoverySource, rhs: DiscoverySource) -> Bool {
        let rank: (DiscoverySource) -> Int = {
            switch $0 {
            case .probeReply: 0
            case .arpReply: 1
            case .neighborResolved: 2
            case .neighborTable: 3
            case .localInterface: 4
            }
        }
        return rank(lhs) < rank(rhs)
    }

    /// What to show a person, rather than the wire spelling.
    public var label: String {
        switch self {
        case .probeReply: "answered a probe"
        case .arpReply: "answered ARP"
        case .neighborResolved: "resolved during the scan"
        case .neighborTable: "neighbour table"
        case .localInterface: "this machine"
        }
    }
}

extension Set where Element == DiscoverySource {
    /// Encoded form: strongest first, stable across runs.
    public var canonical: [DiscoverySource] { sorted() }

    /// Whether anything here is a host that actually spoke during this scan.
    ///
    /// The predicate a reader reconciling against a packet capture wants: these are the
    /// hosts whose frames should be on the wire, and the rest are the hosts whose
    /// absence from it explains itself. A neighbour entry that resolved during the scan
    /// is one of them: the kernel's ARP request and the host's reply are both frames.
    public var answeredThisScan: Bool {
        contains(.probeReply) || contains(.arpReply) || contains(.neighborResolved)
    }
}
