// NeighborTable.swift — free layer-2 truth from the kernel's ARP cache.
//
// The cache holds the MAC of everything this machine has recently exchanged a packet
// with. It costs no probe, needs no privilege, and — the part that matters most — it
// is readable even when the Local Network permission has been denied. That asymmetry
// is the control in the denial heuristic: probes hearing nothing while the cache is
// populated is the signature of a grant we cannot query.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Reads the kernel's ARP cache over the routing socket.
public struct DarwinNeighborCache: NeighborCache {
    /// Creates the reader.
    public init() {}

    /// Every IPv4 neighbour entry the kernel currently holds.
    ///
    /// Incomplete entries — an ARP request that got no answer — are kept and marked,
    /// because they are evidence of *absence* and a caller that treated them as devices
    /// would invent hosts that are not there.
    public func entries() async throws(PlatformError) -> [NeighborEntry] {
        let bytes = try RouteSysctl.fetch(
            [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
        )
        // SAFETY: borrowing a raw view over a buffer this call owns; the span cannot
        // outlive it.
        return unsafe Self.decode(bytes.span.bytes)
    }

    /// Decodes a captured `NET_RT_FLAGS` buffer.
    ///
    /// Separated from the syscall so it can be tested against committed fixtures — the
    /// parser is the part with the alignment hazard, and it should not need a live
    /// network to exercise.
    public static func decode(_ bytes: RawSpan) -> [NeighborEntry] {
        var seen: Set<IPv4Address> = []
        var entries: [NeighborEntry] = []
        for message in RouteMessageParser.parse(bytes) {
            guard let ip = message.destination else { continue }
            // The table is not a list of devices. It also holds the subnet broadcast
            // (an entry for x.x.x.255 against ff:ff:ff:ff:ff:ff) and every multicast
            // group the machine has joined (224.0.0.251 against 01:00:5e:00:00:fb for
            // mDNS). Both are link-layer plumbing, and a scanner that reported them
            // would invent two devices on every network it ever looked at — which is
            // exactly what the captured fixture for this parser contains, and how the
            // omission was caught.
            guard !ip.isMulticast else { continue }
            guard let mac = message.linkAddress else {
                // No link-layer address means an incomplete entry. Recorded so the
                // denial heuristic and the caller can tell "asked and got nothing"
                // apart from "never asked".
                if seen.insert(ip).inserted {
                    entries.append(NeighborEntry(ip: ip, mac: MACAddress(raw: 0),
                                                 isComplete: false, isPermanent: false))
                }
                continue
            }
            guard !mac.isMulticast else { continue }
            guard seen.insert(ip).inserted else { continue }
            entries.append(NeighborEntry(
                ip: ip,
                mac: mac,
                isComplete: true,
                // A static entry the administrator added, rather than one learned from
                // traffic. RTF_STATIC survives cache expiry, so it is weaker evidence
                // that the host is here *now*.
                isPermanent: message.flags & RTF_STATIC != 0
            ))
        }
        return entries.sorted { $0.ip < $1.ip }
    }
}


// ── IPv6: the NDP neighbour cache ──────────────────────────────────────────────────
//
// The same sysctl with AF_INET6 — the table `ndp -an` prints, readable without privilege
// for the same reason the ARP one is.
extension DarwinNeighborCache: IPv6NeighborCache {
    public func ipv6Entries() async throws(PlatformError) -> [IPv6NeighborEntry] {
        let bytes = try RouteSysctl.fetch(
            [CTL_NET, PF_ROUTE, 0, AF_INET6, NET_RT_FLAGS, RTF_LLINFO]
        )
        return unsafe Self.decodeIPv6(bytes.span.bytes) { ICMPv6Socket.interfaceName(UInt32($0)) }
    }

    /// Decodes an AF_INET6 neighbour dump. `interfaceName` turns the message's interface
    /// index into the zone every address carries — a link-local address without one is
    /// ambiguous on a machine with more than one link.
    ///
    /// Kept: complete entries (a MAC is present) for unicast addresses. Dropped: the
    /// incomplete ones, which say a solicitation went unanswered, and multicast. The
    /// permanent ones — this machine's own addresses — are kept and marked, and the caller
    /// decides; reporting this machine as its own neighbour is the caller's mistake to
    /// avoid, not the parser's to hide.
    public static func decodeIPv6(
        _ bytes: RawSpan, interfaceName: (UInt16) -> String?
    ) -> [IPv6NeighborEntry] {
        var seen: Set<IPv6Address> = []
        var entries: [IPv6NeighborEntry] = []
        for message in RouteMessageParser.parse(bytes) {
            guard let bare = message.destination6, !bare.isMulticast,
                  let mac = message.linkAddress, !mac.isMulticast, mac.raw != 0
            else { continue }
            let address = IPv6Address(high: bare.high, low: bare.low,
                                      zone: interfaceName(message.interfaceIndex))
            guard seen.insert(address).inserted else { continue }
            entries.append(IPv6NeighborEntry(
                address: address, mac: mac,
                isPermanent: message.flags & RTF_STATIC != 0
            ))
        }
        return entries.sorted { $0.address < $1.address }
    }
}
#endif
