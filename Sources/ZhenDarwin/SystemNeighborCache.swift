// SystemNeighborCache.swift — which neighbour table this Apple platform has.
//
// One place decides it, so a default argument and the composition root cannot disagree.
// macOS reads the ARP cache over the routing socket. iPadOS has no `<net/route.h>` in its
// SDK and does not hand a sandboxed app the table, so there it is
// `UnavailableNeighborCache`, which discovery neither reads nor claims.
#if canImport(Darwin)

import ZhenCore

/// The neighbour cache of the platform this was built for.
public enum SystemNeighborCache {
    /// `DarwinNeighborCache` on macOS, `UnavailableNeighborCache` on iPadOS.
    public static var current: any NeighborCache {
        #if os(macOS)
        DarwinNeighborCache()
        #else
        UnavailableNeighborCache(
            reason: "iPadOS does not let an app read the system's neighbour table."
        )
        #endif
    }
}

#endif
