// AddressSources.swift — one entry of a device's `address_sources`: an address, and how
// this run found it.

/// How one of a device's addresses was found, in `Device.addressSources` on the wire.
///
/// A device's `discovered_via` is the union over all its addresses, which is what it has
/// always meant. On a dual-stack device that union can say `neighbor_resolved` and
/// `neighbor_table` at once, each true of a different address (questions, Q11). This
/// says which is which, so an analysis can tell a device kept present by an inherited
/// IPv6 neighbour entry alone from one whose v4 address answered.
public struct AddressSources: Sendable, Hashable, Codable {
    /// The address.
    public var address: IPAddress
    /// How it was found, strongest evidence first.
    public var discoveredVia: [DiscoverySource]

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(address: IPAddress, discoveredVia: [DiscoverySource]) {
        self.address = address
        self.discoveredVia = discoveredVia
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case address
        case discoveredVia = "discovered_via"
    }
}
