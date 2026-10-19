// Interfaces.swift — which interface a scan goes out of, and what network it sees.
//
// `getifaddrs` for the addresses, and the routing table for which one is the default.
// The second half matters more than it looks: picking "the first non-loopback interface
// that is up" gets the wrong answer on a machine with a VPN, a container bridge, a
// Thunderbolt link and a phone tethered over USB — all of which are up, all of which
// have addresses, and only one of which reaches the network the user means. Asking the
// kernel which way the default route points is the only answer that is actually right.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Enumerates this machine's IPv4 interfaces via `getifaddrs`.
public struct DarwinInterfaceProvider: InterfaceProvider {
    /// Creates the provider.
    public init() {}

    /// Every IPv4 interface that is up, running and not loopback.
    ///
    /// Point-to-point interfaces are kept — a tethered phone is a legitimate scan
    /// target — but they carry no useful netmask, so they end up as a /32 and a caller
    /// that wants a real sweep has to name a CIDR.
    public func interfaces() throws(PlatformError) -> [NetworkInterface] {
        var head: UnsafeMutablePointer<ifaddrs>?  // freed by the defer below
        // SAFETY: getifaddrs allocates a linked list we own and free below. The
        // `defer` runs on every path out, including a thrown error.
        guard unsafe getifaddrs(&head) == 0, let head = unsafe head else {
            throw PlatformError.syscall("getifaddrs")
        }
        defer { unsafe freeifaddrs(head) }

        // Hardware addresses arrive on a separate AF_LINK entry for the same interface
        // name, so the list is walked once to collect those and once to build results.
        var hardware: [String: MACAddress] = [:]
        var addresses: [(name: String, ip: IPv4Address, mask: UInt32, flags: UInt32)] = []

        var cursor: UnsafeMutablePointer<ifaddrs>? = unsafe head
        while let entry = unsafe cursor {
            // SAFETY: dereferencing a node of the list getifaddrs just built, which
            // stays valid until freeifaddrs.
            let node = unsafe entry.pointee
            unsafe cursor = node.ifa_next
            guard let namePointer = unsafe node.ifa_name else { continue }
            let name = unsafe String(cString: namePointer)
            guard let addressPointer = unsafe node.ifa_addr else { continue }
            let family = unsafe Int32(addressPointer.pointee.sa_family)

            if family == AF_LINK {
                if let mac = unsafe Self.hardwareAddress(addressPointer) {
                    hardware[name] = mac
                }
                continue
            }
            guard family == AF_INET else { continue }
            let flags = unsafe node.ifa_flags
            guard flags & UInt32(IFF_UP) != 0,
                  flags & UInt32(IFF_RUNNING) != 0,
                  flags & UInt32(IFF_LOOPBACK) == 0
            else { continue }

            // SAFETY: an AF_INET ifa_addr is a sockaddr_in by definition; read by
            // offset rather than cast, since the pointer's alignment is the kernel's
            // business and not something to assume.
            let ip = unsafe UnsafeRawPointer(addressPointer)
                .loadUnaligned(fromByteOffset: 4, as: UInt32.self)
            var mask: UInt32 = 0xFFFF_FFFF
            if let maskPointer = unsafe node.ifa_netmask,
               unsafe maskPointer.pointee.sa_family == sa_family_t(AF_INET) {
                mask = unsafe UInt32(bigEndian: UnsafeRawPointer(maskPointer)
                    .loadUnaligned(fromByteOffset: 4, as: UInt32.self))
            }
            addresses.append((name, IPv4Address(raw: UInt32(bigEndian: ip)), mask, flags))
        }

        let result = addresses.map { entry in
            NetworkInterface(
                name: entry.name,
                address: entry.ip,
                network: IPv4Network(base: entry.ip, prefix: Self.prefixLength(entry.mask)),
                hardwareAddress: hardware[entry.name]
            )
        }
        guard !result.isEmpty else {
            throw PlatformError.notFound("No IPv4 interface is up on this machine.")
        }
        return result
    }

    /// The interface the default route points out of.
    ///
    /// Falls back to the first enumerated interface when there is no default route —
    /// an air-gapped LAN is a legitimate thing to scan, and refusing to run on one
    /// because the machine has no path to the internet would be absurd.
    public func primaryInterface() throws(PlatformError) -> NetworkInterface {
        let candidates = try interfaces()
        #if os(macOS)
        guard let index = try? Self.defaultRouteInterfaceIndex() else { return candidates[0] }
        // Map the routing table's interface index back to a name via if_indextoname,
        // which is the only direction the kernel offers cheaply.
        var nameBuffer = [CChar](repeating: 0, count: Int(IFNAMSIZ) + 1)
        // SAFETY: if_indextoname writes at most IFNAMSIZ bytes into a buffer we sized
        // one larger, and returns nil rather than writing on failure.
        let resolved = unsafe nameBuffer.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let base = buffer.baseAddress,
                  unsafe if_indextoname(UInt32(index), base) != nil else { return nil }
            return unsafe String(cString: base)
        }
        guard let resolved, let match = candidates.first(where: { $0.name == resolved }) else {
            return candidates[0]
        }
        return match
        #else
        return Self.preferredWithoutRoutes(candidates)
        #endif
    }

    /// The interface a scan most likely means, when there is no routing table to ask.
    ///
    /// iPadOS: its SDK has no `<net/route.h>`, so the default route cannot be read the
    /// way macOS reads it. The first enumerated interface is not a safe stand-in on a
    /// cellular iPad, where `pdp_ip0` carries an address too. So the order is by kind:
    /// `en*` first (Wi-Fi is `en0`, a USB Ethernet adapter a later `en`), then anything
    /// that is not cellular (`pdp_ip*`), a VPN tunnel (`utun*`, `ipsec*`) or the Personal
    /// Hotspot bridge (`bridge*`), then those. Enumeration order breaks ties.
    ///
    /// Pure and unguarded, so it is tested on every platform. `NWPathMonitor` would
    /// name the path's interface exactly, but it answers through a callback, and waiting
    /// for one inside this synchronous call is a blocked thread on the cooperative pool.
    static func preferredWithoutRoutes(_ candidates: [NetworkInterface]) -> NetworkInterface {
        func rank(_ name: String) -> Int {
            if name.hasPrefix("en") { return 0 }
            for prefix in ["pdp_ip", "utun", "ipsec", "bridge"] where name.hasPrefix(prefix) {
                return 2
            }
            return 1
        }
        // `min(by:)` keeps the first of equal elements, which is the tie-break.
        return candidates.min { rank($0.name) < rank($1.name) } ?? candidates[0]
    }

    #if os(macOS)
    /// The interface index of the IPv4 default route, from the routing table.
    static func defaultRouteInterfaceIndex() throws(PlatformError) -> UInt16 {
        let bytes = try RouteSysctl.fetch([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0])
        // SAFETY: a raw view over a buffer owned by this scope.
        let messages = unsafe RouteMessageParser.parse(bytes[bytes.indices].span.bytes)
        // The default route: up, via a gateway, with a destination of 0.0.0.0 — which
        // the kernel emits as either a zero address or a truncated sockaddr the parser
        // reports as nil.
        for message in messages {
            guard message.flags & RTF_UP != 0, message.flags & RTF_GATEWAY != 0 else { continue }
            guard message.gateway != nil else { continue }
            if message.destination == nil || message.destination?.raw == 0 {
                return message.interfaceIndex
            }
        }
        throw PlatformError.notFound("No IPv4 default route.")
    }
    #endif

    /// Counts the leading one-bits of a netmask.
    ///
    /// Non-contiguous masks are legal in the abstract and meaningless in practice;
    /// counting leading ones gives the answer everyone means and cannot fail.
    static func prefixLength(_ mask: UInt32) -> UInt8 {
        UInt8(mask.leadingZeroBitCount == 32 ? 0 : (~mask).leadingZeroBitCount)
    }

    /// Reads a MAC out of an AF_LINK `sockaddr_dl`.
    static func hardwareAddress(_ pointer: UnsafeMutablePointer<sockaddr>) -> MACAddress? {
        // SAFETY: the same variable-length, unaligned sockaddr_dl the routing parser
        // handles, so it goes through the same byte-offset reader rather than a cast.
        // sdl_len bounds the record.
        let raw = UnsafeRawPointer(pointer)
        let declared = Int(unsafe raw.loadUnaligned(fromByteOffset: 0, as: UInt8.self))
        let length = max(declared, MemoryLayout<sockaddr_dl>.size)
        let bytes = unsafe UnsafeRawBufferPointer(start: raw, count: length)
        let nameLength = Int(unsafe bytes.loadUnaligned(fromByteOffset: 5, as: UInt8.self))
        let addressLength = Int(unsafe bytes.loadUnaligned(fromByteOffset: 6, as: UInt8.self))
        guard addressLength == 6, 8 + nameLength + 6 <= length else { return nil }
        var packed: UInt64 = 0
        for index in 0..<6 {
            let byte = unsafe bytes.loadUnaligned(
                fromByteOffset: 8 + nameLength + index, as: UInt8.self
            )
            packed = (packed << 8) | UInt64(byte)
        }
        // iOS reports `02:00:00:00:00:00` for every interface rather than its address.
        // That is a placeholder, not a hardware address, and stamping it on this
        // device's row would give every iPad the same identity.
        guard packed != 0x0200_0000_0000 else { return nil }
        return MACAddress(raw: packed)
    }
}

#endif
