// CapabilityProbe.swift — what the iPadOS sandbox actually allows, one syscall at a time.
//
// The iPadOS composition was decided from SDK headers and from what is widely reported
// about the sandbox. This checks it: each probe makes the call the engine (or a cut
// feature) would make and records what came back — a byte count, an errno, or a value.
// The simulator runs on the Mac's kernel, so only a device run counts.
//
// Every probe is a plain syscall with a bounded wait; none blocks on the network.

import Darwin
import Foundation
import ZhenCore

/// One probe's result, for the table.
nonisolated struct ProbeResult: Identifiable, Sendable {
    let id = UUID()
    /// What was tried.
    let name: String
    /// What came back, in a sentence.
    let outcome: String
    /// Whether it behaved the way the iPadOS composition assumes.
    let asAssumed: Bool
    /// What the composition assumes, so a surprise is readable without the source.
    let assumption: String
}

/// The probes, run off the main actor.
nonisolated enum CapabilityProbe {
    @concurrent
    static func runAll() async -> [ProbeResult] {
        [
            icmpSocket(),
            routeDump(),
            arpTable(),
            descriptorLimit(),
            interfaceMACs(),
            ssdpSend(),
            bonjourDeclared(),
        ]
    }

    // ── The kept engines ─────────────────────────────────────────────────────────

    /// The ICMP sweep's socket: unprivileged datagram ICMP.
    static func icmpSocket() -> ProbeResult {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        let error = errno
        if fd >= 0 { close(fd) }
        return ProbeResult(
            name: "socket(SOCK_DGRAM, IPPROTO_ICMP)",
            outcome: fd >= 0 ? "opened" : "failed: \(describe(error))",
            asAssumed: fd >= 0,
            assumption: "Opens without privilege — the sweep depends on it."
        )
    }

    /// How many descriptors the process may hold; the connect scan's concurrency is
    /// derived from it.
    static func descriptorLimit() -> ProbeResult {
        var limits = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limits) == 0 else {
            return ProbeResult(name: "getrlimit(RLIMIT_NOFILE)", outcome: "failed: \(describe(errno))",
                               asAssumed: false, assumption: "Readable.")
        }
        let before = limits.rlim_cur
        var raised = limits
        raised.rlim_cur = min(limits.rlim_max, 10_240)
        let ok = setrlimit(RLIMIT_NOFILE, &raised) == 0
        _ = getrlimit(RLIMIT_NOFILE, &limits)
        return ProbeResult(
            name: "RLIMIT_NOFILE",
            outcome: "soft \(before) → \(limits.rlim_cur) (hard \(limits.rlim_max))\(ok ? "" : ", raise refused")",
            asAssumed: limits.rlim_cur > before || before >= 1024,
            assumption: "Raisable well past 256, or the scan runs narrow."
        )
    }

    // ── The cut ones: is the cut still right on this device? ─────────────────────

    /// The default route, which macOS reads to pick the interface. iPadOS uses a name
    /// ranking instead; a readable dump would allow the macOS answer.
    static func routeDump() -> ProbeResult {
        let result = sysctlBytes([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0])
        return ProbeResult(
            name: "sysctl NET_RT_DUMP",
            outcome: result.map { "\($0.count) bytes" } ?? "failed: \(describe(errno))",
            asAssumed: true,
            assumption: "Unused on iPadOS. Readable would mean the interface could come from the route, as on macOS."
        )
    }

    /// The ARP table, and whether the MACs in it are real.
    static func arpTable() -> ProbeResult {
        let rtfLLInfo: Int32 = 0x400  // RTF_LLINFO; <net/route.h> is not in the iOS SDK
        guard let bytes = sysctlBytes([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, rtfLLInfo]) else {
            return ProbeResult(name: "sysctl NET_RT_FLAGS/RTF_LLINFO", outcome: "failed: \(describe(errno))",
                               asAssumed: true, assumption: "Not readable by an app.")
        }
        let macs = linkAddresses(inARPDump: bytes)
        let real = macs.filter { $0 != 0 && $0 != 0x0200_0000_0000 }
        return ProbeResult(
            name: "sysctl NET_RT_FLAGS/RTF_LLINFO",
            outcome: "\(bytes.count) bytes, \(macs.count) entries, \(real.count) with a real MAC",
            asAssumed: real.isEmpty,
            assumption: "No real MACs. If there are, the neighbour table could come back on iPadOS."
        )
    }

    /// This device's own hardware address.
    static func interfaceMACs() -> ProbeResult {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else {
            return ProbeResult(name: "getifaddrs AF_LINK", outcome: "failed: \(describe(errno))",
                               asAssumed: false, assumption: "Readable.")
        }
        defer { freeifaddrs(head) }
        var seen: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == AF_LINK,
                  String(cString: entry.pointee.ifa_name) == "en0" else { continue }
            let raw = UnsafeRawPointer(address)
            let nameLength = Int(raw.load(fromByteOffset: 5, as: UInt8.self))
            let addressLength = Int(raw.load(fromByteOffset: 6, as: UInt8.self))
            guard addressLength == 6 else { continue }
            let bytes = (0..<6).map { raw.load(fromByteOffset: 8 + nameLength + $0, as: UInt8.self) }
            seen.append(bytes.map { String(format: "%02x", $0) }.joined(separator: ":"))
        }
        let placeholder = seen.allSatisfy { $0 == "02:00:00:00:00:00" }
        return ProbeResult(
            name: "getifaddrs en0 MAC",
            outcome: seen.isEmpty ? "no en0 link address" : seen.joined(separator: ", "),
            asAssumed: placeholder,
            assumption: "The 02:00:00:00:00:00 placeholder, which the engine now drops."
        )
    }

    /// An SSDP M-SEARCH send, which is what the multicast entitlement gates.
    static func ssdpSend() -> ProbeResult {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            return ProbeResult(name: "sendto 239.255.255.250:1900", outcome: "no socket: \(describe(errno))",
                               asAssumed: true, assumption: "Refused without the entitlement.")
        }
        defer { close(fd) }
        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = in_port_t(1900).bigEndian
        destination.sin_addr.s_addr = inet_addr("239.255.255.250")
        let search = Array("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".utf8)
        let sent = withUnsafePointer(to: &destination) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, search, search.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        let error = errno
        return ProbeResult(
            name: "sendto 239.255.255.250:1900",
            outcome: sent >= 0 ? "sent \(sent) bytes" : "failed: \(describe(error))",
            asAssumed: sent < 0,
            assumption: "Refused without com.apple.developer.networking.multicast, which is why SSDP is off."
        )
    }

    /// Whether every Bonjour type the browser asks for is declared in Info.plist.
    static func bonjourDeclared() -> ProbeResult {
        let declared = Bundle.main.object(forInfoDictionaryKey: "NSBonjourServices") as? [String] ?? []
        let missing = BonjourVocabulary.browsedTypes.filter { !declared.contains($0) }
        return ProbeResult(
            name: "NSBonjourServices",
            outcome: missing.isEmpty
                ? "all \(BonjourVocabulary.browsedTypes.count) browsed types declared"
                : "missing: \(missing.joined(separator: ", "))",
            asAssumed: missing.isEmpty,
            assumption: "Matches BonjourVocabulary.browsedTypes; a missing type browses to silence."
        )
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /// A sysctl's bytes, or nil with errno set.
    static func sysctlBytes(_ name: [Int32]) -> [UInt8]? {
        var mib = name
        var size = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0 else { return nil }
        guard size > 0 else { return [] }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, UInt32(mib.count), &bytes, &size, nil, 0) == 0 else { return nil }
        return Array(bytes.prefix(size))
    }

    /// The gateway link address of each message in an ARP dump.
    ///
    /// By byte offset, as `RouteMessages.swift` does on macOS: `rt_msghdr` is 92 bytes
    /// with `rtm_msglen` at 0, then the destination `sockaddr_in` rounded to four bytes,
    /// then the gateway `sockaddr_dl` — family at 1, name length at 5, address length at
    /// 6, data at 8. Malformed input stops the walk.
    static func linkAddresses(inARPDump bytes: [UInt8]) -> [UInt64] {
        func roundUp(_ length: Int) -> Int { length == 0 ? 4 : 1 + ((length - 1) | 3) }
        var result: [UInt64] = []
        var base = 0
        while base + 2 <= bytes.count {
            let length = Int(bytes[base]) | Int(bytes[base + 1]) << 8
            guard length > 0, base + length <= bytes.count else { break }
            var cursor = base + 92
            if cursor < base + length {
                cursor += roundUp(Int(bytes[cursor]))
            }
            if cursor + 8 <= base + length, bytes[cursor + 1] == UInt8(AF_LINK) {
                let nameLength = Int(bytes[cursor + 5])
                let addressLength = Int(bytes[cursor + 6])
                let start = cursor + 8 + nameLength
                if addressLength == 6, start + 6 <= base + length {
                    result.append(bytes[start..<start + 6].reduce(0) { $0 << 8 | UInt64($1) })
                } else {
                    result.append(0)
                }
            }
            base += length
        }
        return result
    }

    static func describe(_ code: Int32) -> String {
        "\(String(cString: strerror(code))) (errno \(code))"
    }
}
