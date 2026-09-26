// ICMPv6Socket.swift — ICMPv6 echo without privilege.
//
// The v6 twin of `ICMPSocket`: `SOCK_DGRAM` / `IPPROTO_ICMPV6`, which macOS opens for an
// ordinary user exactly as it does the v4 one (measured at uid 501, D1).
//
// It is BOUND to the interface's own link-local address, for two reasons. A link-local
// destination is meaningless without an interface — `fe80::1` exists once per link — and
// binding with the interface's scope is what says which link. And a bound socket has a
// known source address, so the request's checksum can be computed over the right
// pseudo-header rather than left for the kernel (which, on macOS, rewrites it anyway;
// see `ICMPv6Echo`).
//
// Stage D2 sends to `ff02::1` through this same socket; nothing here is unicast-only.
//
// The descriptor rule is the target's usual one: the read source's cancel handler is the
// only place the descriptor is closed. See `UDPProbe`.

#if canImport(Darwin)
import Darwin
import Dispatch
import ZhenCore

/// One of our echo replies.
struct ICMPv6Reply: Sendable, Hashable {
    /// Who answered, with the zone the reply arrived on.
    var source: IPv6Address
    var sequence: UInt16
    var token: UInt32
    var receivedAt: MonotonicInstant
}

final class ICMPv6Socket: @unchecked Sendable {
    /// The address the socket is bound to, which every request is sent from.
    let local: IPv6Address
    private let fd: Int32
    private var source: DispatchSourceRead?
    private var continuation: AsyncStream<ICMPv6Reply>.Continuation?
    private var stopped = false
    private var sourceOwnsDescriptor = false

    /// Opens a socket bound to `interface`'s link-local address.
    init(interface: String) throws(PlatformError) {
        guard let local = Self.linkLocalAddress(of: interface) else {
            throw PlatformError.syscall("getifaddrs: \(interface) has no link-local IPv6 address")
        }
        let descriptor = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)
        guard descriptor >= 0 else { throw PlatformError.syscall("socket(SOCK_DGRAM, IPPROTO_ICMPV6)") }
        guard setNonBlocking(descriptor) else {
            _ = Darwin.close(descriptor)
            throw PlatformError.syscall("fcntl(O_NONBLOCK)")
        }
        var address = Self.socketAddress(local)
        // SAFETY: bind reads one sockaddr_in6 from storage we own and sized.
        let bound = unsafe withUnsafePointer(to: &address) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bound == 0 else {
            _ = Darwin.close(descriptor)
            throw PlatformError.syscall("bind(\(local))")
        }
        self.local = local
        self.fd = descriptor
    }

    deinit {
        if let source {
            source.cancel()
        } else if !sourceOwnsDescriptor {
            _ = Darwin.close(fd)
        }
    }

    /// Sends one echo request. Returns when it left, or nil if the send failed.
    @discardableResult
    func send(to destination: IPv6Address, sequence: UInt16, token: UInt32) -> MonotonicInstant? {
        // A destination with no zone is sent on this socket's interface: every address
        // this socket reaches is on that link.
        let scoped = destination.zone == nil
            ? IPv6Address(high: destination.high, low: destination.low, zone: local.zone)
            : destination
        let packet = ICMPv6Echo.request(sequence: sequence, token: token,
                                        source: local, destination: scoped)
        var address = Self.socketAddress(scoped)
        // SAFETY: sendto reads `packet.count` bytes from the array's storage and one
        // sockaddr_in6 from storage we own, both only for the duration of the call.
        let sent = unsafe packet.withUnsafeBytes { bytes in
            unsafe withUnsafePointer(to: &address) { pointer in
                unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    unsafe sendto(fd, bytes.baseAddress, bytes.count, 0, $0,
                                  socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
        return sent == packet.count ? .now : nil
    }

    /// Starts the reader and returns our echo replies as they arrive. Everything else
    /// the socket receives — other programs' replies, router advertisements — is dropped
    /// by `ICMPv6Echo.decodeReply`, and anything whose checksum does not verify for the
    /// addresses it travelled between is dropped too.
    func replies() -> AsyncStream<ICMPv6Reply> {
        let (stream, continuation) = AsyncStream<ICMPv6Reply>.makeStream(
            bufferingPolicy: .bufferingNewest(4096)
        )
        self.continuation = continuation
        let descriptor = fd
        let destination = local
        let readSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ReadinessQueue.shared)
        readSource.setEventHandler {
            while let (message, from) = ICMPv6Socket.receive(descriptor) {
                guard ICMPv6Echo.verifies(message, source: from, destination: destination),
                      let (sequence, token) = ICMPv6Echo.decodeReply(message)
                else { continue }
                continuation.yield(ICMPv6Reply(source: from, sequence: sequence, token: token,
                                               receivedAt: .now))
            }
        }
        readSource.setCancelHandler { [fd] in
            _ = Darwin.close(fd)
            continuation.finish()
        }
        sourceOwnsDescriptor = true
        readSource.resume()
        self.source = readSource
        return stream
    }

    /// Stops delivery and closes the descriptor, via the cancel handler.
    func stop() {
        guard !stopped else { return }
        stopped = true
        if let source {
            source.cancel()
            self.source = nil
            continuation = nil
        } else {
            continuation?.finish()
            continuation = nil
        }
    }

    /// Reads one ICMPv6 message and who sent it, or nil when drained.
    private static func receive(_ fd: Int32) -> ([UInt8], IPv6Address)? {
        var buffer = [UInt8](repeating: 0, count: 1500)
        var from = sockaddr_in6()
        var fromLength = socklen_t(MemoryLayout<sockaddr_in6>.size)
        // SAFETY: recvfrom writes at most `buffer.count` bytes into storage we own and a
        // sockaddr_in6 into storage we sized. A negative return wrote nothing.
        let received = unsafe buffer.withUnsafeMutableBytes { bytes in
            unsafe withUnsafeMutablePointer(to: &from) { pointer in
                unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    unsafe recvfrom(fd, bytes.baseAddress, bytes.count, 0, $0, &fromLength)
                }
            }
        }
        guard received > 0, let source = address(from) else { return nil }
        return (Array(buffer[0..<received]), source)
    }

    // ── Addresses across the boundary ─────────────────────────────────────────────

    static func socketAddress(_ address: IPv6Address) -> sockaddr_in6 {
        var storage = sockaddr_in6()
        storage.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        storage.sin6_family = sa_family_t(AF_INET6)
        let bytes = address.bytes
        unsafe withUnsafeMutableBytes(of: &storage.sin6_addr) { raw in
            for index in 0..<16 { unsafe raw[index] = bytes[index] }
        }
        // SAFETY: if_nametoindex reads the C string Swift bridges for the call.
        if let zone = address.zone { storage.sin6_scope_id = unsafe if_nametoindex(zone) }
        return storage
    }

    static func address(_ storage: sockaddr_in6) -> IPv6Address? {
        var raw = unsafe withUnsafeBytes(of: storage.sin6_addr) { unsafe Array($0) }
        var zone: String?
        if raw[0] == 0xFE, raw[1] & 0xC0 == 0x80 {
            // The KAME stack embeds the scope in bytes 2-3 of a link-local address on
            // some kernel paths. It is not part of the address; the scope id is.
            raw[2] = 0
            raw[3] = 0
            zone = interfaceName(storage.sin6_scope_id)
        }
        return IPv6Address(bytes: raw, zone: zone)
    }

    static func interfaceName(_ index: UInt32) -> String? {
        guard index != 0 else { return nil }
        var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        // SAFETY: if_indextoname writes at most IF_NAMESIZE bytes into storage we sized.
        guard unsafe if_indextoname(index, &name) != nil else { return nil }
        return String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// The interface's link-local IPv6 address, with its zone.
    static func linkLocalAddress(of interface: String) -> IPv6Address? {
        var head: UnsafeMutablePointer<ifaddrs>?
        // SAFETY: getifaddrs allocates a list we walk read-only and free before returning.
        guard unsafe getifaddrs(&head) == 0 else { return nil }
        defer { unsafe freeifaddrs(head) }
        var cursor = unsafe head
        while let entry = unsafe cursor {
            defer { unsafe cursor = entry.pointee.ifa_next }
            guard let addr = unsafe entry.pointee.ifa_addr,
                  unsafe addr.pointee.sa_family == sa_family_t(AF_INET6),
                  unsafe String(cString: entry.pointee.ifa_name) == interface
            else { continue }
            let storage = unsafe UnsafeRawPointer(addr).loadUnaligned(as: sockaddr_in6.self)
            if let address = address(storage), address.isLinkLocal {
                return IPv6Address(high: address.high, low: address.low, zone: interface)
            }
        }
        return nil
    }
}

/// One echo to one address, and the round trip if it answered.
enum ICMPv6Ping {
    static func echo(_ address: IPv6Address, interface: String, within budget: Duration) async -> Duration? {
        guard let socket = try? ICMPv6Socket(interface: interface) else { return nil }
        let token = UInt32.random(in: 1...UInt32.max)
        let replies = socket.replies()
        guard let sentAt = socket.send(to: address, sequence: 1, token: token) else {
            socket.stop()
            return nil
        }
        let rtt = await withTaskGroup(of: Duration?.self) { group in
            group.addTask {
                for await reply in replies where reply.token == token {
                    return reply.receivedAt.duration(since: sentAt)
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: budget)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
        socket.stop()
        return rtt
    }
}
#endif
