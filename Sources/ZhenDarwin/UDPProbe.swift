// UDPProbe.swift — the one UDP socket this target has.
//
// There were two. `SSDPSocket` and `NetBIOSSocket` were the same class written twice:
// open, non-blocking, bind to the scanned interface, read through a `DispatchSource`,
// close in its cancel handler, `sendto` and `recvfrom` with the same pointer dance. The
// UDP port scanner would have been a third. This is that class once, in the two shapes
// its callers need:
//
//   bound       one socket, many destinations. The naming probes: an M-SEARCH to a
//               multicast group, a node-status query to every host.
//   connected   one socket, one host and port. The port scanner — and connecting is
//               not a convenience here, it is the whole mechanism: an unconnected UDP
//               socket never hears about ICMP errors, while a connected one has the
//               kernel report a port-unreachable as ECONNREFUSED on its next read. That
//               is how "closed" is told apart from silence without a raw socket.
//
// ── The descriptor rule ───────────────────────────────────────────────────────────
//
// The same one the rest of this target follows, for the same reason.
// `DispatchSource.cancel()` is asynchronous: closing the descriptor before the cancel
// handler runs returns the number to the kernel while a source may still fire on it, and
// this process opens sockets by the thousand during a deep scan — the number is reissued
// almost immediately, and the stale source then reads somebody else's socket.

#if canImport(Darwin)
import Darwin
import Dispatch
import ZhenCore

/// One datagram received.
struct UDPDatagram: Sendable {
    /// Who sent it. The source address of the datagram, which a device cannot misreport
    /// without also not receiving our request.
    var source: IPv4Address
    /// Its bytes.
    var payload: [UInt8]
}

/// What a UDP socket's readiness can deliver.
enum UDPEvent: Sendable {
    /// A datagram arrived.
    case datagram(UDPDatagram)
    /// The kernel reported ICMP port-unreachable. Only a connected socket hears this.
    case refused
    /// The kernel reported some other ICMP error — host or network unreachable,
    /// administratively prohibited. Carries the `errno`. Only a connected socket.
    case unreachable(Int32)
}

/// A UDP socket, bound to an interface or connected to one host and port, readable as a
/// stream of events.
final class UDPProbe: @unchecked Sendable {
    private let fd: Int32
    private let queue: DispatchQueue
    private var source: DispatchSourceRead?
    private var continuation: AsyncStream<UDPEvent>.Continuation?
    private var stopped = false
    /// Whether a read source has taken responsibility for closing the descriptor.
    ///
    /// Exactly one of the source's cancel handler and `deinit` closes it, never both.
    /// The flag stays TRUE after `stop()` — `stop()` cancels the source, and cancellation
    /// is asynchronous, so the handler has not run yet and the descriptor is still the
    /// source's to close. Clearing it there and letting `deinit` close as well is a
    /// double close, and a double close is not harmless: between the two, another thread
    /// can open a socket and be handed the same number, and the second close then tears
    /// down an unrelated connection.
    private var sourceOwnsDescriptor = false

    /// Opens a socket and binds it to the interface's own address, on an ephemeral port.
    ///
    /// The address is the part that matters: the source address of a query decides where
    /// the reply is sent, and on a multi-homed machine an unbound socket can put the
    /// wrong one on the wire. The ephemeral port keeps this socket from fighting anything
    /// already listening on the service's well-known port — Samba on 137, a media server
    /// on 1900 — and every protocol spoken here replies to the source port.
    ///
    /// - Parameter configure: further options, applied after binding. Returns the name
    ///   of the call that failed, or nil.
    init(
        interface: NetworkInterface,
        queue: DispatchQueue,
        configure: (Int32) -> String? = { _ in nil }
    ) throws(PlatformError) {
        let descriptor = try Self.open()
        var local = socketAddress(interface.address, port: 0)
        // SAFETY: bind reads one sockaddr_in from storage we own and sized.
        let bound = unsafe withUnsafePointer(to: &local) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                unsafe bind(descriptor, address, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw Self.fail(descriptor, "bind(\(interface.address))") }
        if let failed = configure(descriptor) { throw Self.fail(descriptor, failed) }
        self.fd = descriptor
        self.queue = queue
    }

    /// Opens a socket connected to one host and port.
    ///
    /// Connecting a UDP socket sends nothing. It fixes the peer, which filters incoming
    /// datagrams to that peer's and makes the kernel deliver ICMP errors for it.
    init(connectingTo address: IPv4Address, port: UInt16, queue: DispatchQueue) throws(PlatformError) {
        let descriptor = try Self.open()
        var peer = socketAddress(address, port: port)
        // SAFETY: connect reads one sockaddr_in from storage we own and sized.
        let connected = unsafe withUnsafePointer(to: &peer) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                unsafe connect(descriptor, address, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw Self.fail(descriptor, "connect(\(address):\(port))") }
        self.fd = descriptor
        self.queue = queue
    }

    deinit {
        if let source {
            source.cancel()               // the cancel handler closes it
        } else if !sourceOwnsDescriptor {
            _ = Darwin.close(fd)          // no source was ever armed, so nobody else will
        }
    }

    private static func open() throws(PlatformError) -> Int32 {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard descriptor >= 0 else { throw PlatformError.syscall("socket(SOCK_DGRAM, UDP)") }
        guard setNonBlocking(descriptor) else { throw fail(descriptor, "fcntl(O_NONBLOCK)") }
        return descriptor
    }

    /// Closes a descriptor no source owns yet, and names the call that failed.
    private static func fail(_ descriptor: Int32, _ api: String) -> PlatformError {
        let error = PlatformError.syscall(api)
        _ = Darwin.close(descriptor)
        return error
    }

    /// Sends one datagram to a destination. Best effort: a refused send is one lost
    /// probe, and every caller sends more than one.
    func send(_ bytes: [UInt8], to address: IPv4Address, port: UInt16) {
        var destination = socketAddress(address, port: port)
        // SAFETY: sendto reads `bytes.count` bytes from the array's storage and the
        // sockaddr from storage we own, both only for the duration of the call.
        _ = unsafe bytes.withUnsafeBytes { buffer in
            unsafe withUnsafePointer(to: &destination) { pointer in
                unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                    unsafe sendto(fd, buffer.baseAddress, buffer.count, 0,
                                  address, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    /// Sends one datagram to the connected peer.
    ///
    /// Returns the `errno` of a failed send, because on a connected socket a send is
    /// also where an earlier ICMP error can surface — and an error consumed here is one
    /// the reader never sees. The caller has to treat ECONNREFUSED from this as the
    /// answer it is.
    @discardableResult
    func send(_ bytes: [UInt8]) -> Int32 {
        // SAFETY: send reads `bytes.count` bytes from the array's storage for the call.
        let sent = unsafe bytes.withUnsafeBytes { buffer in
            unsafe Darwin.send(fd, buffer.baseAddress, buffer.count, 0)
        }
        return sent < 0 ? errno : 0
    }

    /// Starts the reader and returns events as they arrive.
    func events() -> AsyncStream<UDPEvent> {
        let (stream, continuation) = AsyncStream<UDPEvent>.makeStream(
            bufferingPolicy: .bufferingNewest(512)
        )
        self.continuation = continuation
        let descriptor = fd
        let readSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        readSource.setEventHandler {
            // Drain everything ready in one wake-up. A network with a dozen UPnP devices
            // answering `ssdp:all` produces sixty datagrams in a burst.
            while let event = UDPProbe.receive(descriptor) {
                continuation.yield(event)
            }
        }
        // The one place this descriptor is closed.
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

    /// Reads one event, or nil when the socket is drained.
    private static func receive(_ fd: Int32) -> UDPEvent? {
        // 2 KB. Every reply this target parses — an M-SEARCH response, a node-status
        // reply, a DNS, NTP or SNMP answer to the probes it sends — is well under it, and
        // a truncated read of something larger parses to nothing rather than to
        // something wrong. For the port scanner the bytes barely matter: that a datagram
        // came back from the connected peer at all is what makes the port open.
        var buffer = [UInt8](repeating: 0, count: 2048)
        var from = sockaddr_storage()
        var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        // SAFETY: recvfrom writes at most `buffer.count` bytes into storage we own and a
        // sockaddr into storage we sized. A negative return means drained or failed and
        // nothing was written.
        let received = unsafe buffer.withUnsafeMutableBytes { bytes in
            unsafe withUnsafeMutablePointer(to: &from) { pointer in
                unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                    unsafe recvfrom(fd, bytes.baseAddress, bytes.count, 0, address, &fromLength)
                }
            }
        }
        if received < 0 {
            switch errno {
            case ECONNREFUSED: return .refused
            // The ICMP errors a connected socket can be handed. Each is reported once
            // and cleared by the read that reported it, so the drain loop moves on.
            case EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, ENETDOWN: return .unreachable(errno)
            // EAGAIN is drained; anything else is not an answer from the network, and
            // returning an event for it would spin the drain loop on an error that never
            // clears.
            default: return nil
            }
        }
        // A zero-length datagram is still a datagram, and from a connected peer it is
        // still an answer.
        guard let source = ipv4(from: from) else { return nil }
        return .datagram(UDPDatagram(source: source, payload: Array(buffer[0..<received])))
    }
}
#endif
