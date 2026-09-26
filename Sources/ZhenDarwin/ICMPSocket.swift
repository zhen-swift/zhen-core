// ICMPSocket.swift — one socket, every target, on its own executor.
//
// A sweep uses a single ICMP datagram socket rather than one per target. That is not
// an optimisation, it is how the protocol works: ICMP has no ports, so there is nothing
// to bind per host, and the kernel demultiplexes replies to this socket by the
// identifier it rewrites on the way out. One descriptor for a whole /24 also means the
// descriptor limit is irrelevant to discovery — it only binds the TCP connect scan.
//
// The actor runs on a dedicated serial executor rather than the shared cooperative
// pool. Reply handling is the one latency-sensitive thing in this program: a reply that
// waits behind a report encode is measured as network latency and inflates every RTT in
// the artifact. Giving it its own queue costs a `SerialExecutor` conformance and buys
// wake-up latency that does not depend on what else the process is doing.
#if canImport(Darwin)

import Darwin
import Dispatch
import ZhenCore

/// A `SerialExecutor` backed by a dedicated `DispatchQueue`.
///
/// The conformance is small because that is all it needs to be: `DispatchQueue` is
/// already a serial execution context, so the executor is a shim that hands Swift's
/// jobs to it instead of to the cooperative pool.
final class DedicatedExecutor: SerialExecutor {
    private let queue: DispatchQueue

    init(label: String) {
        self.queue = DispatchQueue(label: label, qos: .userInitiated)
    }

    func enqueue(_ job: consuming ExecutorJob) {
        // SAFETY: the standard executor hand-off. `UnownedJob` does not retain the job,
        // so it must be run exactly once and must not outlive this enqueue — which
        // `queue.async` guarantees, since the queue owns the closure until it runs it
        // and `runSynchronously` consumes the job. This is the shape every custom
        // executor has; there is no safe spelling of it.
        let unowned = UnownedJob(job)
        let executor = unsafe asUnownedSerialExecutor()
        queue.async { unsafe unowned.runSynchronously(on: executor) }
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        // SAFETY: unowned by contract — the actor holds this executor for its whole
        // lifetime, so the reference cannot dangle.
        unsafe UnownedSerialExecutor(ordinary: self)
    }
}

/// Owns the ICMP socket and the table of outstanding probes.
actor ICMPSocket {
    private let executor = DedicatedExecutor(label: "com.jctec.zhen.icmp")

    /// Routes this actor's work to the dedicated queue instead of the cooperative pool.
    nonisolated var unownedExecutor: UnownedSerialExecutor { unsafe executor.asUnownedSerialExecutor() }

    /// The raw descriptor.
    ///
    /// A raw `Int32` rather than an `OwnedDescriptor`, deliberately. A class cannot
    /// consume a stored property, so the noncopyable wrapper's whole benefit — a
    /// compile-time single-close guarantee — is unavailable here anyway. This socket
    /// has one obvious owner and one `deinit`; the wrapper earns its keep on the TCP
    /// probes, where there are tens of thousands of short-lived descriptors and the
    /// ownership question is real.
    private let fd: Int32
    private var source: DispatchSourceRead?
    private var continuation: AsyncStream<ICMPReply>.Continuation?
    /// Whether the read source has taken responsibility for closing the descriptor.
    ///
    /// Exactly one of the source's cancel handler and `deinit` closes it, never both
    /// and never neither. A double close is not harmless: between the two, another
    /// thread can open a socket and be handed the same number.
    private var sourceOwnsDescriptor = false

    /// Opens an unprivileged ICMP datagram socket.
    ///
    /// - Throws: `.denied` when the kernel refuses the socket, which on a Mac means
    ///   something unusual — this socket type is available to normal users and is the
    ///   reason this tool needs no password.
    init() throws(PlatformError) {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard descriptor >= 0 else { throw PlatformError.syscall("socket(SOCK_DGRAM, IPPROTO_ICMP)") }
        guard setNonBlocking(descriptor) else {
            _ = Darwin.close(descriptor)
            throw PlatformError.syscall("fcntl(O_NONBLOCK)")
        }
        // Ask for the TTL as a control message. Best effort: if the kernel declines,
        // the IP-header path in the decoder may still recover it, and a missing TTL is
        // one absent hint rather than a failed scan.
        var enable: Int32 = 1
        _ = unsafe setsockopt(descriptor, IPPROTO_IP, IP_RECVTTL,
                              &enable, socklen_t(MemoryLayout<Int32>.size))
        // A large receive buffer. A /24 answering at once is 254 replies inside a few
        // milliseconds, and the default buffer drops them faster than any reader can
        // drain — which would read as packet loss from hosts that in fact replied.
        var receiveBuffer: Int32 = 1 << 20
        _ = unsafe setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF,
                              &receiveBuffer, socklen_t(MemoryLayout<Int32>.size))
        // And a large send buffer. Sweeping a /24 means 254 datagrams handed to the
        // kernel back to back; against the default buffer roughly half of them are
        // refused with EAGAIN, which reads as half the network being absent. The send
        // path retries, but not having to is cheaper.
        var sendBuffer: Int32 = 1 << 20
        _ = unsafe setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF,
                              &sendBuffer, socklen_t(MemoryLayout<Int32>.size))
        self.fd = descriptor
    }

    deinit {
        if let source {
            // The cancel handler closes it. Cancellation is asynchronous, so the
            // descriptor stays valid until the handler runs — which is the entire
            // point of closing there rather than here.
            source.cancel()
        } else if !sourceOwnsDescriptor {
            // No source was ever armed, so nobody else is going to close this.
            //
            // The flag has to be consulted here, and an earlier version did not: `stop()`
            // cancels the source and clears `self.source`, so a socket that had been
            // stopped reached this branch with a descriptor the cancel handler was
            // already on its way to closing, and closed it a second time. Harmless in
            // isolation and not in this program — a deep scan opens thousands of sockets
            // a second, so the number is reissued almost immediately and the second close
            // tears down an unrelated probe's connection.
            _ = Darwin.close(fd)
        }
    }

    /// Starts the reader and returns replies as they arrive.
    ///
    /// The stream declares `.bufferingNewest`: replies are drained by the sweep as fast
    /// as they arrive, and a consumer that fell behind by four thousand replies has
    /// bigger problems than the oldest of them.
    func replies() -> AsyncStream<ICMPReply> {
        let (stream, continuation) = AsyncStream<ICMPReply>.makeStream(
            bufferingPolicy: .bufferingNewest(4096)
        )
        self.continuation = continuation

        let readSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ReadinessQueue.shared)
        let descriptor = fd
        readSource.setEventHandler {
            // Drain everything ready in one wake-up rather than one datagram per
            // event. Amortising the domain crossing is the whole point of a readiness
            // API that reports how much is pending.
            // Drain until the socket is empty, not until the first datagram that is
            // not an echo reply.
            //
            // Stopping early was a real bug with a quiet failure mode:
            // destination-unreachable messages arrive routinely on this socket — one
            // per dead address that a router bothers to answer for — and each one
            // ended the drain, leaving every echo reply queued behind it until the
            // next readiness wake-up. Those replies were then stamped with the later
            // wake-up's timestamp, so their RTT was inflated by however long the
            // socket sat idle, and that inflated number fed the adaptive timeout.
            //
            // Stamp on arrival, inside the readiness handler: every later hop is our
            // own scheduling, and a timestamp taken after them measures the scanner
            // rather than the network.
            while true {
                switch ICMPSocket.receive(descriptor, at: .now) {
                case .datagram(let reply):
                    if let reply { continuation.yield(reply) }
                case .drained:
                    return
                }
            }
        }
        // The descriptor is closed HERE and nowhere else once a source exists.
        //
        // `DispatchSource.cancel()` is asynchronous: it returns immediately and the
        // kernel deregistration completes later. Closing the descriptor before that
        // happens is a use-after-close that libdispatch detects as
        // DISPATCH_CLIENT_CRASH when it is loud, and that silently rebinds a stale
        // source to a freshly issued descriptor when it is not. The cancel handler is
        // the one place the runtime guarantees the source is finished with the
        // descriptor.
        readSource.setCancelHandler { [fd] in
            _ = Darwin.close(fd)
            continuation.finish()
        }
        sourceOwnsDescriptor = true
        readSource.resume()
        self.source = readSource
        return stream
    }

    /// Stops delivery, closes the descriptor and finishes the stream.
    ///
    /// The close happens inside the source's cancel handler, so this returns before the
    /// descriptor is actually gone. That is correct and deliberate: nothing else may
    /// touch the descriptor after this call anyway.
    func stop() {
        if let source {
            source.cancel()      // cancel handler closes the fd and finishes the stream
            self.source = nil
            // `sourceOwnsDescriptor` deliberately stays true: cancellation is
            // asynchronous, the handler has not run yet, and the descriptor is still the
            // source's to close.
            continuation = nil
        } else {
            continuation?.finish()
            continuation = nil
        }
    }

    /// Sends a whole round in one actor hop.
    ///
    /// One crossing per round rather than one per probe, and the difference is not
    /// small: a /24 sweep is 254 probes, and going through the actor for each of them
    /// cost more wall clock than every `sendto` combined — 254 raw sends take about ten
    /// milliseconds, while 254 round trips through a dispatch-queue-backed executor
    /// took several hundred. This is the specialization paper's fourth principle at the
    /// smallest possible scale: amortize the domain crossing, do not eliminate the work.
    ///
    /// - Returns: the instant each probe actually went out, for the ones that did.
    ///   Addresses missing from the result were never sent and must not be counted as
    ///   unanswered.
    func sendRound(_ assignments: [ProbeAssignment]) async -> [UInt32: MonotonicInstant] {
        var sent: [UInt32: MonotonicInstant] = [:]
        sent.reserveCapacity(assignments.count)
        for assignment in assignments {
            if Task.isCancelled { break }
            if let instant = await send(to: assignment.address,
                                        sequence: assignment.sequence,
                                        token: assignment.token) {
                sent[assignment.token] = instant
            }
        }
        return sent
    }

    /// Sends one echo request, returning when it went out.
    ///
    /// The returned instant is taken immediately after `sendto` rather than before the
    /// call, so the round trip measured against it is the wire and not our own
    /// scheduling. Returns nil for a probe that could not be sent at all.
    ///
    /// `EAGAIN` is retried rather than treated as failure. A non-blocking socket
    /// handed 254 datagrams in a tight loop refuses a large fraction of them once the
    /// send buffer fills, and counting those as unanswered would report half the
    /// network as absent — which is exactly what the first version of this did.
    func send(to address: IPv4Address, sequence: UInt16, token: UInt32) async -> MonotonicInstant? {
        let packet = ICMPEcho.request(sequence: sequence, token: token)
        var destination = socketAddress(address)
        for attempt in 0..<8 {
            let sent = unsafe packet.withUnsafeBytes { payload -> Int in
                unsafe withUnsafePointer(to: &destination) { pointer in
                    unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
                        unsafe sendto(fd, payload.baseAddress, payload.count, 0,
                                      addr, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            if sent == packet.count { return .now }
            guard errno == EAGAIN || errno == ENOBUFS else { return nil }
            // Wait for the socket to drain via kqueue, not by sleeping. Sleeping was
            // the first attempt and it was badly wrong: `Task.sleep` granularity is on
            // the order of a millisecond, so microsecond-scale retries across a /24
            // cost whole seconds of a sweep that should take tens of milliseconds.
            // Readiness returns immediately when the socket is already writable, which
            // is the common case, and costs nothing when it is not.
            // Yield first. A datagram socket whose buffer is momentarily full drains
            // within microseconds, and a cooperative yield costs nothing. Falling
            // straight to a DispatchSource would build and tear down a kqueue
            // registration per refused datagram, which across a /24 is thousands of
            // them — that cost more wall clock than the sends themselves.
            //
            // `Task.sleep` is not an option here at all: its granularity is around a
            // millisecond, so microsecond-scale retries across a sweep cost seconds.
            if attempt < 4 {
                await Task.yield()
            } else if await Readiness.writableBorrowed(fd, within: .milliseconds(50)) == .cancelled {
                return nil
            }
        }
        return nil
    }

    /// Reads one datagram, or nil when the socket has nothing left.
    ///
    /// `recvmsg` rather than `recvfrom` because the TTL arrives as a control message
    /// and there is no other way to see it on a datagram ICMP socket.
    /// The result of one `recvmsg`: a datagram (which may not be one of ours), or an
    /// empty socket.
    ///
    /// Distinguishing them is what lets the drain loop keep going past a datagram it
    /// cannot use instead of treating it as end-of-queue.
    enum Received {
        case datagram(ICMPReply?)
        case drained
    }

    /// Internal rather than private so a test can feed it a datagram over loopback and
    /// assert it distinguishes "not one of ours" from "the socket is empty" — the
    /// distinction the drain loop turns on.
    static func receive(_ fd: Int32, at receivedAt: MonotonicInstant) -> Received {
        var buffer = [UInt8](repeating: 0, count: 2048)
        var control = [UInt8](repeating: 0, count: 256)
        var peer = sockaddr_storage()
        var received = 0
        var ttl: UInt8?

        // SAFETY: one `recvmsg` over three buffers this function owns. Every pointer
        // below is derived from one of them, none outlives the closure, and the kernel
        // is told the exact size of each. This block is unavoidably unsafe end to end —
        // `msghdr` is a struct of raw pointers and there is no safe spelling of it — so
        // the containment is that it is short, it is the only one in this file, and
        // nothing above it ever sees a pointer: the decoder takes a bounds-checked
        // `Span`.
        unsafe buffer.withUnsafeMutableBytes { payload in
            unsafe control.withUnsafeMutableBytes { controlBytes in
                var iov = unsafe iovec(iov_base: payload.baseAddress, iov_len: payload.count)
                var message = unsafe msghdr()
                unsafe withUnsafeMutablePointer(to: &peer) {
                    unsafe message.msg_name = UnsafeMutableRawPointer($0)
                }
                unsafe message.msg_namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
                unsafe withUnsafeMutablePointer(to: &iov) { unsafe message.msg_iov = $0 }
                unsafe message.msg_iovlen = 1
                unsafe message.msg_control = controlBytes.baseAddress
                unsafe message.msg_controllen = socklen_t(controlBytes.count)

                let count = unsafe recvmsg(fd, &message, 0)
                guard count > 0 else { return }
                received = count
                ttl = unsafe ControlMessages.receivedTTL(&message)
            }
        }

        guard received > 0 else { return .drained }
        guard let source = ipv4(from: peer) else { return .datagram(nil) }
        // Decoding happens outside the pointer closures over a bounds-checked `Span`,
        // so the parser itself never sees a pointer.
        return .datagram(ICMPReplyDecoder.decode(
            buffer.span.extracting(0..<received),
            source: source, controlTTL: ttl, receivedAt: receivedAt
        ))
    }
}

/// One probe: where it goes, what the wire says, and what identifies it.
struct ProbeAssignment: Sendable {
    /// The host to probe.
    var address: IPv4Address
    /// The wire sequence field. Informational.
    var sequence: UInt16
    /// The identifier the reply is matched on. See `ICMPEcho.request(sequence:token:)`.
    var token: UInt32
}

/// Walking the control-message list by hand.
///
/// `CMSG_FIRSTHDR`, `CMSG_NXTHDR` and `CMSG_DATA` are function-like C macros over
/// `sizeof(struct cmsghdr)` and a 32-bit alignment round-up. ClangImporter cannot
/// import a function-like macro, so to Swift they simply do not exist — this is the
/// same class of problem as the `BIOC*` ioctl request macros, and it has the same
/// containment: reimplement the arithmetic once, in one place, tested, and let nothing
/// above it know.
///
/// The arithmetic, from `<sys/socket.h>`:
///
///     ALIGN32(n)        = (n + 3) & ~3
///     CMSG_FIRSTHDR(m)  = msg_controllen >= sizeof(cmsghdr) ? msg_control : NULL
///     CMSG_DATA(c)      = (unsigned char *)c + ALIGN32(sizeof(cmsghdr))
///     CMSG_NXTHDR(m, c) = c + ALIGN32(c->cmsg_len), or NULL past the end
enum ControlMessages {
    /// Darwin's 32-bit control-message alignment.
    static func align32(_ value: Int) -> Int { (value + 3) & ~3 }

    /// The received IP TTL, if the kernel attached one.
    ///
    /// Returns nil rather than a default when absent. A missing TTL means *not
    /// observed*, and inventing 64 would put a confident OS hint in the report that
    /// nothing on the wire supported.
    static func receivedTTL(_ message: inout msghdr) -> UInt8? {
        let headerSize = MemoryLayout<cmsghdr>.size
        guard Int(unsafe message.msg_controllen) >= headerSize else { return nil }
        // SAFETY: walking the control buffer the caller allocated, bounded by the
        // msg_controllen the kernel wrote back. Every read is checked against that
        // bound before it happens, and `cmsg_len` is validated so a hostile or
        // corrupted value cannot advance the cursor backwards or past the end.
        guard let base = unsafe message.msg_control else { return nil }
        let total = Int(unsafe message.msg_controllen)
        var offset = 0
        while offset + headerSize <= total {
            let header = unsafe base.loadUnaligned(fromByteOffset: offset, as: cmsghdr.self)
            let length = Int(header.cmsg_len)
            guard length >= headerSize, offset + length <= total else { break }
            if header.cmsg_level == IPPROTO_IP, header.cmsg_type == IP_RECVTTL {
                let dataOffset = offset + align32(headerSize)
                guard dataOffset + 1 <= total else { return nil }
                return unsafe base.loadUnaligned(fromByteOffset: dataOffset, as: UInt8.self)
            }
            offset += align32(length)
        }
        return nil
    }
}

#endif
