// DarwinPlatform.swift — the syscall floor: descriptors, errno, resource limits.
//
// Everything in this target is wrapped in `#if canImport(Darwin)`. That is not the
// conditional the design rules forbid: the rule is that no conditional appears inside
// a public type in core or inside command code. Here the whole target *is* the
// platform layer, and the guard exists so a Linux build yields an empty module rather
// than a failure while a ZhenLinux target is written beside it.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// Closes a descriptor with `Darwin.close`.
///
/// This is the whole reason `OwnedDescriptor` takes a static policy rather than a
/// stored closure: the syscall cannot be named in core, and a stored closure would
/// cost a heap allocation per descriptor across tens of thousands of probes.
public enum DarwinDescriptorPolicy: DescriptorPolicy {
    /// Closes the descriptor.
    public static func close(_ raw: Int32) {
        // Not an `unsafe` expression as far as the compiler is concerned — no pointer
        // crosses this call — but the ownership hazard is real: between two closes
        // another thread can open a socket and be handed the same number, and the
        // second close then tears down an unrelated connection. `OwnedDescriptor`
        // guarantees the single owner that makes this safe.
        _ = Darwin.close(raw)
    }
}

/// A uniquely owned Darwin file descriptor.
///
/// Used for the short-lived descriptors — one per TCP connect probe, tens of thousands
/// per deep scan — where the ownership question is real and a leak exhausts the process
/// limit rather than merely wasting memory. Long-lived sockets (the single ICMP socket)
/// hold a raw `Int32` inside an actor instead, because a class cannot consume a stored
/// property and the ceremony would buy nothing for a descriptor with one obvious owner
/// and a `deinit`.
public typealias DarwinDescriptor = OwnedDescriptor<DarwinDescriptorPolicy>

extension PlatformError {
    /// Wraps the current `errno` for a named syscall.
    static func syscall(_ api: String) -> PlatformError {
        // Read immediately after the failed call, before anything else can clobber it.
        let code = errno
        switch code {
        case EPERM, EACCES:
            return .denied("\(api) was refused (errno \(code))")
        case ENOENT, ENXIO, ENODEV:
            return .notFound("\(api) found nothing (errno \(code))")
        default:
            return .systemError(code: code, api: api)
        }
    }
}

/// Raises the descriptor limit and reports what the kernel actually granted.
public struct DarwinResourceLimits: ResourceLimits {
    /// Creates the provider.
    public init() {}

    /// Raises `RLIMIT_NOFILE` as far as the kernel will actually allow, and returns what
    /// was granted.
    ///
    /// Returns the granted value rather than a success flag because that value is what
    /// concurrency is derived from — never a constant.
    ///
    /// Two things make the obvious implementation wrong, and this machine demonstrates
    /// the second one rather than the first:
    ///
    /// Asking for `rlim_max` can be refused outright with `EINVAL` when the hard limit
    /// is `RLIM_INFINITY`, on which the raise silently never happens and the pool runs
    /// at whatever the 256-descriptor default derives to. (Not reproduced here — this
    /// kernel accepts it — but the retry below costs nothing and removes the failure
    /// mode on kernels that do not.)
    ///
    /// And `RLIMIT_NOFILE` is not the real ceiling anyway. `kern.maxfilesperproc` is,
    /// and on this machine the two disagree by an order of magnitude: the hard limit
    /// reports 9,223,372,036,854,775,807 while the kernel will not hand out more than
    /// 92,160 descriptors to one process. Deriving a concurrency window from the former
    /// produces a number no descriptor table could satisfy, which is exactly the class
    /// of bug that "derive it from what was granted" was supposed to prevent — so the
    /// request is clamped to the sysctl and then walked downward until one sticks.
    public func raiseDescriptorLimit() -> Int {
        var limits = rlimit()
        // SAFETY: getrlimit writes into a struct we own and fully initialized.
        guard unsafe getrlimit(RLIMIT_NOFILE, &limits) == 0 else { return 256 }

        let ceiling = Self.perProcessCeiling()
        var wanted = min(Self.clamp(limits.rlim_max), ceiling)
        // Walk down rather than give up. A refusal at one value says nothing about the
        // next, and halving converges in a handful of syscalls.
        while wanted > Self.clamp(limits.rlim_cur) {
            var attempt = limits
            attempt.rlim_cur = rlim_t(wanted)
            if unsafe setrlimit(RLIMIT_NOFILE, &attempt) == 0 { break }
            wanted /= 2
        }
        _ = unsafe getrlimit(RLIMIT_NOFILE, &limits)
        // Report the effective limit, which is the SMALLER of the soft limit and what
        // the kernel will actually issue. A soft limit above `kern.maxfilesperproc` is
        // a promise the kernel will not keep.
        return min(Self.clamp(limits.rlim_cur), ceiling)
    }

    /// The kernel's hard per-process descriptor ceiling.
    ///
    /// Falls back to the granted soft limit's own clamp when the sysctl is unavailable,
    /// which is the conservative direction: under-reporting costs a smaller scan,
    /// over-reporting costs a scan that fails partway through with EMFILE.
    static func perProcessCeiling() -> Int {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        // SAFETY: sysctlbyname writes one Int32 into storage we own and sized.
        guard unsafe sysctlbyname("kern.maxfilesperproc", &value, &size, nil, 0) == 0,
              value > 0
        else { return 1_048_576 }
        return Int(value)
    }

    /// Folds an `rlim_t` into an `Int` without overflowing.
    ///
    /// `RLIM_INFINITY` is `UInt64.max` and this machine reports `Int64.max` for the hard
    /// limit. Converting either straight to `Int` traps or produces a window no
    /// descriptor table could satisfy.
    static func clamp(_ value: rlim_t) -> Int {
        value >= rlim_t(1_048_576) ? 1_048_576 : Int(value)
    }
}

/// Puts a descriptor into non-blocking mode.
///
/// Called on every descriptor this target opens, with no exceptions, and the reason is
/// the single most likely way this implementation goes wrong. `Task.cancel()` is
/// cooperative: a task blocked in `connect()` or `read()` does not unblock when
/// cancelled, and a task group will not return until its child does. The Swift
/// cooperative pool is sized to the core count, so a handful of blocked descriptors
/// does not slow the scanner down — it deadlocks it outright.
@discardableResult
func setNonBlocking(_ fd: Int32) -> Bool {
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0 else { return false }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
}

/// Builds a `sockaddr_in` for an address and port.
func socketAddress(_ address: IPv4Address, port: UInt16 = 0) -> sockaddr_in {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: address.raw.bigEndian)
    return addr
}

/// The socket family an address is reached over.
func socketFamily(_ address: IPAddress) -> Int32 {
    switch address {
    case .v4: AF_INET
    case .v6: AF_INET6
    }
}

/// Calls `body` with a socket address for either family, and its length.
///
/// The v6 half is `ICMPv6Socket.socketAddress` plus a port, deliberately: that is the one
/// place this target already builds a `sockaddr_in6`, zone included, and was checked
/// against a captured packet (D1). The zone is the part that bites — a link-local
/// destination without `sin6_scope_id` is unroutable on a machine with more than one
/// link, and the connect fails or leaves by the wrong interface.
func withSocketAddress<T>(
    _ address: IPAddress, port: UInt16,
    _ body: (UnsafePointer<sockaddr>, socklen_t) -> T
) -> T {
    switch address {
    case .v4(let v4):
        var storage = socketAddress(v4, port: port)
        // SAFETY: a sockaddr_in this scope owns, viewed as the sockaddr it begins with,
        // for the duration of the call only.
        return unsafe withUnsafePointer(to: &storage) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    case .v6(let v6):
        var storage = ICMPv6Socket.socketAddress(v6)
        storage.sin6_port = port.bigEndian
        // SAFETY: as above, for a sockaddr_in6.
        return unsafe withUnsafePointer(to: &storage) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                unsafe body($0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
    }
}

/// Reads the address out of a `sockaddr_storage` of either family, or nil for any other.
func ipAddress(from storage: sockaddr_storage) -> IPAddress? {
    if let v4 = ipv4(from: storage) { return .v4(v4) }
    guard storage.ss_family == sa_family_t(AF_INET6) else { return nil }
    // SAFETY: the same reinterpretation `ipv4(from:)` justifies, for the sockaddr_in6
    // the storage declares itself to be.
    let v6 = unsafe withUnsafeBytes(of: storage) { raw in
        unsafe raw.loadUnaligned(as: sockaddr_in6.self)
    }
    return ICMPv6Socket.address(v6).map(IPAddress.v6)
}

/// Reads a `sockaddr_in`'s address, or nil if it is not AF_INET.
func ipv4(from storage: sockaddr_storage) -> IPv4Address? {
    guard storage.ss_family == sa_family_t(AF_INET) else { return nil }
    // SAFETY: reinterpreting a sockaddr_storage as the sockaddr_in it declares itself
    // to be. sockaddr_storage exists precisely to be large enough and aligned for any
    // sockaddr, so this cast is the one the type was designed for — unlike the
    // variable-length sockaddr_dl in RouteMessages.swift, which is parsed by byte
    // offset for exactly that reason.
    let raw = unsafe withUnsafeBytes(of: storage) { bytes in
        unsafe bytes.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
    }
    return IPv4Address(raw: UInt32(bigEndian: raw))
}

#endif
