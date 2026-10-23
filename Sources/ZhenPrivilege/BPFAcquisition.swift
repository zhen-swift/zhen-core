// BPFAcquisition.swift — opening and configuring a capture device, and nothing else.
//
// ── Why this is its own target ─────────────────────────────────────────────────
//
// This code runs in two processes now. `BPFDevice` calls it in-process, the way it
// always has; the privileged helper calls it as root and passes the descriptor back
// over XPC. The alternative was to let the helper link `ZhenDarwin`, which would
// put a TLS client, a Bonjour browser and a whole port scanner inside a launch daemon
// running as root to perform one `open`. A root daemon should be small enough to read.
//
// The other alternative was a second copy of the ioctl sequence, which is worse. The
// order below is not documented anywhere obvious, every line of it was found by a
// device that silently delivered nothing, and two copies would drift the first time
// one was corrected.
//
// ── The order of the ioctls, which is the whole content of this file ────────────
//
//   BIOCSBLEN before BIOCSETIF — the buffer is sized when the device is bound, and a
//     length set afterwards is refused with EINVAL.
//   BIOCGBLEN after — the kernel clamps what it was asked for, and a read into a
//     buffer smaller than the device's own is refused with EINVAL every time, which
//     reads as a device that never delivers anything.
//   BIOCIMMEDIATE, or replies sit in the kernel until the buffer fills. On a segment
//     whose only traffic is the ten ARP replies we asked for, that is never.
//   BIOCSHDRCMPLT, because the sweep builds the entire Ethernet header itself.
//   BIOCSSEESENT off, so a read does not return our own requests.
//   BIOCSETF last, so nothing arrives unfiltered between binding and filtering.
//   BIOCFLUSH after that, to drop whatever the device buffered while being set up.
// macOS only. iOS has no `/dev/bpf*` and its SDK no `<net/bpf.h>`, so on iPadOS this
// layer is absent and the scanner composes without it (see `DarwinScanner.make`).
#if os(macOS)

import CBPFShim
import Darwin

/// Why a BPF device could not be opened or configured.
///
/// Carries the sentence a user reads, because the caller's job is to put it in a
/// degradation and the reason is the whole content of one.
public enum BPFUnavailable: Error, Sendable, Hashable {
    /// Every node refused with EACCES or EPERM. This is the "not root" case.
    case notPrivileged
    /// Nodes exist and every one is held by another process.
    case allDevicesBusy(tried: Int)
    /// An ioctl failed after the device opened.
    case configurationFailed(String)
    /// The interface is not Ethernet, so an ARP frame built for it would be nonsense.
    case notEthernet(dataLinkType: Int32)
    /// There is no helper to talk to: nothing is listening on the Mach service.
    ///
    /// Kept apart from `helperRefused` because this is the NORMAL state of this
    /// program, exactly as `notPrivileged` is. Most people will never install the
    /// helper, and a degradation on every scan saying so would train them to stop
    /// reading the degradation list — which is where the things that actually cost them
    /// results appear.
    case helperAbsent

    /// The helper answered, and refused. Carries what it said.
    ///
    /// Distinct from the others because it is the only one that happened in another
    /// process: the reason text came over a connection rather than from `errno` here.
    case helperRefused(String)

    /// What to tell the person running the scan.
    public var reason: String {
        switch self {
        case .notPrivileged:
            """
            No packet-capture device could be opened, so the layer-2 ARP sweep did not \
            run and hosts that answer only ARP will be missing. /dev/bpf* is root-only \
            on this machine; install the privileged helper, or re-run under sudo, to \
            include it.
            """
        case .allDevicesBusy(let tried):
            """
            All \(tried) packet-capture devices are in use by another process — \
            Wireshark, tcpdump, a VPN client and Little Snitch all hold one — so the \
            layer-2 ARP sweep did not run. The unprivileged sweep ran as normal.
            """
        case .configurationFailed(let detail):
            """
            A packet-capture device opened but could not be configured (\(detail)), so \
            the layer-2 ARP sweep did not run. The unprivileged sweep ran as normal.
            """
        case .notEthernet(let type):
            """
            The selected interface is not Ethernet (data-link type \(type)), so there \
            is no ARP to sweep on it. The unprivileged sweep ran as normal.
            """
        case .helperAbsent:
            """
            No packet-capture device could be opened, so the layer-2 ARP sweep did not \
            run and hosts that answer only ARP will be missing. Install the privileged \
            helper from Settings, or re-run under sudo, to include it.
            """
        case .helperRefused(let detail):
            """
            The privileged helper declined to open a capture device (\(detail)), so the \
            layer-2 ARP sweep did not run. The unprivileged sweep ran as normal.
            """
        }
    }
}

/// A configured descriptor, and what the kernel granted for it.
public struct AcquiredDevice: Sendable {
    /// The open file descriptor. The caller owns it and must close it.
    public var descriptor: Int32
    /// The buffer length the kernel granted. Every read is sized from this.
    public var bufferLength: Int
    /// Which node it came from, for the artifact and for diagnosis.
    public var devicePath: String

    /// Creates a value from its fields.
    public init(descriptor: Int32, bufferLength: Int, devicePath: String) {
        self.descriptor = descriptor
        self.bufferLength = bufferLength
        self.devicePath = devicePath
    }
}

/// Opening a `/dev/bpf*` node and putting it in the state a sweep needs.
public enum BPFAcquisition {
    /// How far up the `/dev/bpf*` walk goes before giving up.
    public static let deviceCeiling = 256
    /// What is asked for. The kernel clamps it and `BIOCGBLEN` says to what.
    public static let requestedBufferBytes: Int32 = 256 * 1024

    /// Opens the first free device and binds it to `interface`.
    ///
    /// Walks upward from `/dev/bpf0` rather than assuming zero is free, because on a
    /// developer's machine it frequently is not. EACCES on the first node ends the
    /// walk: every node has the same ownership, so 255 more `open` calls would return
    /// the same answer more slowly.
    public static func open(
        interface: String, filter: [bpf_insn]
    ) throws(BPFUnavailable) -> AcquiredDevice {
        var busy = 0

        for index in 0..<deviceCeiling {
            let path = "/dev/bpf\(index)"
            // SAFETY: `open` takes the C string Swift materialises for the literal
            // path; the pointer does not outlive the call.
            let descriptor = unsafe Darwin.open(path, O_RDWR)
            if descriptor < 0 {
                switch errno {
                case EACCES, EPERM:
                    throw BPFUnavailable.notPrivileged
                case EBUSY:
                    busy += 1
                    continue
                case ENOENT:
                    break
                default:
                    busy += 1
                    continue
                }
                break
            }

            do {
                let granted = try configure(descriptor, interface: interface, filter: filter)
                return AcquiredDevice(
                    descriptor: descriptor, bufferLength: granted, devicePath: path
                )
            } catch {
                _ = Darwin.close(descriptor)
                throw error
            }
        }

        throw BPFUnavailable.allDevicesBusy(tried: max(busy, 1))
    }

    /// Applies every setting the sweep depends on, in the order they have to happen in.
    ///
    /// - Returns: the buffer length the kernel granted, which every read is sized from.
    public static func configure(
        _ fd: Int32, interface: String, filter: [bpf_insn]
    ) throws(BPFUnavailable) -> Int {
        var requested = requestedBufferBytes
        _ = unsafe ioctl(fd, ns_bpf_sblen(), &requested)

        try bind(fd, to: interface)

        var granted: Int32 = 0
        guard unsafe ioctl(fd, ns_bpf_gblen(), &granted) == 0, granted > 0 else {
            throw BPFUnavailable.configurationFailed("BIOCGBLEN: \(errnoText())")
        }

        var dataLink: Int32 = 0
        guard unsafe ioctl(fd, ns_bpf_gdlt(), &dataLink) == 0 else {
            throw BPFUnavailable.configurationFailed("BIOCGDLT: \(errnoText())")
        }
        guard dataLink == DLT_EN10MB else {
            throw BPFUnavailable.notEthernet(dataLinkType: dataLink)
        }

        var immediate: Int32 = 1
        guard unsafe ioctl(fd, ns_bpf_immediate(), &immediate) == 0 else {
            throw BPFUnavailable.configurationFailed("BIOCIMMEDIATE: \(errnoText())")
        }

        var headerComplete: Int32 = 1
        guard unsafe ioctl(fd, ns_bpf_hdrcmplt(), &headerComplete) == 0 else {
            throw BPFUnavailable.configurationFailed("BIOCSHDRCMPLT: \(errnoText())")
        }

        // Best effort. Seeing our own sends is wasteful rather than wrong, and a
        // kernel that declines this should not cost the whole capability.
        var seeSent: Int32 = 0
        _ = unsafe ioctl(fd, ns_bpf_seesent(), &seeSent)

        try install(filter, on: fd)

        // Drop whatever arrived while the device was being set up, so the first read
        // does not return frames captured before the filter was installed.
        _ = unsafe ioctl(fd, ns_bpf_flush(), UnsafeMutableRawPointer(bitPattern: 0x1)!)

        guard nonBlocking(fd) else {
            throw BPFUnavailable.configurationFailed("fcntl(O_NONBLOCK): \(errnoText())")
        }
        return Int(granted)
    }

    /// `BIOCSETIF` with a `struct ifreq` carrying the interface name.
    ///
    /// The name goes at offset zero of a buffer sized by the C shim, rather than
    /// through Swift's import of `ifr_name` — which is a sixteen-element tuple and
    /// makes the obvious spelling of this unreadable.
    static func bind(_ fd: Int32, to interface: String) throws(BPFUnavailable) {
        let capacity = Int(ns_bpf_ifnamsiz())
        let name = Array(interface.utf8)
        guard !name.isEmpty, name.count < capacity else {
            throw BPFUnavailable.configurationFailed(
                "interface name '\(interface)' does not fit IFNAMSIZ"
            )
        }
        var request = [UInt8](repeating: 0, count: Int(ns_bpf_ifreq_size()))
        for (index, byte) in name.enumerated() { request[index] = byte }

        // SAFETY: `ioctl` writes nothing past `sizeof(struct ifreq)`, which is exactly
        // how the buffer was sized, and the pointer does not escape the call.
        let result = unsafe request.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return -1 }
            return unsafe ioctl(fd, ns_bpf_setif(), base)
        }
        guard result == 0 else {
            throw BPFUnavailable.configurationFailed("BIOCSETIF(\(interface)): \(errnoText())")
        }
    }

    /// Installs the filter the caller chose.
    ///
    /// Without one, every frame on the segment is copied into our buffer and parsed.
    /// On an idle home LAN that is a few hundred frames a second of other people's
    /// traffic; on a busy one it is the whole scan's budget spent discarding video.
    static func install(_ program: [bpf_insn], on fd: Int32) throws(BPFUnavailable) {
        var program = program

        // SAFETY: `bpf_program` holds a borrowed pointer to the instruction array. The
        // kernel copies the program during the ioctl and keeps nothing, so the pointer
        // only has to be valid for the duration of the call.
        let result = unsafe program.withUnsafeMutableBufferPointer { buffer -> Int32 in
            var filter = unsafe bpf_program(
                bf_len: u_int(buffer.count), bf_insns: buffer.baseAddress
            )
            return unsafe ioctl(fd, ns_bpf_setf(), &filter)
        }
        guard result == 0 else {
            throw BPFUnavailable.configurationFailed("BIOCSETF: \(errnoText())")
        }
    }

    /// Puts the descriptor in non-blocking mode.
    static func nonBlocking(_ fd: Int32) -> Bool {
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0 else { return false }
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
    }

    static func errnoText() -> String {
        String(cString: unsafe strerror(errno))
    }
}

// MARK: - Crossing between the wire form and Darwin's struct

extension BPFInstruction {
    /// Reads Darwin's struct into the portable form the connection carries.
    public init(_ insn: bpf_insn) {
        self.init(code: insn.code, jt: insn.jt, jf: insn.jf, k: insn.k)
    }

    /// The form `BIOCSETF` takes.
    public var instruction: bpf_insn {
        bpf_insn(code: code, jt: jt, jf: jf, k: k)
    }
}

extension Array where Element == BPFInstruction {
    /// The program, ready for `BPFAcquisition.install`.
    public var instructions: [bpf_insn] { map(\.instruction) }
}

extension Array where Element == bpf_insn {
    /// The program, ready for the connection.
    public var portable: [BPFInstruction] { map(BPFInstruction.init) }
}

#endif
