// HelperProtocol.swift — the entire surface the privileged helper exposes.
//
// ── One method, on purpose ─────────────────────────────────────────────────────
//
// `Docs/04-privileged-helper.md` weighed two shapes: hand the descriptor to the client,
// or keep it in the helper and run the sweep there. This is the first. The helper opens
// a capture device, configures it and passes the descriptor back; the sweep, the SYN
// scan and the fingerprint probe all run unprivileged in the app, exactly as they do
// under `sudo` today, and none of them learns a helper exists.
//
// The privileged surface is therefore one `open` and a handful of ioctls, which is
// small enough to read in a sitting. The alternative put a TLS client and a port
// scanner inside a root daemon.
//
// ── What the design document said this costs, and why it is still the right shape ─
//
// Darwin has no `BIOCLOCK`. FreeBSD can freeze a capture descriptor before handing it
// over, so the receiver only ever sees the traffic the helper chose; the ioctl list in
// `net/bpf.h` ends at `BIOCSETFNR` and there is no equivalent. So a descriptor that
// crosses this connection is a permanent grant of promiscuous capture to whatever is on
// the other end, and it can re-filter at will.
//
// That is exactly why `ClientRequirement` below is not optional and is checked on every
// connection rather than once at startup. The design document said this shape is
// "acceptable only with a strict code-signing requirement on the client, checked per
// connection — and a signing requirement is exactly the thing that is missing today".
// It is not missing now, and it is the thing that makes the small helper defensible.
//
// Since the client can re-filter anyway, letting it SEND the filter it wants costs no
// security and saves the helper from knowing what a sweep is.
#if canImport(Darwin)

import Foundation

/// Names the two processes have to agree on, in one place.
///
/// A launch daemon whose label, Mach service and plist filename disagree fails with
/// `SMAppService` error 108, "unable to read plist" — which names the wrong thing and
/// sends people to check their XML. Declaring them once removes the whole class.
public enum HelperIdentity {
    /// The daemon's label, its Mach service name, and the stem of its plist filename.
    ///
    /// Deliberately readable. A person looking at Login Items or at Activity Monitor
    /// should see something that plainly belongs to this app, not an opaque reverse-DNS
    /// string they have to search for before they can decide whether to trust it.
    public static let label = "com.jctec.zhen.helper"

    /// The app that owns it. `AssociatedBundleIdentifiers` in the daemon plist points
    /// here, and that key is what makes Login Items show the app's name and icon
    /// instead of the bare label.
    public static let applicationBundleIdentifier = "com.jctec.zhen"

    /// The filename `SMAppService.daemon(plistName:)` is given.
    public static var plistName: String { "\(label).plist" }

    /// Where that file lives inside the app bundle.
    public static var plistBundlePath: String { "Contents/Library/LaunchDaemons/\(plistName)" }
}

/// The code-signing requirements each side demands of the other.
///
/// Both directions, because both matter and for different reasons. The helper checks
/// the client because handing a capture descriptor to an unverified process is handing
/// it promiscuous capture. The client checks the helper because a descriptor arriving
/// from something that is not our daemon is a descriptor from something that wants us
/// to read its choice of traffic.
public enum CodeRequirement {
    /// The Team ID both binaries are signed with.
    ///
    /// `SMAppService` enforces that the app and its daemon match; this is here so the
    /// requirement strings can be written once, and so the build can check it rather
    /// than leaving the first mismatch to be discovered at a user's first launch.
    public static let teamIdentifier = "S8662L649U"

    /// What the helper demands of anything that connects to it.
    public static let client = """
        identifier "\(HelperIdentity.applicationBundleIdentifier)" \
        and anchor apple generic \
        and certificate leaf[subject.OU] = "\(teamIdentifier)"
        """

    /// What the client demands of the helper.
    public static let helper = """
        identifier "\(HelperIdentity.label)" \
        and anchor apple generic \
        and certificate leaf[subject.OU] = "\(teamIdentifier)"
        """
}

/// The helper's whole interface.
///
/// `@objc` because this crosses `NSXPCConnection`, which is Objective-C runtime
/// machinery. The reply blocks are the NSXPC convention: a method returns by calling
/// its block, once, on the connection's queue.
@objc public protocol ZhenHelperProtocol {
    /// Opens a capture device on `interface`, applies `filter`, and returns it.
    ///
    /// - Parameters:
    ///   - interface: the BSD name, for example `en0`.
    ///   - filter: a packed array of `bpf_insn`, eight bytes each, in the layout
    ///     `BPFFilterCoding` writes. The client chooses it because the client is the
    ///     one that knows whether it is sweeping ARP or watching for a SYN-ACK, and
    ///     because it could set its own filter after receiving the descriptor anyway.
    ///   - reply: the descriptor as a `FileHandle`, the buffer length the kernel
    ///     granted, and a reason when there is no descriptor. `NSFileHandle` is one of
    ///     the types `NSXPCConnection` transfers by passing the underlying descriptor
    ///     rather than by copying bytes, which is the whole mechanism this depends on.
    func openCaptureDevice(
        interface: String,
        filter: Data,
        reply: @escaping (FileHandle?, Int, String?) -> Void
    )

    /// What the helper is, for the app to show and for a mismatch to be visible.
    ///
    /// A helper left behind by an older install answers this with an older version, and
    /// an app that can see that can say so instead of failing in a way nobody can read.
    func helperVersion(reply: @escaping (String) -> Void)
}

/// Packing a BPF program into bytes and back.
///
/// `bpf_insn` is `{ u_short code; u_char jt; u_char jf; u_int k; }` — eight bytes with
/// no padding on every platform this runs on. Written out field by field rather than by
/// copying the struct's memory, so the wire layout is a decision in this file instead of
/// whatever the compiler happened to lay out.
public enum BPFFilterCoding {
    /// The width of one instruction on the wire.
    public static let instructionWidth = 8

    /// Packs a program for the connection.
    public static func encode(_ program: [BPFInstruction]) -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(program.count * instructionWidth)
        for insn in program {
            bytes.append(UInt8(truncatingIfNeeded: insn.code))
            bytes.append(UInt8(truncatingIfNeeded: insn.code >> 8))
            bytes.append(insn.jt)
            bytes.append(insn.jf)
            for shift in stride(from: 0, to: 32, by: 8) {
                bytes.append(UInt8(truncatingIfNeeded: insn.k >> UInt32(shift)))
            }
        }
        return Data(bytes)
    }

    /// Unpacks a program, or nil when the length is not a whole number of instructions.
    ///
    /// Returning nil rather than truncating: a short read here would install a filter
    /// that is a prefix of the one asked for, which passes traffic the caller meant to
    /// exclude and does it silently.
    public static func decode(_ data: Data) -> [BPFInstruction]? {
        guard !data.isEmpty, data.count % instructionWidth == 0 else { return nil }
        let bytes = [UInt8](data)
        var program: [BPFInstruction] = []
        program.reserveCapacity(bytes.count / instructionWidth)
        for base in stride(from: 0, to: bytes.count, by: instructionWidth) {
            let code = UInt16(bytes[base]) | (UInt16(bytes[base + 1]) << 8)
            var k: UInt32 = 0
            for offset in 0..<4 {
                k |= UInt32(bytes[base + 4 + offset]) << UInt32(offset * 8)
            }
            program.append(BPFInstruction(
                code: code, jt: bytes[base + 2], jf: bytes[base + 3], k: k
            ))
        }
        return program
    }
}

/// One classic BPF instruction, in a form that crosses a process boundary.
///
/// A plain value rather than Darwin's `bpf_insn`, so this file and the protocol above
/// do not drag the C import into every module that needs to name a filter.
public struct BPFInstruction: Sendable, Hashable {
    /// The opcode.
    public var code: UInt16
    /// Branch taken when the test passes, as a count of instructions to skip.
    public var jt: UInt8
    /// Branch taken when it fails.
    public var jf: UInt8
    /// The operand.
    public var k: UInt32

    /// Creates an instruction.
    public init(code: UInt16, jt: UInt8, jf: UInt8, k: UInt32) {
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k
    }
}

#endif
