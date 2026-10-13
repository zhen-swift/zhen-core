// main.swift — the privileged helper, which opens one kind of thing and nothing else.
//
// ── What runs as root, in full ─────────────────────────────────────────────────
//
// An `NSXPCListener` on a Mach service, and for each connection that satisfies a
// code-signing requirement, one `open("/dev/bpfN")` followed by the ioctl sequence in
// `BPFAcquisition`. The descriptor goes back to the caller and this process forgets it.
//
// There is no scanning here, no parsing, no network client, no file the daemon writes.
// `Docs/04-privileged-helper.md` weighed keeping the descriptor here and running the
// sweep as root instead, which would be a stronger privilege boundary and a very much
// larger root process — three engines, a TLS client and a Bonjour browser. This is the
// smaller of the two and the one whose entire behaviour fits on a page.
//
// ── The check that makes the small version defensible ──────────────────────────
//
// Darwin has no `BIOCLOCK`. A capture descriptor handed to another process can be
// re-filtered by that process, so what crosses this connection is not "the ARP sweep's
// device", it is promiscuous capture of the whole segment, permanently, for whoever is
// on the other end. The design document was explicit that this shape is acceptable only
// with a strict code-signing requirement on the client checked per connection.
//
// `setCodeSigningRequirement` is that check and it is not optional. A connection that
// does not satisfy it is rejected in `listener(_:shouldAcceptNewConnection:)` before an
// interface name is ever read.
//
// ── Why there is no timeout, retry or state ────────────────────────────────────
//
// `launchd` owns the lifetime. The daemon is demand-launched by a connection to its
// Mach service and can be killed at any moment without losing anything, because it holds
// nothing between calls. That is deliberate: a root process with no state cannot have
// its state corrupted.
// Everything below is Apple-only: an `NSXPCListener` on a Mach service, `/dev/bpf`, and
// a code-signing requirement. There is no portable version of this daemon and there is
// not meant to be — `SMAppService` has no counterpart, and the Linux plan replaces the
// mechanism entirely with `CAP_NET_RAW` on the `zhen` binary and no helper at all.
//
// An executable target always compiles, so this cannot be dropped from the manifest, and
// `main.swift` must produce top-level code or the link fails with no entry point. Hence
// the `#else` at the bottom: on Linux this builds to a binary that says what it is and
// exits 69, the same `EX_UNAVAILABLE` the command line uses when the platform has no
// engine for it.
#if canImport(Darwin)
import Darwin
import Foundation
import ZhenPrivilege

/// The object vended on each accepted connection.
///
/// One instance per connection rather than a shared one, so nothing can leak between
/// callers even by accident — there is nothing to leak, and keeping it that way is
/// cheaper than checking later.
final class HelperService: NSObject, ZhenHelperProtocol, @unchecked Sendable {
    func openCaptureDevice(
        interface: String,
        filter: Data,
        reply: @escaping (FileHandle?, Int, String?) -> Void
    ) {
        // The interface name is the only attacker-controlled value that reaches a
        // syscall here, and `BPFAcquisition.bind` bounds it against IFNAMSIZ before it
        // reaches `ioctl`. Checked again at this boundary because a length check living
        // only in a library is one refactor away from not running.
        guard !interface.isEmpty, interface.utf8.count < 16,
              interface.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." }) else {
            reply(nil, 0, "'\(interface)' is not a plausible interface name")
            return
        }
        guard let program = BPFFilterCoding.decode(filter) else {
            reply(nil, 0, "the filter was not a whole number of BPF instructions")
            return
        }
        // A filter is required. Without one the device delivers every frame on the
        // segment, and a caller that asked for that by omission rather than on purpose
        // should be told rather than served.
        guard !program.isEmpty else {
            reply(nil, 0, "an empty filter would capture the entire segment")
            return
        }

        do {
            let device = try BPFAcquisition.open(
                interface: interface, filter: program.instructions
            )
            // `closeOnDealloc: true` — this process is done with the descriptor the
            // moment the reply is sent, and XPC duplicates it across the boundary. The
            // caller's copy is unaffected by this one closing.
            let handle = FileHandle(fileDescriptor: device.descriptor, closeOnDealloc: true)
            reply(handle, device.bufferLength, nil)
        } catch {
            // The reason, not the error. The caller puts this in a degradation a person
            // reads, and `BPFUnavailable.reason` is written for exactly that.
            reply(nil, 0, error.reason)
        }
    }

    func helperVersion(reply: @escaping (String) -> Void) {
        reply(HelperBuild.version)
    }
}

/// Accepts connections that prove who they are, and refuses the rest.
final class HelperDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    func listener(
        _ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: ZhenHelperProtocol.self)
        connection.exportedObject = HelperService()
        // The whole security argument, in one call. Anything that is not the app,
        // signed by this team, never reaches `openCaptureDevice`.
        if #available(macOS 13.0, *) {
            connection.setCodeSigningRequirement(CodeRequirement.client)
        } else {
            // There is no supported fallback that is worth having. An unverified client
            // is handed permanent promiscuous capture, so refusing is the only honest
            // answer on a system too old to check.
            return false
        }
        connection.resume()
        return true
    }
}

/// What this build is, so a stale helper left by an older install can say so.
enum HelperBuild {
    static let version = "0.7.0"
}

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: HelperIdentity.label)
listener.delegate = delegate
listener.resume()
// Never returns. `launchd` starts this on demand and stops it when it is idle; there is
// no state to write out on the way down.
RunLoop.main.run()

#else

import Foundation

// Not an error path worth a type: this binary has exactly one thing to say.
let explanation = """
zhen-helper: this daemon is Apple-only, and there is no portable equivalent.

It exists to open /dev/bpf as root and hand the descriptor back over XPC, registered
through SMAppService. On Linux the privileged path is CAP_NET_RAW on the zhen binary
itself, so there is no helper to install and nothing for this process to do.

See Docs/DIRECTION.md, the section on portability.
"""

FileHandle.standardError.write(Data(explanation.utf8))
exit(69)  // EX_UNAVAILABLE

#endif
