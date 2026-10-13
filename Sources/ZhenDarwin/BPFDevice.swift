// BPFDevice.swift — the descriptor, and everything that has to be true before a frame
// goes out of it.
//
// ── Selection is by attempt, never by geteuid() ──────────────────────────────────
//
// Asking whether we are root answers the wrong question. `/dev/bpf*` nodes are
// exclusive-open and Wireshark, tcpdump, a VPN client or Little Snitch may be holding
// every one of them, so root without a free device has exactly the capability a normal
// user has. And the inverse exists too: a machine with a ChmodBPF-style daemon hands
// the group read access, and a `geteuid()` check would refuse a device that would have
// opened. `open()` is the only honest test, and it is also cheap.
//
// So this type has no `isPrivileged` and takes no opinion. It opens, or it says which
// of the two reasons it could not, and the engine above turns that into a `Degradation`
// and falls back. Nothing hard-fails.
//
// ── The order of the ioctls matters and is not documented anywhere obvious ───────
//
//   BIOCSBLEN before BIOCSETIF — the buffer is sized when the device is bound, and a
//     length set afterwards is refused with EINVAL.
//   BIOCGBLEN after — the kernel clamps what it was asked for, and a read into a
//     buffer smaller than the device's own is refused with EINVAL every time, which
//     reads as a device that never delivers anything.
//   BIOCIMMEDIATE, or replies sit in the kernel until the buffer fills. On a segment
//     whose only traffic is the ten ARP replies we asked for, that is never, and the
//     sweep waits out its whole budget having already been answered.
//   BIOCSHDRCMPLT, because this engine builds the entire Ethernet header including the
//     source address. Without it the kernel overwrites that field, which happens to be
//     harmless here — the address it writes is the same one — and would stop being
//     harmless the moment anything wanted to send as something else.
//   BIOCSSEESENT off, so a read does not return our own 254 requests. Left on, the
//     reader spends the sweep parsing frames it sent.
//   BIOCSETF last, so nothing arrives unfiltered between binding and filtering.
//   BIOCFLUSH after that, to drop whatever the device buffered while being set up.
//
// Promiscuous mode is deliberately not requested. An ARP reply to our own request is
// unicast to our own hardware address, so there is nothing to gain — and a segment's
// entire traffic to read, parse and discard if we asked for it.
#if canImport(Darwin)

import CBPFShim
import Darwin
import Dispatch
import ZhenCore
import ZhenPrivilege


/// One `/dev/bpf*` device, bound to one interface, owned by one actor.
///
/// The descriptor never leaves this type. It is not `Sendable`, it is not returned, and
/// the only things that cross the boundary are `[UInt8]` frames going out and
/// `ARPFrame.Message` values coming back.
actor BPFDevice {
    private let executor = DedicatedExecutor(label: "com.jctec.zhen.bpf")

    /// Routes this actor's work to its own queue rather than the cooperative pool, for
    /// the reason `ICMPSocket` gives: a reply that waits behind a report encode is
    /// measured as network latency.
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        unsafe executor.asUnownedSerialExecutor()
    }

    /// How many `/dev/bpf*` nodes to try before giving up.
    ///
    /// macOS creates them on demand — opening the highest existing one makes the next
    /// appear — so this is a ceiling rather than a count, and ENOENT ends the walk
    /// before it is reached on a machine that has fewer.
    static let deviceCeiling = 256

    /// What to ask for with BIOCSBLEN.
    ///
    /// A request, not a size: the kernel clamps it and `BIOCGBLEN` reports what it
    /// actually gets, which is the number every read is sized from. 256 KiB is enough
    /// that a whole /24 answering at once fits in one wake-up.
    static let requestedBufferBytes: Int32 = 256 * 1024

    private let fd: Int32
    /// The buffer length the kernel granted. **Every read must be exactly this long**
    /// — a BPF read into a shorter buffer fails with EINVAL rather than returning less.
    private let bufferLength: Int
    /// Which node this is, for the record.
    ///
    /// `nonisolated` because it is immutable and `Sendable`: a caller asking which
    /// device it got should not have to suspend to find out.
    nonisolated let devicePath: String
    /// The interface it is bound to.
    nonisolated let interfaceName: String

    private var source: DispatchSourceRead?
    private var continuation: AsyncStream<[UInt8]>.Continuation?
    private var sourceOwnsDescriptor = false

    private init(fd: Int32, bufferLength: Int, devicePath: String, interfaceName: String) {
        self.fd = fd
        self.bufferLength = bufferLength
        self.devicePath = devicePath
        self.interfaceName = interfaceName
    }

    deinit {
        if let source {
            // The cancel handler closes it; cancellation is asynchronous and the
            // descriptor stays valid until it runs.
            source.cancel()
        } else if !sourceOwnsDescriptor {
            _ = Darwin.close(fd)
        }
    }

    // MARK: - Opening

    /// Opens the first free device and binds it to `interface`.
    ///
    /// The walk and the ioctl sequence live in `ZhenPrivilege` now, because the
    /// privileged helper performs exactly the same acquisition as root and a second
    /// copy would drift the first time one was corrected. What stays here is the part
    /// that is about this type: wrapping a configured descriptor in the actor that owns
    /// its lifetime.
    static func open(
        interface: String, filter: [bpf_insn] = BPFFilter.arp()
    ) throws(BPFUnavailable) -> BPFDevice {
        let acquired = try BPFAcquisition.open(interface: interface, filter: filter)
        return BPFDevice(
            fd: acquired.descriptor, bufferLength: acquired.bufferLength,
            devicePath: acquired.devicePath, interfaceName: interface
        )
    }

    /// Wraps a descriptor that was opened somewhere else.
    ///
    /// The seam the whole helper design rests on. `init` never cared where `fd` came
    /// from, and this is the second way to reach it: a descriptor the privileged helper
    /// opened, configured and passed back over XPC. Everything downstream — the ARP
    /// sweep, the SYN scan, the fingerprint probe — reads and writes it exactly as it
    /// reads and writes one opened in this process, and none of them can tell.
    static func adopting(_ acquired: AcquiredDevice, interface: String) -> BPFDevice {
        BPFDevice(
            fd: acquired.descriptor, bufferLength: acquired.bufferLength,
            devicePath: acquired.devicePath, interfaceName: interface
        )
    }

    /// Asks the privileged helper for a device.
    ///
    /// The rung above a direct open. It exists so an app the user never launched with
    /// `sudo` can still put ARP on the wire, and it fails the same way every other rung
    /// does — by returning why, so the caller can try the next one.
    static func openViaHelper(
        interface: String, filter: [bpf_insn] = BPFFilter.arp(),
        timeout: Duration = HelperClient.acquisitionTimeout
    ) async throws(BPFUnavailable) -> BPFDevice {
        let acquired = try await HelperClient.openCaptureDevice(
            interface: interface, filter: filter.portable, timeout: timeout
        )
        return adopting(acquired, interface: interface)
    }

    /// Whether a device can be opened and bound to `interface`, right now.
    ///
    /// Opens one and closes it again. That is a real attempt and not a guess: it is the
    /// only way to learn that `/dev/bpf*` is readable, that a node is free and that the
    /// interface is Ethernet, and `geteuid()` answers none of the three — root with
    /// every node held by Wireshark has exactly the capability a normal user has, and a
    /// machine with a ChmodBPF-style daemon gives a normal user the capability root
    /// would have.
    ///
    /// The device is closed rather than kept because the composition root runs long
    /// before the sweep does, and holding an exclusive-open node across a naming stage
    /// would lock out the very packet capture a person is running to check this engine's
    /// work. The cost is a race — another process can take the last node in between —
    /// and that race lands on the sweep's own fallback path, which exists anyway and
    /// records a recoverable degradation when it fires.
    ///
    /// - Returns: nil when a device opened, or why it did not.
    static func probe(interface: String) -> BPFUnavailable? {
        do {
            // Opened and dropped. No read source was ever armed, so `deinit` is what
            // closes the descriptor — which is the branch `sourceOwnsDescriptor` guards
            // and the reason that flag exists. Handing it to a `Task` to call `stop()`
            // would only retain it for longer and close nothing, because `stop()` with
            // no source has nothing to cancel.
            _ = try open(interface: interface)
            return nil
        } catch {
            return error
        }
    }

    // MARK: - Receiving

    /// Starts the reader and returns captured frames as they arrive.
    ///
    /// Frames rather than parsed messages, because two engines read this device and
    /// they decode different protocols. Each frame is copied out of the shared read
    /// buffer, which is what lets it cross to the consumer at all — the buffer is
    /// reused on the next wake-up, and a `Span` into it could not outlive the handler.
    /// The copies are small and there are as many of them as there were replies.
    ///
    /// `.bufferingNewest` for the reason every stream in this package declares one: the
    /// scan drains this as fast as it fills, and a consumer four thousand frames behind
    /// has a different problem from the one dropping the oldest would solve.
    func frames() -> AsyncStream<[UInt8]> {
        let (stream, continuation) = AsyncStream<[UInt8]>.makeStream(
            bufferingPolicy: .bufferingNewest(4096)
        )
        self.continuation = continuation

        let readSource = DispatchSource.makeReadSource(
            fileDescriptor: fd, queue: ReadinessQueue.shared
        )
        let descriptor = fd
        let length = bufferLength
        // One buffer for the life of the source rather than one per wake-up. The
        // handler is serialised on the readiness queue, so there is exactly one reader
        // and no sharing to guard.
        let scratch = ReadScratch(length: length)

        readSource.setEventHandler {
            // Drain until the device is empty, not until the first read. With
            // BIOCIMMEDIATE a wake-up can carry one record or two hundred, and stopping
            // after one read leaves the rest queued until traffic happens to arrive
            // again — which on a segment whose only traffic is the replies we are
            // waiting for is the definition of never.
            while true {
                let count = scratch.read(from: descriptor)
                guard count > 0 else { return }
                for frame in scratch.frames(upTo: count) {
                    continuation.yield(frame)
                }
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

    /// Stops delivery and closes the descriptor.
    ///
    /// Returns before the descriptor is actually gone: the close happens in the cancel
    /// handler, because `DispatchSource.cancel()` is asynchronous and closing here
    /// would be a use-after-close the moment another probe was handed the number.
    func stop() {
        if let source {
            source.cancel()
            self.source = nil
            continuation = nil
        } else {
            continuation?.finish()
            continuation = nil
        }
    }

    // MARK: - Sending

    /// Writes a round of frames, in order.
    ///
    /// One actor hop for the whole round rather than one per frame, for the reason
    /// `ICMPSocket.sendRound` gives: on a /24 the crossings cost more than the sends.
    ///
    /// Frames rather than addresses, because the ARP sweep and the SYN scan build
    /// different ones and the device's business is putting bytes on the wire.
    ///
    /// - Returns: how many frames reached the kernel, counting from the front. Writing
    ///   stops at the first refusal that is not transient, so the count is a prefix and
    ///   the caller can mark exactly those probes as sent — a frame that was never
    ///   written is not a probe that went unanswered.
    func send(_ frames: [[UInt8]]) async -> Int {
        var delivered = 0
        for frame in frames {
            if Task.isCancelled { break }
            guard write(frame) else { break }
            delivered += 1
        }
        return delivered
    }

    /// Writes one frame, retrying the transient refusals.
    ///
    /// `ENOBUFS` is the normal answer to handing a driver 254 frames in a tight loop
    /// and means "not yet", not "no". Counting it as a failed probe would report a
    /// chunk of the network absent, which is the bug `ICMPSocket.send` already has a
    /// paragraph about.
    private func write(_ frame: [UInt8]) -> Bool {
        for _ in 0..<8 {
            // SAFETY: a borrowed view of an array this scope owns, handed to `write`
            // for the duration of the call.
            let written = unsafe frame.withUnsafeBytes { bytes -> Int in
                unsafe Darwin.write(fd, bytes.baseAddress, bytes.count)
            }
            if written == frame.count { return true }
            guard errno == ENOBUFS || errno == EAGAIN else { return false }
            // A microsecond-scale wait. `Task.sleep` is around a millisecond and would
            // cost seconds across a sweep, and a fresh kqueue registration per refused
            // frame costs more than the frame did.
            sched_yield()
        }
        return false
    }
}

/// The reader's buffer and the parse that follows a read.
///
/// A class so the read source's handler can own one for its lifetime. It is touched
/// only from the serial readiness queue, which is what makes that safe without a lock,
/// and it is `@unchecked Sendable` on exactly that promise.
private final class ReadScratch: @unchecked Sendable {
    private var storage: [UInt8]

    init(length: Int) {
        self.storage = [UInt8](repeating: 0, count: length)
    }

    /// One `read`, into the whole buffer.
    ///
    /// **The length must be the device's own buffer length.** A BPF read into anything
    /// shorter fails with EINVAL rather than returning fewer bytes, which presents as a
    /// device that never delivers a single frame.
    func read(from fd: Int32) -> Int {
        // SAFETY: `read` writes at most `count` bytes into storage this object owns,
        // and the pointer does not escape the call.
        let count = unsafe storage.withUnsafeMutableBytes { raw -> Int in
            unsafe Darwin.read(fd, raw.baseAddress, raw.count)
        }
        return count > 0 ? count : 0
    }

    /// The captured frames in the first `count` bytes of the buffer.
    ///
    /// The buffer is bound to a local `let` first. A `Span` borrowed straight from a
    /// mutable stored property has no scope the compiler can prove it stays inside —
    /// "lifetime-dependent variable escapes its scope" — and the local binding is what
    /// gives it one. Arrays are copy-on-write, so this is a retain and not a copy.
    func frames(upTo count: Int) -> [[UInt8]] {
        let buffer = storage
        let bytes = buffer.span
        let usable = bytes.extracting(0..<min(count, bytes.count))
        var found: [[UInt8]] = []
        for record in BPFBuffer.records(in: usable) {
            // A truncated capture cannot be trusted to hold a whole payload, and a
            // partial one parsed as whole invents a host or a port verdict. The snap
            // length is above the frame ceiling, so this should not happen; it is
            // checked because "should not" is not a guarantee.
            guard !record.isTruncated else { continue }
            let packet = usable.extracting(record.packet)
            var copy = [UInt8](repeating: 0, count: packet.count)
            for index in 0..<packet.count { copy[index] = packet[index] }
            found.append(copy)
        }
        return found
    }
}

#endif
