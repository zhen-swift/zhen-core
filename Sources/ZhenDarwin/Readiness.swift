// Readiness.swift — kqueue readiness, bridged to async, without ever blocking.
//
// The rule this file exists to enforce: every descriptor is `O_NONBLOCK` and readiness
// arrives through a `DispatchSource`, which on Darwin is kqueue underneath. No task
// ever sits in a blocking `read` or `connect`.
//
// The reason is not tidiness. `Task.cancel()` is cooperative — a task blocked in a
// syscall does not unblock when cancelled, and a task group will not return until its
// child does. The Swift cooperative pool is sized to the core count, so a handful of
// blocked descriptors does not make the scanner slow, it makes it stop. Everything
// else in this target is downstream of that rule.
//
// Sources run on a dedicated serial queue rather than the cooperative pool. Readiness
// handling is latency-sensitive in a way ordinary async work is not: it is the one
// thing in this program whose wake-up delay is directly the product's headline number,
// and sharing a pool with report encoding and terminal rendering would put it behind
// them.
#if canImport(Darwin)

import Darwin
import Dispatch
import Foundation
import ZhenCore

/// The queue every readiness source is delivered on.
enum ReadinessQueue {
    /// Dedicated, serial, and high priority. Serial because the reader loop reads one
    /// socket and ordering its wake-ups costs nothing; high priority because a probe
    /// reply that sits in a queue behind a redraw is measured as network latency and
    /// silently inflates every RTT in the report.
    static let shared = DispatchQueue(
        label: "com.jctec.zhen.readiness",
        qos: .userInitiated,
        autoreleaseFrequency: .workItem
    )
}

/// Readiness, with the descriptor lifetime attached to the source rather than to the
/// caller.
///
/// The rule this type enforces, and the reason it owns descriptors at all:
/// **`DispatchSource.cancel()` is asynchronous.** It returns immediately and the kernel
/// deregistration completes some time later. An earlier version cancelled the source
/// and resumed the continuation in the same breath, and the caller then closed the
/// descriptor — a use-after-close with two failure modes, one loud and one not.
///
/// Loud: libdispatch notices and aborts the process with DISPATCH_CLIENT_CRASH, which
/// on a deep scan means a crash somewhere in the middle of twenty-five thousand probes.
///
/// Quiet, and worse: the descriptor number is returned to the kernel and immediately
/// reissued to the next `socket()` call, of which this scanner makes thousands per
/// second. The stale write source then fires on a completely different connection, the
/// probe that was about to time out reports itself ready, `getsockopt(SO_ERROR)` reads
/// zero from a socket that was never asked anything — and a filtered port is reported
/// open, with a sub-millisecond round trip, in the artifact.
///
/// So: a source that owns a descriptor closes it in `setCancelHandler`, which is the
/// one place the runtime guarantees the source is finished with it, and the continuation
/// is resumed from inside that handler so no caller can run before the close.
enum Readiness {
    /// What ended the wait.
    enum Outcome: Sendable {
        /// The descriptor became writable.
        case ready
        /// The budget expired first.
        case timedOut
        /// The task was cancelled.
        case cancelled
    }

    /// How a connect attempt finished.
    enum ConnectOutcome: Sendable {
        /// The handshake resolved. Carries `SO_ERROR`: zero for open, `ECONNREFUSED`
        /// for a refusal, and so on.
        case resolved(Int32)
        /// Nothing came back within the budget.
        case timedOut
        /// The task was cancelled. Not evidence about the port.
        case cancelled
    }

    /// Waits for a connect to resolve, taking ownership of the descriptor.
    ///
    /// The descriptor is closed inside the source's cancel handler and must not be
    /// touched by the caller afterwards — it is consumed by this call in every sense
    /// except the type system's.
    ///
    /// `SO_ERROR` is read on the readiness queue at the moment the source fires, before
    /// the close, because it is only meaningful on the descriptor it belongs to.
    static func connectOutcome(owning fd: Int32, within budget: Duration) async -> ConnectOutcome {
        let claim = ResumeOnce()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<ConnectOutcome, Never>) in
                let source = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: ReadinessQueue.shared)
                let timer = DispatchSource.makeTimerSource(queue: ReadinessQueue.shared)
                let box = OutcomeBox()

                // The ONLY place this descriptor is closed, and the only place the
                // continuation is resumed. Both happen after the source has been
                // deregistered, which is what the cancel handler means.
                source.setCancelHandler {
                    timer.cancel()
                    _ = Darwin.close(fd)
                    continuation.resume(returning: box.take())
                }

                source.setEventHandler {
                    var failure: Int32 = 0
                    var size = socklen_t(MemoryLayout<Int32>.size)
                    // SAFETY: SO_ERROR writes one Int32 into storage we own and sized.
                    // Read here, on the readiness queue, while the descriptor is still
                    // ours and still open.
                    let queried = unsafe getsockopt(fd, SOL_SOCKET, SO_ERROR, &failure, &size)
                    box.set(queried == 0 ? .resolved(failure) : .timedOut)
                    source.cancel()
                }
                timer.schedule(deadline: .now() + .nanoseconds(budget.wholeNanoseconds))
                timer.setEventHandler {
                    box.set(.timedOut)
                    source.cancel()
                }
                claim.onCancel = {
                    box.set(.cancelled)
                    source.cancel()
                }

                source.resume()
                timer.resume()

                // A cancellation that landed between entering the handler and arming
                // the sources would otherwise be missed and the probe would run its
                // full budget.
                if Task.isCancelled {
                    box.set(.cancelled)
                    source.cancel()
                }
            }
        } onCancel: {
            claim.fire()
        }
    }

    /// Waits for writability on a descriptor the CALLER owns and keeps.
    ///
    /// Used for the one long-lived socket in the system — the shared ICMP socket, whose
    /// descriptor outlives every wait on it — so there is no reuse hazard: the number is
    /// never returned to the kernel while a source might still hold it. Do not call this
    /// with a descriptor you are about to close; use `connectOutcome(owning:within:)`,
    /// which exists precisely because that is the dangerous case.
    static func writableBorrowed(_ fd: Int32, within budget: Duration) async -> Outcome {
        let claim = ResumeOnce()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Outcome, Never>) in
                let source = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: ReadinessQueue.shared)
                let timer = DispatchSource.makeTimerSource(queue: ReadinessQueue.shared)
                let box = ReadinessBox()

                source.setCancelHandler {
                    timer.cancel()
                    continuation.resume(returning: box.take())
                }
                source.setEventHandler { box.set(.ready); source.cancel() }
                timer.schedule(deadline: .now() + .nanoseconds(budget.wholeNanoseconds))
                timer.setEventHandler { box.set(.timedOut); source.cancel() }
                claim.onCancel = { box.set(.cancelled); source.cancel() }

                source.resume()
                timer.resume()
                if Task.isCancelled { box.set(.cancelled); source.cancel() }
            }
        } onCancel: {
            claim.fire()
        }
    }

    /// Waits for readability on a descriptor the CALLER owns and keeps.
    ///
    /// The read counterpart of `writableBorrowed(_:within:)`, and it carries the same
    /// warning: do not call it with a descriptor you are about to close. It exists for
    /// the banner probe, which holds one connection open across several reads and
    /// closes it itself when the conversation is over.
    static func readableBorrowed(_ fd: Int32, within budget: Duration) async -> Outcome {
        let claim = ResumeOnce()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Outcome, Never>) in
                let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ReadinessQueue.shared)
                let timer = DispatchSource.makeTimerSource(queue: ReadinessQueue.shared)
                let box = ReadinessBox()

                source.setCancelHandler {
                    timer.cancel()
                    continuation.resume(returning: box.take())
                }
                source.setEventHandler { box.set(.ready); source.cancel() }
                timer.schedule(deadline: .now() + .nanoseconds(budget.wholeNanoseconds))
                timer.setEventHandler { box.set(.timedOut); source.cancel() }
                claim.onCancel = { box.set(.cancelled); source.cancel() }

                source.resume()
                timer.resume()
                if Task.isCancelled { box.set(.cancelled); source.cancel() }
            }
        } onCancel: {
            claim.fire()
        }
    }
}

/// One TCP connection, held open across a short conversation.
///
/// The connect scan opens a descriptor to learn one bit and closes it; this keeps one
/// so the banner probe can listen, then ask, then listen again. Everything is
/// `O_NONBLOCK` with readiness through a `DispatchSource`, for the reason the header of
/// this file gives: a blocked descriptor on the cooperative pool does not slow the scan
/// down, it stops it.
///
/// Not `Sendable` and deliberately so. It owns a descriptor, it is used by exactly one
/// task between `connect` and `close`, and letting it cross an isolation boundary is
/// the thing that turns a descriptor into a use-after-close.
final class TCPStream {
    private let fd: Int32
    private var closed = false

    private init(fd: Int32) { self.fd = fd }

    deinit { if !closed { _ = Darwin.close(fd) } }

    /// Opens a connection, or nil if it did not complete in time.
    static func connect(
        to address: IPv4Address, port: UInt16, within budget: Duration
    ) async -> TCPStream? {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return nil }
        guard setNonBlocking(descriptor) else {
            _ = Darwin.close(descriptor)
            return nil
        }
        var destination = socketAddress(address, port: port)
        // SAFETY: a non-blocking connect against a sockaddr_in this scope owns; the
        // pointer does not outlive the call.
        let started = unsafe withUnsafePointer(to: &destination) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
                unsafe Darwin.connect(descriptor, addr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if started != 0, errno != EINPROGRESS {
            _ = Darwin.close(descriptor)
            return nil
        }
        if started != 0 {
            guard await Readiness.writableBorrowed(descriptor, within: budget) == .ready else {
                _ = Darwin.close(descriptor)
                return nil
            }
            var failure: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            // SAFETY: SO_ERROR writes one Int32 into storage we own and sized.
            let queried = unsafe getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &failure, &size)
            guard queried == 0, failure == 0 else {
                _ = Darwin.close(descriptor)
                return nil
            }
        }
        return TCPStream(fd: descriptor)
    }

    /// Reads whatever arrives within the budget, up to a ceiling.
    ///
    /// Returns what it got rather than failing on a short read: a banner is whatever
    /// the far side chose to send, and waiting for more than that is waiting forever.
    func read(upTo limit: Int, within budget: Duration) async -> [UInt8] {
        var collected: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: min(limit, 4096))
        let stop = MonotonicInstant.now.advanced(by: budget)
        while collected.count < limit, MonotonicInstant.now < stop {
            let remaining = stop.duration(since: .now)
            guard remaining > .zero else { break }
            guard await Readiness.readableBorrowed(fd, within: remaining) == .ready else { break }
            // SAFETY: `read` writes at most `count` bytes into storage this object
            // owns, and the pointer does not escape the call.
            let got = unsafe buffer.withUnsafeMutableBytes { raw -> Int in
                unsafe Darwin.read(fd, raw.baseAddress, min(raw.count, limit - collected.count))
            }
            // Zero is the far side closing, which is a complete answer and not an error.
            guard got > 0 else { break }
            collected.append(contentsOf: buffer[0..<got])
            // A banner arrives in one segment on a LAN. Going round again would wait
            // out the whole budget for bytes that are not coming.
            break
        }
        return collected
    }

    /// Writes a request in full, or reports that it could not.
    func write(_ bytes: [UInt8]) -> Bool {
        var offset = 0
        while offset < bytes.count {
            // SAFETY: a borrowed view of an array this scope owns, for the call only.
            let written = unsafe bytes.withUnsafeBytes { raw -> Int in
                unsafe Darwin.write(fd, raw.baseAddress?.advanced(by: offset), raw.count - offset)
            }
            guard written > 0 else { return false }
            offset += written
        }
        return true
    }

    /// Closes the descriptor. Idempotent.
    func close() {
        guard !closed else { return }
        closed = true
        _ = Darwin.close(fd)
    }
}

/// Holds the first outcome any racing handler produced.
///
/// First write wins: the source firing, the timer expiring and the task being cancelled
/// all race, and the one that got there first is the truth. The cancel handler then
/// reads it once, so the continuation resumes exactly once no matter how many of them
/// ran.
final class OutcomeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var outcome: Readiness.ConnectOutcome?
    func set(_ value: Readiness.ConnectOutcome) {
        lock.withLock { if outcome == nil { outcome = value } }
    }
    func take() -> Readiness.ConnectOutcome {
        lock.withLock { outcome ?? .timedOut }
    }
}

/// The same, for plain readiness waits.
final class ReadinessBox: @unchecked Sendable {
    private let lock = NSLock()
    private var outcome: Readiness.Outcome?
    func set(_ value: Readiness.Outcome) {
        lock.withLock { if outcome == nil { outcome = value } }
    }
    func take() -> Readiness.Outcome {
        lock.withLock { outcome ?? .timedOut }
    }
}

extension Duration {
    /// Whole nanoseconds, saturating rather than overflowing.
    ///
    /// `DispatchSourceTimer` wants a `DispatchTimeInterval`, which has no `Duration`
    /// overload. Clamped because a caller can legitimately pass a budget of hours and
    /// `Int` nanoseconds runs out at about 292 years.
    var wholeNanoseconds: Int {
        let (seconds, attoseconds) = components
        let nanos = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !nanos.overflow else { return .max }
        let total = nanos.partialValue.addingReportingOverflow(attoseconds / 1_000_000_000)
        guard !total.overflow, total.partialValue <= Int64(Int.max) else { return .max }
        return Int(max(0, total.partialValue))
    }
}

/// A one-shot claim shared between racing handlers.
///
/// A small lock rather than an atomic flag because the cancellation closure has to be
/// stored as well as read, and a `Mutex` over both fields keeps the store and the
/// claim from racing each other.
final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    private var cancelHandler: (@Sendable () -> Void)?

    /// Installs the cancellation action, running it immediately if cancellation has
    /// already been requested.
    var onCancel: (@Sendable () -> Void)? {
        get { lock.withLock { cancelHandler } }
        set {
            let pending: (@Sendable () -> Void)?
            lock.lock()
            cancelHandler = newValue
            pending = pendingCancel ? newValue : nil
            lock.unlock()
            pending?()
        }
    }

    private var pendingCancel = false

    /// Takes the claim. Returns true exactly once across all callers.
    func claim() -> Bool {
        lock.withLock {
            if claimed { return false }
            claimed = true
            return true
        }
    }

    /// Requests cancellation, remembering it if the handler is not installed yet.
    func fire() {
        let handler: (@Sendable () -> Void)?
        lock.lock()
        pendingCancel = true
        handler = cancelHandler
        lock.unlock()
        handler?()
    }
}

#endif
