// HelperClient.swift — the app's side of the connection, and the rung above sudo.
//
// ── This is a rung, not a replacement ──────────────────────────────────────────
//
// `DarwinScanner` tries the helper, then a direct open, then falls back to the
// unprivileged engines. Every one of those can fail for reasons that have nothing to do
// with the others: the helper can be absent, unregistered, awaiting approval in Login
// Items, or an older version left behind by a previous install; the direct open works
// under `sudo` and not otherwise; and the unprivileged path always works. So the answer
// is still found by attempting, exactly as `BPFDevice.probe` decided it, and a helper is
// simply one more thing that can be absent.
//
// ── Why the connection is per acquisition ──────────────────────────────────────
//
// Held connections have to be invalidated, reconnected, and reasoned about when the
// helper is removed mid-session — and removal is a button in Settings, so mid-session is
// a normal case rather than an edge one. A connection costs a few milliseconds against a
// scan measured in seconds, and a scan opens at most a handful of devices.
// macOS only. The helper is a launch daemon reached over a Mach service, and iOS has
// neither; an iPadOS build composes without a capture device at all.
#if os(macOS)

import Darwin
import Foundation

/// Talking to the privileged helper.
public enum HelperClient {
    /// How long to wait for the helper before giving up and trying the next rung.
    ///
    /// Short, because this is on the path of every privileged scan and the fallback
    /// below it always works. A helper that has not answered in this long is a helper
    /// that is not going to.
    public static let timeoutMilliseconds = 3_000

    /// The bound on an acquisition the scan itself makes — the sweep opening its device.
    public static let acquisitionTimeout: Duration = .milliseconds(timeoutMilliseconds)

    /// The bound on the composition-time check: whether a helper answers at all.
    ///
    /// ── Why the check has a bound of its own ────────────────────────────────────
    ///
    /// Building a scanner asks whether a capture device can be had, and under
    /// `.helperThenDirect` that means asking the helper. A registration launchd cannot
    /// start — a build that has since been deleted is the case measured — accepts the
    /// connection and never answers, and the check waited out the full acquisition
    /// timeout: 3.2 s on every engine build, which the app paid on every launch. A
    /// helper that is there answers in milliseconds, launch included; and once this check
    /// fails, the privileged engines are not built, so nothing waits again until the next
    /// build. So the question "is anybody there" gets a fraction of the patience a real
    /// acquisition does.
    public static let probeTimeout: Duration = .milliseconds(750)

    /// Asks the helper for a configured capture device.
    ///
    /// - Parameter timeout: how long to wait for an answer. The acquisition timeout
    ///   unless the caller is only asking whether anyone is there.
    /// - Returns: the descriptor, which the caller owns and must close.
    public static func openCaptureDevice(
        interface: String, filter: [BPFInstruction], timeout: Duration = acquisitionTimeout
    ) async throws(BPFUnavailable) -> AcquiredDevice {
        let outcome: Result<AcquiredDevice, BPFUnavailable> = await answer(
            within: timeout,
            otherwise: .failure(.helperRefused("the helper did not answer within \(timeout.spokenMilliseconds)"))
        ) { done in
            let connection = NSXPCConnection(
                machServiceName: HelperIdentity.label, options: .privileged
            )
            connection.remoteObjectInterface = NSXPCInterface(
                with: ZhenHelperProtocol.self
            )
            // The other half of the mutual check. The helper verifies us because handing
            // out a capture descriptor is handing out promiscuous capture; we verify it
            // because a descriptor arriving from something that is not our daemon is a
            // descriptor onto traffic somebody else chose.
            if #available(macOS 13.0, *) {
                connection.setCodeSigningRequirement(CodeRequirement.helper)
            }

            // Exactly one resumption, whichever of the four paths gets there first: a
            // reply, an error handler, an invalidation, or the timeout. NSXPC will call
            // more than one of these in ordinary operation — an interrupted connection
            // is also invalidated — and resuming a continuation twice is a crash.
            //
            // Absent, not refused. An invalidation before any reply is what a Mach
            // service nobody is listening on looks like, and that is the ordinary state
            // of a machine with no helper installed rather than something to report.
            connection.invalidationHandler = { done.finish(.failure(.helperAbsent)) }
            connection.interruptionHandler = {
                done.finish(.failure(.helperRefused("the helper stopped responding")))
            }
            connection.resume()

            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                done.finish(.failure(.helperRefused(error.localizedDescription)))
            } as? ZhenHelperProtocol

            guard let proxy else {
                done.finish(.failure(.helperRefused("the helper does not implement the expected interface")))
                connection.invalidate()
                return {}
            }

            proxy.openCaptureDevice(
                interface: interface, filter: BPFFilterCoding.encode(filter)
            ) { handle, bufferLength, refusal in
                defer { connection.invalidate() }
                if let refusal {
                    done.finish(.failure(.helperRefused(refusal)))
                    return
                }
                guard let handle else {
                    done.finish(.failure(.helperRefused("the helper returned neither a device nor a reason")))
                    return
                }
                // Duplicated, because the FileHandle the connection built owns its
                // descriptor and closes it when it is deallocated — which happens as
                // soon as this block returns. The dup is what outlives the reply.
                let descriptor = dup(handle.fileDescriptor)
                guard descriptor >= 0 else {
                    done.finish(.failure(.helperRefused("the descriptor could not be duplicated")))
                    return
                }
                done.finish(.success(AcquiredDevice(
                    descriptor: descriptor,
                    bufferLength: bufferLength,
                    devicePath: "helper"
                )))
            }

            // What the timeout does when it wins: a helper that is registered but
            // awaiting approval accepts the connection and never answers, which without
            // this would hang the scan rather than degrade it.
            let box = ConnectionBox(connection: connection)
            return { box.connection.invalidate() }
        }

        switch outcome {
        case .success(let device): return device
        case .failure(let error): throw error
        }
    }

    /// Whether the helper is there and answering, and what it says it is.
    ///
    /// Used by the app to render its Settings row from the live connection rather than
    /// from `SMAppService.status`, which reports what was registered rather than what
    /// will answer.
    public static func version() async -> String? {
        await answer(within: .seconds(2), otherwise: nil) { done in
            let connection = NSXPCConnection(
                machServiceName: HelperIdentity.label, options: .privileged
            )
            connection.remoteObjectInterface = NSXPCInterface(with: ZhenHelperProtocol.self)
            if #available(macOS 13.0, *) {
                connection.setCodeSigningRequirement(CodeRequirement.helper)
            }
            connection.invalidationHandler = { done.finish(nil) }
            connection.interruptionHandler = { done.finish(nil) }
            connection.resume()

            let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
                done.finish(nil)
            } as? ZhenHelperProtocol
            proxy?.helperVersion { version in
                defer { connection.invalidate() }
                done.finish(version)
            }
            let box = ConnectionBox(connection: connection)
            return { box.connection.invalidate() }
        }
    }

    /// The first answer `ask` gives, or `fallback` once `bound` has passed.
    ///
    /// The shape every call to the helper has: several callbacks that may each fire, one
    /// of which must win, and a bound after which nobody is listening. Pulled out of the
    /// two calls that had it inline so the bound can be shown to hold without a helper —
    /// the XPC half cannot be faked, and the timing half does not need it.
    ///
    /// - Parameter ask: starts the request, offers answers to the `Resumption` it is
    ///   given, and returns what to do if the bound wins (invalidate the connection).
    static func answer<Value: Sendable>(
        within bound: Duration,
        otherwise fallback: Value,
        _ ask: (Resumption<Value>) -> @Sendable () -> Void
    ) async -> Value {
        await withCheckedContinuation { (continuation: CheckedContinuation<Value, Never>) in
            let done = Resumption(continuation)
            let giveUp = ask(done)
            let (seconds, attoseconds) = bound.components
            let nanoseconds = Int(seconds) * 1_000_000_000 + Int(attoseconds / 1_000_000_000)
            DispatchQueue.global().asyncAfter(deadline: .now() + .nanoseconds(nanoseconds)) {
                if done.finish(fallback) { giveUp() }
            }
        }
    }
}

extension Duration {
    /// "750ms", as the refusal sentence has always spelled its bound.
    fileprivate var spokenMilliseconds: String {
        let (seconds, attoseconds) = components
        return "\(seconds * 1_000 + attoseconds / 1_000_000_000_000_000)ms"
    }
}

/// An `NSXPCConnection` carried into a callback.
///
/// The class is documented as safe to use from any thread and is not marked `Sendable`,
/// which is the ordinary state of an Objective-C API that predates the annotation. The
/// box says where that judgement was made rather than scattering it.
private struct ConnectionBox: @unchecked Sendable {
    let connection: NSXPCConnection
}

/// A continuation that can be offered an answer many times and resumes once.
///
/// NSXPC calls more than one of its handlers in ordinary operation: an interrupted
/// connection is also invalidated, and a timeout can fire while a reply is in flight.
/// Resuming a checked continuation twice is a crash, so the guard has to be here rather
/// than in the shape of the callbacks.
final class Resumption<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?

    init(_ continuation: CheckedContinuation<Value, Never>) {
        self.continuation = continuation
    }

    /// Resumes with `value` if nothing else has. Returns whether this call was the one.
    @discardableResult
    func finish(_ value: Value) -> Bool {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
        return pending != nil
    }
}

#endif
