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
#if canImport(Darwin)

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

    /// Asks the helper for a configured capture device.
    ///
    /// - Returns: the descriptor, which the caller owns and must close.
    public static func openCaptureDevice(
        interface: String, filter: [BPFInstruction]
    ) async throws(BPFUnavailable) -> AcquiredDevice {
        let outcome = await withCheckedContinuation { (continuation: CheckedContinuation<Result<AcquiredDevice, BPFUnavailable>, Never>) in
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
            let done = Resumption(continuation)
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
                return
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

            // The timeout. A helper that is registered but awaiting approval accepts the
            // connection and never answers, which without this would hang the scan
            // rather than degrade it.
            let box = ConnectionBox(connection: connection)
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(timeoutMilliseconds)) {
                if done.finish(.failure(.helperRefused("the helper did not answer within \(timeoutMilliseconds)ms"))) {
                    box.connection.invalidate()
                }
            }
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
        await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let connection = NSXPCConnection(
                machServiceName: HelperIdentity.label, options: .privileged
            )
            connection.remoteObjectInterface = NSXPCInterface(with: ZhenHelperProtocol.self)
            if #available(macOS 13.0, *) {
                connection.setCodeSigningRequirement(CodeRequirement.helper)
            }
            let done = Resumption(continuation)
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
            DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(2)) {
                if done.finish(nil) { box.connection.invalidate() }
            }
        }
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
private final class Resumption<Value: Sendable>: @unchecked Sendable {
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
