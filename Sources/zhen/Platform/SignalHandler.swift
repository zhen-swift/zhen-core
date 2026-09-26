// SignalHandler.swift — Ctrl-C that commits the work instead of discarding it.
//
// `signal()` handlers may only call async-signal-safe functions, which excludes
// essentially everything interesting and gives Swift no guarantees at all — allocating,
// touching an actor or writing to a stream inside one is undefined behaviour that
// usually appears to work.
//
// So: `signal(SIGINT, SIG_IGN)` first, then a `DispatchSourceSignal`, which delivers on
// a queue where ordinary code is legal. Ignoring the signal first is not optional —
// without it the default disposition still terminates the process and the source never
// runs.
//
// First signal unwinds cleanly and commits the partial run. Second exits at once,
// because a user pressing Ctrl-C twice has stopped asking.

import Dispatch
import Foundation

/// Watches for interruption and reports the first one.
nonisolated final class SignalHandler: @unchecked Sendable {
    private var sources: [DispatchSourceSignal] = []
    private let queue = DispatchQueue(label: "com.jctec.zhen.signals")
    private let lock = NSLock()
    private var interrupted = false

    /// Whether a first interrupt has arrived.
    var wasInterrupted: Bool { lock.withLock { interrupted } }

    /// What each watched signal's disposition was before this handler changed it.
    ///
    /// Restored by `stop()`. Leaving SIGINT set to `SIG_IGN` after the handler is gone
    /// makes the process unkillable by Ctrl-C — harmless at the end of a command that
    /// is exiting anyway, and actively poisonous in a test process, where every suite
    /// that ran afterwards inherited an ignored SIGINT.
    ///
    /// Values are optional and written with `updateValue`, not subscript assignment.
    /// `SIG_DFL` is a null function pointer, which Swift imports as `nil`, and
    /// `dictionary[key] = nil` REMOVES the entry rather than storing one — so the
    /// common case, a process whose SIGINT was at its default, recorded nothing and
    /// restored nothing. The test that asserts the disposition is restored is what
    /// caught it.
    private var previous: [Int32: sig_t?] = [:]

    /// Installs handlers for SIGINT and SIGTERM.
    ///
    /// - Parameter onFirst: run on the first signal, off the main actor. The second
    ///   signal exits immediately without running it again — at hour three of a watch,
    ///   a user who presses Ctrl-C twice wants out now, not a tidy shutdown.
    init(onFirst: @escaping @Sendable () -> Void) {
        for number in [SIGINT, SIGTERM] {
            // Ignore the default disposition first, or the process dies before the
            // dispatch source ever sees anything.
            previous.updateValue(signal(number, SIG_IGN), forKey: number)
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { [weak self] in
                guard let self else { return }
                let alreadyInterrupted: Bool = self.lock.withLock {
                    let previous = self.interrupted
                    self.interrupted = true
                    return previous
                }
                if alreadyInterrupted {
                    // Restore the default and re-raise, so the shell sees a real signal
                    // death rather than a fabricated exit code.
                    signal(number, SIG_DFL)
                    raise(number)
                } else {
                    onFirst()
                }
            }
            source.resume()
            sources.append(source)
        }
    }

    /// Stops watching and restores the previous signal dispositions.
    func stop() {
        for source in sources { source.cancel() }
        sources.removeAll()
        for (number, disposition) in previous { signal(number, disposition ?? SIG_DFL) }
        previous.removeAll()
    }
}

extension SignalHandler {
    /// The current disposition of a signal, for asserting that it was restored.
    ///
    /// Reads it by setting it and putting it straight back, which is the only way POSIX
    /// offers to ask.
    static func isIgnored(_ number: Int32) -> Bool {
        // `sig_t` is a C function pointer and not Equatable, so the comparison is on
        // the raw bit pattern.
        let previous = signal(number, SIG_IGN)
        signal(number, previous ?? SIG_DFL)
        guard let previous else { return false }
        return unsafeBitCast(previous, to: UInt.self) == unsafeBitCast(SIG_IGN, to: UInt.self)
    }
}
