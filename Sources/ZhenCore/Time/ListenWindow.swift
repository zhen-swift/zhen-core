// ListenWindow.swift — waits out a listening window that a signal may close early.
//
// Here rather than in the Darwin echo so the rule — the signal closes it, the floor holds
// it open, the cap closes it regardless — is tested on Linux, like the reach plan.

/// The wait behind `IPv6Window`: from now until `closing` yields or finishes, but no
/// sooner than `floor` and no later than `cap`.
public enum ListenWindow {
    /// Returns when the window closes, and how long it was open.
    ///
    /// - Parameters:
    ///   - floor: the least it stays open, however early `closing` arrives.
    ///   - cap: the most it stays open, whether or not `closing` ever arrives.
    ///   - closing: one element, or the end of the stream, closes the window.
    @discardableResult
    public static func wait(floor: Duration, cap: Duration, closing: AsyncStream<Void>) async -> Duration {
        let opened = MonotonicInstant.now
        let floor = min(floor, cap)
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                try? await Task.sleep(for: cap)
            }
            group.addTask {
                // Ends on the signal, on the stream finishing, or on cancellation once the
                // cap has already closed the window.
                for await _ in closing { break }
                let open = MonotonicInstant.now.duration(since: opened)
                if open < floor { try? await Task.sleep(for: floor - open) }
            }
            // Whichever closes first; the other is cancelled, and both sleeps return at
            // once when cancelled.
            await group.next()
            group.cancelAll()
        }
        return MonotonicInstant.now.duration(since: opened)
    }
}
