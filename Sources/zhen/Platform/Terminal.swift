// Terminal.swift — the POSIX bits of talking to a terminal, kept in Platform/.
//
// `isatty` is POSIX and has no Windows equivalent, so it belongs behind this seam with
// the signal handling rather than sprinkled through the renderers — which is where it
// was, and which made the acceptance item about compiling with `Platform/` excluded
// false. The renderers now ask `Terminal` and know nothing about file descriptors.

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

import Foundation

/// What the process's standard streams are attached to.
nonisolated enum Terminal {
    /// Whether stdout is a terminal.
    ///
    /// This is the decision that governs colour, because colour is a property of what
    /// is being written and the thing being written to stdout is the artifact. Reading
    /// stderr's state to decide how to format stdout — which the first version did —
    /// puts escape sequences into a redirected file whenever the two streams disagree,
    /// which is exactly the common case of `zhen scan > out.txt` in a terminal.
    static var stdoutIsTTY: Bool {
        #if canImport(Darwin) || canImport(Glibc)
        return isatty(1) == 1
        #else
        return false
        #endif
    }

    /// Whether stderr is a terminal. Governs the progress display, which lives there.
    static var stderrIsTTY: Bool {
        #if canImport(Darwin) || canImport(Glibc)
        return isatty(2) == 1
        #else
        return false
        #endif
    }

    /// Whether the environment has asked for no colour at all.
    static var colorDisabledByEnvironment: Bool {
        ProcessInfo.processInfo.environment["NO_COLOR"] != nil
    }

    /// The width, in columns, that stdout should be formatted for.
    ///
    /// `PORTS-rendering.md`'s section on terminal width gives three sources in order:
    /// `ioctl(TIOCGWINSZ)`, then `COLUMNS`, then 80 when stdout is not a terminal.
    ///
    /// **When stdout is not a terminal the answer is 80 and nothing else is consulted,
    /// `COLUMNS` included.** That is the reading the plan's own gate requires: it asks
    /// that `zhen scan > out.txt` produce identical bytes from an 80-column and a
    /// 200-column window, and a shell exports `COLUMNS` from the window it was launched
    /// in. Honouring it on a redirect would make the file depend on the window, which
    /// is the same class of problem as a study run depending on `ZHEN_HISTORY`.
    ///
    /// So `COLUMNS` is the fallback for the case where stdout IS a terminal and the
    /// ioctl still fails — some pseudo-terminals under CI, a terminal with no window
    /// size set. It is a narrow case and it is the only one where the variable is read.
    static var stdoutWidth: Int {
        width(isTTY: stdoutIsTTY,
              ioctlWidth: windowSize(ofDescriptor: 1),
              columnsVariable: ProcessInfo.processInfo.environment["COLUMNS"])
    }

    /// The width a run should use, from its three sources. Pure, so the order is
    /// testable without a terminal.
    ///
    /// - Parameters:
    ///   - isTTY: whether the stream is attached to a terminal.
    ///   - ioctlWidth: what `TIOCGWINSZ` said, or `nil` if it failed.
    ///   - columnsVariable: the raw `COLUMNS` value, unparsed.
    static func width(isTTY: Bool, ioctlWidth: Int?, columnsVariable: String?) -> Int {
        guard isTTY else { return fallbackWidth }
        if let ioctlWidth, ioctlWidth >= minimumUsableWidth { return ioctlWidth }
        if let columnsVariable, let parsed = Int(columnsVariable),
           parsed >= minimumUsableWidth {
            return parsed
        }
        return fallbackWidth
    }

    /// What a non-terminal gets, and what a terminal gets when nothing else answers.
    static let fallbackWidth = 80

    /// Below this, a reported width is treated as not having been reported.
    ///
    /// A terminal can legitimately answer 0 — `TIOCGWINSZ` succeeds with a zeroed
    /// struct on a pty that has never been sized — and a shell can export `COLUMNS=0`.
    /// Formatting a table for zero columns produces nothing legible, so an implausible
    /// answer falls through to the next source rather than being believed.
    static let minimumUsableWidth = 20

    /// `TIOCGWINSZ` on a descriptor, or `nil` when the call fails.
    static func windowSize(ofDescriptor descriptor: Int32) -> Int? {
        #if canImport(Darwin) || canImport(Glibc)
        var size = winsize()
        guard ioctl(descriptor, UInt(TIOCGWINSZ), &size) == 0 else { return nil }
        return Int(size.ws_col)
        #else
        return nil
        #endif
    }
}
