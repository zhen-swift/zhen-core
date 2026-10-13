// ExitCodes.swift — what a script that wraps this binary is allowed to conclude.
//
// The one rule worth stating outright: **a partial result exits zero.** The deadline
// expiring is the system working as designed, not a failure, and a CI job that treated
// it as one would go red every time the network was busy. Whether a run was complete is
// a field in the artifact, not the exit status.
//
// Everything that can stop a scan *before* it starts is enumerated in `ScanSetupError`,
// so the mapping below is a switch the compiler checks for exhaustiveness. Once
// scanning starts nothing throws: failures are degradations in the artifact.

import ArgumentParser
import Foundation
import ZhenCore

/// The exit codes this binary can produce.
nonisolated enum ExitStatus: Int32 {
    /// The scan ran — including a partial result from an expired deadline.
    case ok = 0
    /// Under `--check` only: the scan ran and nothing it was asked about was open.
    ///
    /// **Never returned without `--check`.** A scan that completed and found nothing is
    /// a working scan, which is the same reasoning that makes a partial discovery exit
    /// 0. `--check` opts into the other meaning explicitly, and every failure code below
    /// stays what it was so a broken scan is never mistaken for a closed port.
    case noneOpen = 1
    /// Usage error. `EX_USAGE`.
    case usage = 64
    /// A required capability was unavailable — Local Network denied, no interface.
    /// `EX_UNAVAILABLE`.
    case unavailable = 69
    /// Temporary failure: the interface went away mid-scan. `EX_TEMPFAIL`.
    case temporary = 75
    /// Interrupted.
    case interrupted = 130
}

/// Everything that can stop a scan before it starts.
///
/// Typed and closed on purpose. Enumerating them is what lets the exit-code mapping be
/// exhaustive rather than a default case that quietly turns a new failure into a
/// usage error.
nonisolated enum ScanSetupError: Error {
    /// The CIDR, interface name or option value could not be used.
    case badArgument(String)
    /// No usable network interface.
    case noInterface(String)
    /// The platform refused something the scan needs.
    case denied(String)
    /// The platform has no implementation — a Linux build with no engine yet.
    case unsupportedPlatform(String)
    /// A syscall failed for a reason that may not recur.
    case transient(String)

    /// Wraps a platform failure, preserving which kind it was.
    init(_ error: PlatformError) {
        switch error {
        case .unavailable(let message): self = .unsupportedPlatform(message)
        case .denied(let message): self = .denied(message)
        case .notFound(let message): self = .noInterface(message)
        case .systemError(let code, let api): self = .transient("\(api) failed with errno \(code)")
        }
    }

    /// What to tell the user, written for a person rather than a log parser.
    var message: String {
        switch self {
        case .badArgument(let message): message
        case .noInterface(let message): message
        case .denied(let message): message
        case .unsupportedPlatform(let message): message
        case .transient(let message): message
        }
    }

    /// The process exit code.
    var status: ExitStatus {
        switch self {
        case .badArgument: .usage
        case .noInterface, .denied, .unsupportedPlatform: .unavailable
        case .transient: .temporary
        }
    }
}

nonisolated extension Outcome {
    /// The exit code a completed run produces.
    ///
    /// Two of the three outcomes are partial results and only one of those is an
    /// interruption. `deadlineExpired` exits zero deliberately: a script that treated a
    /// busy network as a failure would be wrong.
    var status: ExitStatus {
        switch self {
        case .complete, .deadlineExpired: .ok
        case .cancelled: .interrupted
        }
    }
}
