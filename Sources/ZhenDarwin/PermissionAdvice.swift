// PermissionAdvice.swift — which Local Network remedy this process should give.
//
// Whether this process is an app is a fact about the process, and it is the fact the two
// Apple remedies differ on: a command-line build has no bundle and its grant may be listed
// under the terminal; an app has one and is listed under its own name. So it is read here,
// from the running bundle, rather than threaded from every caller — the same way the CLI
// gets its Info.plist section rather than being told it has one.
#if canImport(Darwin)
import Foundation
import ZhenCore

extension ProbePermissionAdvice {
    /// The Apple remedy for a process whose main bundle is at `bundleURL`.
    ///
    /// An `.app` gets `appleLocalNetworkInApp`; anything else — a bare executable, a test
    /// runner — gets `appleLocalNetwork`, which is the text `zhen` has always printed.
    public static func apple(bundleURL: URL) -> ProbePermissionAdvice {
        bundleURL.pathExtension == "app" ? .appleLocalNetworkInApp : .appleLocalNetwork
    }

    /// The Apple remedy for this process.
    public static var appleForThisProcess: ProbePermissionAdvice {
        apple(bundleURL: Bundle.main.bundleURL)
    }
}
#endif
