// PermissionAdvice.swift — which Local Network remedy this process should give.
//
// Whether this process is an app is a fact about the process, and it is the fact the two
// Apple remedies differ on: a command-line build has no bundle and its grant may be listed
// under the terminal; an app has one and is listed under its own name. So it is read here,
// from the running bundle, rather than threaded from every caller — the same way the CLI
// gets its Info.plist section rather than being told it has one.
//
// The permission itself is a fact about the OS: macOS 15 introduced it. On 14 there is no
// Local Network setting to send anyone to, so there is no Apple remedy at all, and the
// degradation reports the observation alone.
#if canImport(Darwin)
import Foundation
import ZhenCore

extension ProbePermissionAdvice {
    /// The Apple remedy for a process whose main bundle is at `bundleURL`.
    ///
    /// An `.app` gets `appleLocalNetworkInApp`; anything else — a bare executable, a test
    /// runner — gets `appleLocalNetwork`, which is the text `zhen` has always printed.
    /// Where the OS has no such permission, `unspecified`: a wrong instruction is worse
    /// than none.
    public static func apple(
        bundleURL: URL,
        osHasLocalNetworkPrivacy: Bool = osHasLocalNetworkPrivacy
    ) -> ProbePermissionAdvice {
        guard osHasLocalNetworkPrivacy else { return .unspecified }
        return bundleURL.pathExtension == "app" ? .appleLocalNetworkInApp : .appleLocalNetwork
    }

    /// Whether this OS has the Local Network permission. macOS 15 introduced it.
    public static var osHasLocalNetworkPrivacy: Bool {
        if #available(macOS 15, *) { true } else { false }
    }

    /// The Apple remedy for this process.
    public static var appleForThisProcess: ProbePermissionAdvice {
        apple(bundleURL: Bundle.main.bundleURL)
    }
}
#endif
