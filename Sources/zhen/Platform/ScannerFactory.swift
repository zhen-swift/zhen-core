// ScannerFactory.swift — the only conditional compilation in this package.
//
// `#if os(...)` appears here and nowhere else: not in a command, not in a renderer, not
// in anything in core. The moment one leaks into command code the portability claim is
// gone and nobody notices for six months, so the seam is one file with one function and
// the rest of the program cannot tell which platform it is on.
//
// A missing platform is a clean setup error, not a build failure — which is what lets a
// Linux build of this package compile today, before a ZhenLinux target exists, and
// say so at runtime instead of failing to link.

import ZhenCore

#if canImport(Darwin)
import ZhenDarwin
#endif

/// What a platform must provide for `scan` to run.
///
/// Deliberately narrow. Everything the command needs is here and nothing else is, so a
/// second conformance has a small, obvious surface to fill.
nonisolated struct PlatformScanner: Sendable {
    /// Enumerates interfaces.
    var interfaces: any InterfaceProvider
    /// Host discovery.
    var discovery: any HostDiscovery
    /// Port scanning.
    var ports: any PortScanning
    /// UDP port scanning, for the `U:` half of a spec.
    var udpPorts: any PortScanning
    /// Naming: the mDNS, SSDP and NetBIOS cascade behind one stage.
    var naming: any NameResolving
    /// The descriptor soft limit the kernel granted.
    var descriptorLimit: Int
    /// The in-flight window derived from it.
    var concurrency: Int
    /// Whatever the platform wants said about how it assembled itself.
    ///
    /// A list rather than one value because there is more than one thing worth saying
    /// and they are independent: a concurrency request that had to be clamped, and a
    /// privileged engine that could have run and could not. Both belong in the
    /// artifact, and both were `nil` in the shape this replaced — which is how the
    /// second one would have been lost.
    var notices: [Degradation]

    /// Builds the scanner for this platform.
    ///
    /// - Parameter concurrencyOverride: a user-supplied `--concurrency`, clamped rather
    ///   than rejected. Asking for more than the descriptor table supports is a
    ///   preference, not a usage error, and failing the scan over it would be obnoxious
    ///   — but the clamp travels back as a `Degradation` so it reaches the artifact
    ///   rather than only the terminal.
    /// - Parameter budgets: the sweep's timing policy, as chosen on the command line.
    ///   A core type, so this signature needs no `#if` around it and a platform with no
    ///   sweep simply ignores it.
    /// Always `.directOnly` on this path. The command line is the binary study 2
    /// measures, and its gate requires the unprivileged discovery path to be
    /// behaviourally unchanged from the tag study 1 measured. Probing for a helper on
    /// the startup path of every scan is a change to that path whether or not a helper
    /// is there, so the command line does not do it: `sudo zhen` opens a device
    /// directly exactly as it always has.
    static func make(
        concurrencyOverride: Int?,
        budgets: SweepBudgets = .split,
        portScanType: PortScanType = .auto
    ) async throws(ScanSetupError) -> PlatformScanner {
        #if canImport(Darwin)
        let scanner: DarwinScanner
        do {
            scanner = try await DarwinScanner.make(
                concurrencyOverride: concurrencyOverride, budgets: budgets,
                capture: .directOnly, portScanType: portScanType
            )
        } catch {
            throw ScanSetupError(error)
        }
        return PlatformScanner(
            interfaces: scanner.interfaces,
            discovery: scanner.discovery,
            ports: scanner.ports,
            udpPorts: scanner.udpPorts,
            naming: scanner.naming,
            descriptorLimit: scanner.descriptorLimit,
            concurrency: scanner.concurrency,
            notices: [
                DarwinScanner.clampNotice(
                    requested: concurrencyOverride,
                    granted: scanner.descriptorLimit,
                    effective: scanner.concurrency
                ),
                scanner.privilegedEngineNotice,
            ].compactMap(\.self)
        )
        #else
        throw ScanSetupError.unsupportedPlatform("""
            zhen has no scanning engine for this platform yet. The seam is a set of \
            protocols in ZhenCore's Platform directory; a Linux conformance needs \
            getifaddrs, /proc/net/arp or netlink, and epoll readiness.
            """)
        #endif
    }
}
