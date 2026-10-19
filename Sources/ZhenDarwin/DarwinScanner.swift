// DarwinScanner.swift — the composition root for the Apple platform.
//
// Everything above this file sees one type with one factory. Which engines exist, how
// concurrency was derived, and what the kernel granted are all settled here, so a
// consumer — the CLI today, the Mac app next — never assembles a scanner itself and the
// two cannot drift.
#if canImport(Darwin)

import Darwin
import ZhenCore
import ZhenPrivilege

/// The Apple-platform scanner: interfaces, neighbour table, ICMP sweep, connect scan.
public struct DarwinScanner: Sendable {
    /// Enumerates interfaces.
    public let interfaces: any InterfaceProvider
    /// Reads the ARP cache.
    public let neighbors: any NeighborCache
    /// Host discovery.
    ///
    /// An existential rather than `ICMPSweepEngine`, because which engine this is now
    /// depends on what the machine turned out to be able to do: the unprivileged sweep
    /// alone, or a `CompositeDiscoveryEngine` of it and the layer-2 ARP sweep. Nothing
    /// above here branches on which — that is what `descriptor.kind` is for.
    public let discovery: any HostDiscovery
    /// Port scanning.
    ///
    /// An existential for the same reason `discovery` is: which engine this is depends
    /// on whether a BPF device opened. Half-open SYN probing when it did, full connect
    /// when it did not, and nothing above here branches on which.
    public let ports: any PortScanning
    /// UDP port probing, used by `zhen ports` for a spec's `U:` ports.
    ///
    /// Always the same engine: it needs no privilege, so nothing about how this scanner
    /// assembled changes it. Deliberately NOT in `capabilities` — that set describes
    /// what a `zhen scan` run did, and a scan does not probe UDP.
    public let udpPorts: any PortScanning = DarwinUDPPortScan()
    /// Naming: Bonjour, UPnP and NetBIOS behind one stage.
    public let naming: DarwinNameResolver
    /// The descriptor soft limit the kernel actually granted at startup.
    public let descriptorLimit: Int
    /// The in-flight window derived from that limit.
    public let concurrency: Int
    /// Why the layer-2 sweep is not in the composition, when it is not and the reason
    /// is worth saying.
    ///
    /// Absent on an ordinary unprivileged run, and that silence is deliberate: running
    /// without root is this tool's documented default and the whole reason it needs no
    /// password, so reporting it as a degradation would put a complaint in the artifact
    /// of every normal scan. What does get reported is the case where the capability
    /// was reachable and something took it — every `/dev/bpf*` node held by another
    /// process, an interface that is not Ethernet, an ioctl that failed — because that
    /// is a person who could have had the ARP sweep and did not.
    public let privilegedEngineNotice: Degradation?

    /// Builds a scanner, raising the descriptor limit first.
    ///
    /// - Parameter concurrencyOverride: a user-supplied `--concurrency`. Clamped to
    ///   what the descriptor table can actually support rather than rejected: a request
    ///   for more than the machine can do is a preference, not a usage error, and
    ///   failing the scan over it would be obnoxious. The caller is told it clamped.
    /// - Parameter budgets: how the sweep chooses its retransmit interval. Defaults to
    ///   the split; the other cases are ablations and exist to be measured against it.
    /// - Parameter capture: which routes to a capture device this scanner may use.
    ///   Defaults to a direct open and nothing else, which is exactly what this factory
    ///   did before the privileged helper existed. The app opts into the helper; the
    ///   command line does not, because it is the binary study 2 measures and a helper
    ///   probe on the startup path of an unprivileged scan is a change to the thing
    ///   being measured whether or not it finds anything.
    /// - Parameter neighborWatch: whether the unprivileged sweep watches the neighbour
    ///   table while it runs. On by default; off is the `--no-neighbor-watch` ablation.
    public static func make(
        concurrencyOverride: Int? = nil,
        budgets: SweepBudgets = .split,
        capture: CapturePolicy = .directOnly,
        portScanType: PortScanType = .auto,
        neighborWatch: Bool = true
    ) async throws(PlatformError) -> DarwinScanner {
        // Raise first, then derive. The soft limit is the binding constraint on the
        // deep scan — one descriptor per port per host — and both the brief and SPEC
        // record it as 256, while this machine reports 1,048,576. Reading what was
        // granted rather than trusting either number is the whole point.
        let granted = DarwinResourceLimits().raiseDescriptorLimit()
        let derived = ConcurrencyBudget.fromDescriptorLimit(granted)
        let effective = concurrencyOverride.map { min(max(1, $0), derived) } ?? derived

        let interfaces = DarwinInterfaceProvider()
        // Fail early and specifically if there is no interface: everything downstream
        // would otherwise produce an empty scan and call it a success.
        let primary = try interfaces.primaryInterface()

        let unprivileged = ICMPSweepEngine(
            concurrency: effective, budgets: budgets, neighborWatch: neighborWatch
        )

        #if os(macOS)
        // ── Which engines exist is decided by attempting, never by asking who we are ─
        //
        // `geteuid() == 0` is the wrong question in both directions. Root with every
        // `/dev/bpf*` node held by Wireshark has exactly the capability a normal user
        // has, and a machine running a ChmodBPF-style daemon gives a normal user the
        // capability root would have. Opening a device is the only answer that is about
        // this machine at this moment, and it costs one syscall.
        //
        // A failure is never fatal. The unprivileged sweep is the default and stays
        // fully functional, which is requirement 8 of the specification and the reason
        // this tool needs no password at all.
        // With `.directOnly` this is the same open-and-close it always was. With
        // `.helperThenDirect` it also tries the helper, because "is a helper installed
        // and approved" has exactly as many wrong answers available to a check that
        // does not try as `geteuid()` had.
        let source = CaptureSource.source(for: capture)
        let refusal = await source.probe(interface: primary.name)

        // Port scanning takes the privileged path when there is one, and this is a
        // substitution rather than a composition — unlike discovery, where the two
        // engines find different hosts and the union is the point. A SYN scan and a
        // connect scan answer the *same* question about the same ports, so running
        // both would ask every host twice for one verdict. The privileged answer is
        // strictly better where it is available: it costs the target one packet
        // instead of an accepted connection, and it still says `open` against a
        // listener whose accept backlog is full, where `connect` times out into
        // `filtered`.
        // Banners wrap whichever verdict engine was chosen. A service identity needs a
        // completed handshake, which half-open declines to perform, so the two are
        // composed rather than merged: SYN decides every port and a full connection is
        // opened only to the few that turned out to be open.
        // `--scan-type` chooses, when it has been asked to. `auto` is the branch above,
        // unchanged.
        //
        // **`syn` without a capture device is refused rather than quietly downgraded.**
        // A flag that says "use SYN" and silently runs connect is worse than no flag: a
        // run would report a measurement of the mechanism it was not using, which is the
        // exact defect the study's capability list exists to prevent.
        let useSYN: Bool
        switch portScanType {
        case .auto: useSYN = refusal == nil
        case .connect: useSYN = false
        case .syn:
            guard refusal == nil else {
                // Its own sentence rather than the sweep's. The capture refusal is
                // phrased for discovery — it talks about hosts that answer only ARP —
                // and pasting it after "--scan-type syn needs" produces a paragraph
                // about the wrong stage.
                throw PlatformError.denied(
                    "--scan-type syn needs a packet-capture device, and /dev/bpf* "
                    + "could not be opened. Re-run under sudo, or use "
                    + "--scan-type connect, which needs no privilege."
                )
            }
            useSYN = true
        }
        let verdicts: any PortScanning = useSYN
            ? SYNScanEngine(concurrency: effective, budgets: budgets, capture: source)
            : TCPConnectScanEngine(concurrency: effective)
        let named = BannerProbingPortScan(base: verdicts)
        // Stack fingerprinting writes its own SYN, so it exists only on the privileged
        // path. Without BPF the layer is simply absent and the artifact reports the
        // capabilities that were — rather than claiming one and producing nothing,
        // which is the defect this whole sequence of work started from.
        // Follows `useSYN`, not the capture device's availability: stack fingerprinting
        // writes its own SYN, so a run forced to `connect` must not sprout one.
        let chosen: any PortScanning = useSYN
            ? FingerprintingPortScan(base: named, probe: OSFingerprintProbe(capture: source))
            : named
        // Half-open is IPv4 only. Under `auto`, v6 targets go to connect instead of
        // being named as unscanned; under `syn`, `zhen ports` has already refused them.
        let ports: any PortScanning = useSYN && portScanType == .auto
            ? FamilyRoutedPortScan(
                v4: chosen,
                v6: BannerProbingPortScan(base: TCPConnectScanEngine(concurrency: effective)))
            : chosen

        let discovery: any HostDiscovery = refusal == nil
            // Composed, not substituted. An either/or branch here would make `sudo`
            // find a DIFFERENT set of hosts rather than a larger one — losing every
            // host that answers ICMP from behind a proxy-ARP boundary — and "root must
            // never find fewer" is the property `.composite` exists to hold.
            //
            // The ARP sweep leads, so its hardware addresses win a contested merge:
            // a MAC read off a reply this scan provoked beats one read out of a cache
            // that may predate it.
            ? CompositeDiscoveryEngine(
                [
                    BPFDiscoveryEngine(concurrency: effective, budgets: budgets, capture: source),
                    unprivileged,
                ],
                name: "darwin-composite"
            )
            : unprivileged
        let naming = DarwinNameResolver()
        let notice = Self.notice(for: refusal)
        #else
        // ── iPadOS: the unprivileged composition, and nothing to attempt ──────────
        //
        // There is no `/dev/bpf*` to open and no helper to ask, so `capture` has nothing
        // to choose between and the composition is the one macOS falls back to: the
        // ICMP sweep, and connect with banners. Silent, as a refused open is silent on
        // macOS — this is the platform's normal state, and the descriptor already
        // says which capabilities are absent.
        //
        // SSDP is off because the M-SEARCH is a multicast send, which iOS gives only to
        // an app holding the managed `com.apple.developer.networking.multicast`
        // entitlement. Without it the send fails and the source would be counted as
        // asked; off, it is never named as a source that went quiet.
        _ = primary  // asked for its failure above; nothing here probes it
        if portScanType == .syn {
            throw PlatformError.unavailable(
                "--scan-type syn needs a packet-capture device, and iPadOS has none. "
                + "Use --scan-type connect, which is what runs here anyway."
            )
        }
        let ports: any PortScanning = BannerProbingPortScan(
            base: TCPConnectScanEngine(concurrency: effective)
        )
        let discovery: any HostDiscovery = unprivileged
        let naming = DarwinNameResolver(usesSSDP: false)
        let notice: Degradation? = nil
        #endif

        return DarwinScanner(
            interfaces: interfaces,
            neighbors: SystemNeighborCache.current,
            discovery: discovery,
            ports: ports,
            naming: naming,
            descriptorLimit: granted,
            concurrency: effective,
            privilegedEngineNotice: notice
        )
    }

    #if os(macOS)
    /// Turns a refused BPF open into something worth putting in the artifact, or
    /// nothing.
    ///
    /// `.notPrivileged` returns nil. Not being root is the normal state of this program
    /// and the unprivileged engine is the product, so announcing it on every scan would
    /// train a reader to ignore the degradation list — which is where the things that
    /// genuinely went wrong live.
    static func notice(for refusal: BPFUnavailable?) -> Degradation? {
        // Two silences, for the same reason. Not being root is the normal state of this
        // program, and so is having no helper installed — most people never will. A
        // degradation on every scan for either would train a reader to skip the list,
        // which is where the things that actually cost them hosts appear. A helper that
        // is present and REFUSED is a different matter and is reported.
        guard let refusal, refusal != .notPrivileged, refusal != .helperAbsent else {
            return nil
        }
        return Degradation(stage: .setup, reason: refusal.reason, recoverable: true)
    }
    #endif

    /// What this platform can do, for a surface that wants to explain an absence.
    public var capabilities: EngineCapabilities {
        discovery.descriptor.capabilities.union(ports.descriptor.capabilities)
    }

    /// A descriptor naming the composition rather than either half of it.
    ///
    /// The kind comes from the discovery engine that was actually assembled rather than
    /// being written in. It said `.unprivileged` unconditionally until the layer-2 sweep
    /// existed, at which point a hard-coded kind would have described a composite scan
    /// as an unprivileged one — the exact class of claim the study withdrew H3 over.
    public var descriptor: EngineDescriptor {
        EngineDescriptor(
            name: discovery.descriptor.kind == .composite ? "darwin-composite" : "darwin-unprivileged",
            kind: discovery.descriptor.kind,
            capabilities: capabilities
        )
    }

    /// Whether a requested concurrency had to be clamped, and to what.
    ///
    /// Returned as a `Degradation` so it travels in the artifact with everything else
    /// that did not go as asked, rather than as a log line the JSON consumer never sees.
    public static func clampNotice(requested: Int?, granted: Int, effective: Int) -> Degradation? {
        guard let requested, requested > effective else { return nil }
        return Degradation(
            stage: .setup,
            reason: """
                A concurrency of \(requested) was requested but the process can hold \
                \(granted) open files, so it was clamped to \(effective). More probes in \
                flight than the descriptor table allows makes the slowest probe slower, \
                not the scan faster.
                """,
            recoverable: true
        )
    }
}

#endif
