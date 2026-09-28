// FamilyRoutedPortScan.swift — `auto` means the best mechanism for each target.
//
// With a capture device, `auto` picks the half-open scan, and half-open is IPv4 only.
// Handing it a v6 target would get that target named in a degradation and not scanned —
// honest, and not what a person who asked for "whatever works" asked for. This sends
// the v4 targets to the chosen engine and the v6 ones to one that speaks v6, and joins
// the answers.
//
// Only `auto` is routed. An explicit `--scan-type syn` with a v6 target is refused
// before anything is sent: substituting a mechanism the person named is the defect
// `--scan-type` exists to prevent.

/// Two port engines, one per address family, presented as one.
public struct FamilyRoutedPortScan: PortScanning {
    private let v4: any PortScanning
    private let v6: any PortScanning

    /// - Parameters:
    ///   - v4: the engine for IPv4 targets. Its descriptor is this engine's.
    ///   - v6: the engine for IPv6 targets.
    public init(v4: any PortScanning, v6: any PortScanning) {
        self.v4 = v4
        self.v6 = v6
    }

    /// The v4 engine's, unchanged. What was actually exercised on a given run is in the
    /// result's `usedCapabilities`, which is where a reader looks for it.
    public var descriptor: EngineDescriptor { v4.descriptor }

    /// With targets of one family this is exactly that family's engine — so a v4-only
    /// run is byte-for-byte what it was before this type existed. With both, the two run
    /// one after the other against the same deadline and their results are joined by
    /// `PortScanResult.combined(with:)`, which keeps the worse outcome.
    public func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> PortScanResult {
        let v4Targets = targets.filter { $0.v4 != nil }
        let v6Targets = targets.filter { $0.v6 != nil }
        if v6Targets.isEmpty {
            return await v4.scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                                 deadline: deadline, progress: progress)
        }
        if v4Targets.isEmpty {
            return await v6.scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                                 deadline: deadline, progress: progress)
        }
        let first = await v4.scan(v4Targets, ports: ports, perHostDeadline: perHostDeadline,
                                  deadline: deadline, progress: progress)
        let second = await v6.scan(v6Targets, ports: ports, perHostDeadline: perHostDeadline,
                                   deadline: deadline, progress: progress)
        return first.combined(with: second)
    }

    /// Streaming form, built on the terminal one like every other port engine here.
    public func stream(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task { [self] in
            let result = await scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                                    deadline: deadline, progress: sink)
            for (ip, observations) in result.ipv4Hosts {
                sink(.hostUpdated(HostFacts(ip: ip, ports: observations)))
            }
            finish()
        }
        return AsyncStream { continuation in
            Task {
                for await event in stream { continuation.yield(event) }
                continuation.finish()
            }
            continuation.onTermination = { _ in work.cancel() }
        }
    }
}
