// TransportSplitPortScan.swift — a spec's TCP ports to one engine, its UDP ports to another.
//
// `PortSpec` carries both halves, and the engines each read only their own: the TCP engine
// iterates `ports`, the UDP engine `udpPorts`. Handing a mixed spec to the TCP engine alone
// probes the TCP half and drops the rest without a word — which is what the app's
// `probePorts` did until this existed. The command line has always run both, inline; this
// is that composition as a value, so a second caller cannot forget the second half.
//
// A second engine rather than a second transport inside the first: the TCP engine is SYN
// or connect depending on what the platform granted, the UDP engine is always the same
// unprivileged one.

/// A port engine per transport, presented as one.
public struct TransportSplitPortScan: PortScanning {
    private let tcp: any PortScanning
    private let udp: any PortScanning
    /// The per-host budget for a UDP probe.
    ///
    /// A full second rather than the TCP ceiling, because for UDP silence is a verdict
    /// (`open_filtered`) and the resend at 40% of it needs room. The value `zhen ports`
    /// has always used.
    public let udpPerHostDeadline: Duration

    /// - Parameters:
    ///   - tcp: the engine for `spec.ports`. Its descriptor is this engine's.
    ///   - udp: the engine for `spec.udpPorts`.
    ///   - udpPerHostDeadline: the per-host budget for the UDP half.
    public init(tcp: any PortScanning, udp: any PortScanning, udpPerHostDeadline: Duration = .seconds(1)) {
        self.tcp = tcp
        self.udp = udp
        self.udpPerHostDeadline = udpPerHostDeadline
    }

    /// The TCP engine's, unchanged, as `FamilyRoutedPortScan` does with its v4 engine.
    /// Whether UDP was exercised on a given run is in the result's `usedCapabilities`.
    public var descriptor: EngineDescriptor { tcp.descriptor }

    /// With only TCP ports this is exactly the TCP engine; with only UDP ports, exactly
    /// the UDP one. With both, TCP runs first and UDP after it against the same deadline,
    /// and the results are joined by `PortScanResult.combined(with:)`.
    public func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> PortScanResult {
        var result = PortScanResult()
        if !ports.ports.isEmpty {
            result = await tcp.scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                                    deadline: deadline, progress: progress)
        }
        if !ports.udpPorts.isEmpty, !Task.isCancelled {
            let second = await udp.scan(targets, ports: ports, perHostDeadline: udpPerHostDeadline,
                                        deadline: deadline, progress: progress)
            result = ports.ports.isEmpty ? second : result.combined(with: second)
        }
        return result
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
