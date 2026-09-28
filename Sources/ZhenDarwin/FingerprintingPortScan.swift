// FingerprintingPortScan.swift — one more question asked of the hosts that answered.
//
// A second decorator rather than a bigger one, composed over the banner probe the same
// way the banner probe composes over the verdict engine:
//
//     FingerprintingPortScan(BannerProbingPortScan(SYNScanEngine()))
//
// Each layer adds exactly one capability and knows nothing about the others, which is
// what lets the unprivileged path drop this layer and the privileged path keep it
// without either engine learning about privilege.
//
// It runs last because it needs what the others produced: a fingerprint needs a SYN-ACK,
// a SYN-ACK needs an open port, and an open port is what the scan just established. It
// sends one probe per host rather than one per port — the stack is a property of the
// host, and asking it twice would only cost the target packets.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// A port scan whose hosts are then asked what stack they run.
public struct FingerprintingPortScan: PortScanning {
    /// Where the port verdicts and service names come from.
    public let base: any PortScanning
    /// The probe.
    public var probe: OSFingerprintProbe

    /// What the composition can do: the base engine's capabilities plus fingerprinting.
    public var descriptor: EngineDescriptor {
        EngineDescriptor(
            name: "\(base.descriptor.name)+osfp",
            kind: base.descriptor.kind,
            capabilities: base.descriptor.capabilities.union(OSFingerprintProbe.capability)
        )
    }

    /// Wraps a port-scanning engine.
    public init(base: any PortScanning, probe: OSFingerprintProbe = OSFingerprintProbe()) {
        self.base = base
        self.probe = probe
    }

    /// Terminal form, with an optional observer.
    public func scan(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> PortScanResult {
        var result = await base.scan(
            targets, ports: ports, perHostDeadline: perHostDeadline,
            deadline: deadline, progress: progress
        )
        guard !deadline.isExpired, !Task.isCancelled else { return result }

        // The lowest open port on each host. Any open port elicits the same SYN-ACK, so
        // the choice does not affect the answer — taking the lowest only makes two runs
        // of an unchanged network probe the same port and produce comparable captures.
        var openPort: [IPv4Address: UInt16] = [:]
        for (ip, observations) in result.ipv4Hosts {
            if let lowest = observations.filter({ $0.state == .open }).map(\.port).min() {
                openPort[ip] = lowest
            }
        }
        guard !openPort.isEmpty else { return result }

        let outcome = await probe.fingerprint(openPort, deadline: deadline)
        result.fingerprints = outcome.fingerprints
        result.degradations.append(contentsOf: outcome.degradations)
        result.usedCapabilities.formUnion(outcome.used)
        return result
    }

    /// Streaming form.
    public func stream(
        _ targets: [IPAddress],
        ports: PortSpec,
        perHostDeadline: Duration,
        deadline: Deadline
    ) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task { [self] in
            _ = await scan(targets, ports: ports, perHostDeadline: perHostDeadline,
                           deadline: deadline, progress: sink)
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

#endif
