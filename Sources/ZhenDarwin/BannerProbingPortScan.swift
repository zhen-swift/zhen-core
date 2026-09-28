// BannerProbingPortScan.swift — a port scan, and then asking the open ones what they are.
//
// A decorator rather than a fourth engine, because "which ports are open" and "what is
// on them" are two questions and only the first one has two answers. Under root the
// verdicts come from `SYNScanEngine`; without it they come from `TCPConnectScanEngine`;
// either way the banners come from here, and neither of those engines had to learn
// about the other.
//
// It also keeps a rule the half-open scan would otherwise break. A banner needs a
// *completed* handshake, which is exactly the thing half-open declines to perform — so
// a privileged scan that wanted service identities would have had to abandon SYN
// probing or grow a second connect path inside it. Composing them instead means the SYN
// scan decides the verdicts on every port and a full connection is opened only to the
// handful that turned out to be open.
//
// ── The budget, and why banners go last ─────────────────────────────────────────
//
// The verdicts are the load-bearing result: a port list with no service names is
// useful, and service names with no port list is nothing. So the base scan runs against
// the whole deadline and the banners take what is left, which on a LAN is nearly all of
// it — a deep scan of a /24 across a few dozen ports settles in well under a second.
// When the base scan does spend the budget, the banners are skipped and the artifact
// says so rather than silently reporting fewer identities than it could have found.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// A port scan whose open ports are then asked what they are.
public struct BannerProbingPortScan: PortScanning {
    /// Where the verdicts come from.
    public let base: any PortScanning
    /// How the open ones are identified.
    public var probe: BannerProbe
    /// How many banner conversations run at once.
    ///
    /// Much smaller than the scan's window. A banner probe holds a descriptor open for
    /// up to a second and there are only ever a handful of open ports, so a wide pool
    /// would buy nothing and hold descriptors the deep scan may still want.
    public var concurrency: Int

    /// What the composition can do: the base engine's capabilities plus banners.
    public var descriptor: EngineDescriptor {
        EngineDescriptor(
            name: "\(base.descriptor.name)+banner",
            kind: base.descriptor.kind,
            capabilities: base.descriptor.capabilities.union([.bannerProbe])
        )
    }

    /// Wraps a port-scanning engine.
    public init(
        base: any PortScanning,
        probe: BannerProbe = BannerProbe(),
        concurrency: Int = 16
    ) {
        self.base = base
        self.probe = probe
        self.concurrency = concurrency
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

        // Only the open ones. A closed port has already told us everything it will —
        // the host is there and said no — and a filtered one has told us nothing, so
        // connecting to either would spend the budget learning what we know.
        // Identification is v4-only: the TLS half goes through Network.framework, where a
        // scoped v6 endpoint needs an `NWInterface`, and that is not built. An absent
        // service means "not observed", and these were not even asked, so say so.
        let unasked = result.ports.filter { $0.key.v6 != nil }
            .flatMap(\.value).filter { $0.state == .open }.count
        if unasked > 0 {
            result.degradations.append(Degradation(
                stage: .deepScan,
                reason: """
                    \(unasked) open port\(unasked == 1 ? "" : "s") on IPv6 \
                    \(unasked == 1 ? "was" : "were") not asked what \
                    \(unasked == 1 ? "it is" : "they are"): service identification \
                    speaks IPv4 only. The port states are complete.
                    """,
                recoverable: false
            ))
        }

        let open = result.ipv4Hosts.flatMap { ip, observations in
            observations.filter { $0.state == .open }.map { (ip: ip, port: $0.port) }
        }
        guard !open.isEmpty else { return result }

        guard !deadline.isExpired, !Task.isCancelled else {
            result.degradations.append(Degradation(
                stage: .deepScan,
                reason: """
                    \(open.count) open port\(open.count == 1 ? "" : "s") \
                    \(open.count == 1 ? "was" : "were") found but the scan's budget was \
                    already spent, so nothing was asked what it is. The port states are \
                    complete; the service names are absent because they were not \
                    attempted, not because nothing answered.
                    """,
                recoverable: true
            ))
            return result
        }

        let identities = await boundedPool(
            over: open.map { OpenPort(ip: $0.ip, port: $0.port) },
            concurrency: concurrency,
            deadline: deadline
        ) { target -> ProbeOutcome<ServiceIdentity> in
            // `.silent` rather than an optional, which `boundedPool` refuses outright:
            // returning `ServiceIdentity?` would bind its result type to the optional
            // itself, so a port that said nothing would be stored as a nil identity and
            // the count of results would become "ports asked" instead of "ports that
            // answered". A port with nothing to say is the common case here.
            guard let identity = await probe.identify(
                target.ip, port: target.port, deadline: deadline
            ) else { return .silent }
            return .observed(identity)
        }

        var named = 0
        for (target, identity) in identities.results {
            guard var observations = result.ports[.v4(target.ip)] else { continue }
            guard let index = observations.firstIndex(where: { $0.port == target.port }) else {
                continue
            }
            observations[index].service = identity
            result.ports[.v4(target.ip)] = observations
            named += 1
        }

        if named > 0 { result.usedCapabilities.insert(.bannerProbe) }
        // Emitted so a live display shows the names filling in, and so the streaming
        // form has something to yield. The artifact comes from the returned value.
        for (ip, observations) in result.ipv4Hosts {
            progress(.hostUpdated(HostFacts(ip: ip, ports: observations)))
        }
        return result
    }

    /// Streaming form: the base engine's events, then the identities.
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

/// One open port, as the banner pool's work item.
private struct OpenPort: Sendable, Hashable {
    var ip: IPv4Address
    var port: UInt16
}

#endif
