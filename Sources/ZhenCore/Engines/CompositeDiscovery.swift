// CompositeDiscovery.swift — running as root must never find fewer hosts.
//
// That sentence is the whole reason `EngineKind` has a `.composite` case and the whole
// reason discovery is a protocol rather than a class with a flag. The obvious design —
// "if privileged, use the BPF engine, otherwise use the ICMP one" — is an either/or
// branch, and an either/or branch loses hosts: the ARP sweep reaches a host that filters
// ICMP, the ICMP sweep reaches a host on the far side of a proxy-ARP boundary, and a
// user who typed `sudo` to get *more* would get a different set with a hole in it. The
// only defensible relationship between the two engines is a union.
//
// So this runs its engines and merges. It knows nothing about privilege, nothing about
// BPF and nothing about ICMP — it is composition over the protocol, which is why it
// lives in core and compiles on Linux, where a future `ZhenLinux` will hand it two
// entirely different engines.
//
// ── Concurrently, not one after the other ────────────────────────────────────────
//
// Sequential composition would make `sudo zhen scan` take twice as long as the
// unprivileged run, which is the same failure as finding fewer hosts wearing a
// stopwatch: the user paid a password for a worse experience. Both engines get the
// whole deadline and run at once. They are probing the same segment with different
// protocols at a few hundred frames each, which is nothing a LAN notices.
//
// The cost of that choice is stated where it falls: `BPFSweep.swift` explains why an
// ARP round trip measured while an ICMP sweep is running beside it is not attributable,
// and therefore why that engine reports no per-host RTT.

/// Several discovery engines, reported as their union.
///
/// The descriptor is `.composite` and its capabilities are the union of the parts', so
/// a surface asking "can this scan do a layer-2 sweep?" gets the right answer without
/// knowing how many engines are underneath.
public struct CompositeDiscoveryEngine: HostDiscovery {
    /// The engines, in precedence order.
    ///
    /// Order decides only which value wins when two engines report *different*
    /// non-nil facts about one host — a MAC read off an ARP reply should beat one read
    /// out of a cache — and nothing else. It never decides which hosts appear: that is
    /// a union and is order-independent by construction.
    public let engines: [any HostDiscovery]

    /// Which engine this is and what the composition can do.
    public let descriptor: EngineDescriptor

    /// Composes engines, in precedence order.
    ///
    /// - Parameters:
    ///   - engines: at least one. A composite of one is legal and behaves as that
    ///     engine with a `.composite` label, which is what makes the caller's
    ///     assembly code free of "did the privileged engine open?" branches.
    ///   - name: how the composition identifies itself in the artifact.
    public init(_ engines: [any HostDiscovery], name: String = "composite") {
        self.engines = engines
        self.descriptor = EngineDescriptor(
            name: name,
            kind: .composite,
            capabilities: engines.reduce(into: EngineCapabilities()) {
                $0.formUnion($1.descriptor.capabilities)
            }
        )
    }

    /// Terminal form, with an optional observer.
    ///
    /// Every engine's events reach the sink as they happen, so a live display shows a
    /// host the moment either sweep hears from it. A host both engines find is emitted
    /// twice; the sink is for display and the artifact comes from the returned value,
    /// which is exactly the separation `HostDiscovery` documents.
    public func discover(
        _ target: ScanTarget, deadline: Deadline, progress: ProgressSink
    ) async -> DiscoveryResult {
        guard !engines.isEmpty else { return DiscoveryResult() }
        guard engines.count > 1 else {
            return await engines[0].discover(target, deadline: deadline, progress: progress)
        }

        let results = await withTaskGroup(
            of: (Int, DiscoveryResult).self, returning: [Int: DiscoveryResult].self
        ) { group in
            for (index, engine) in engines.enumerated() {
                group.addTask {
                    (index, await engine.discover(target, deadline: deadline, progress: progress))
                }
            }
            var collected: [Int: DiscoveryResult] = [:]
            for await (index, result) in group { collected[index] = result }
            return collected
        }
        // Re-ordered by engine rather than by completion, so precedence is the array's
        // and not a race's. An engine that finished first would otherwise win every
        // contested field, which would make the merge non-deterministic.
        return Self.merge(engines.indices.compactMap { results[$0] })
    }

    /// Streaming form: hosts from every engine, as they answer.
    public func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent> {
        let (stream, sink, finish) = ProbeStream.sinking(buffering: .progress)
        let work = Task {
            _ = await discover(target, deadline: deadline, progress: sink)
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

    /// Folds several results into one.
    ///
    /// Exposed rather than private because it is the part with the rules in it, and a
    /// rule that cannot be tested without opening a socket is a rule nobody checks.
    public static func merge(_ results: [DiscoveryResult]) -> DiscoveryResult {
        guard let first = results.first else { return DiscoveryResult() }
        guard results.count > 1 else { return first }

        var hosts: [IPv4Address: HostFacts] = [:]
        var order: [IPv4Address] = []
        var degradations: [Degradation] = []
        var capabilities = EngineCapabilities()
        var outcome = Outcome.complete

        for result in results {
            for host in result.hosts {
                if let existing = hosts[host.ip] {
                    hosts[host.ip] = existing.merged(with: host)
                } else {
                    hosts[host.ip] = host
                    order.append(host.ip)
                }
            }
            degradations.append(contentsOf: result.degradations)
            capabilities.formUnion(result.usedCapabilities)
            outcome = Self.worse(outcome, result.outcome)
        }

        return DiscoveryResult(
            hosts: order.compactMap { hosts[$0] }.sorted { $0.ip < $1.ip },
            degradations: degradations,
            usedCapabilities: capabilities,
            outcome: outcome,
            timing: Self.mergeTiming(results, hostsFound: hosts.count),
            // Only the unprivileged sweep watches, so at most one part has a report.
            neighborWatch: results.lazy.compactMap(\.neighborWatch).first
        )
    }

    /// The less complete of two outcomes.
    ///
    /// A composition is as finished as its least finished part. One engine completing
    /// while the other was cancelled is a cancelled scan carrying partial results, and
    /// reporting `.complete` over it would tell a consumer the device list is
    /// exhaustive when half of it was never gathered.
    static func worse(_ lhs: Outcome, _ rhs: Outcome) -> Outcome {
        let rank: (Outcome) -> Int = { outcome in
            switch outcome {
            case .complete: 0
            case .deadlineExpired: 1
            case .cancelled: 2
            }
        }
        return rank(lhs) >= rank(rhs) ? lhs : rhs
    }

    /// One discovery stage describing the composition.
    ///
    /// Not one stage per engine. A consumer reading `timing.stages` would then find
    /// `discovery` twice with no field distinguishing them, which is worse than either
    /// summarising or omitting.
    ///
    /// The rule for the fields that cannot be summed: **the budgets reported are those
    /// of the sweep that took longest.** Elapsed time is the maximum, because the
    /// engines ran concurrently and the stage lasted as long as the slowest; the
    /// retransmit and declaration budgets are the ones that explain that number, so
    /// taking them from any other sweep would put a schedule next to an elapsed time it
    /// did not produce. Probes and replies are sums, because they are counts of things
    /// that actually happened.
    static func mergeTiming(_ results: [DiscoveryResult], hostsFound: Int) -> Timing {
        let stages = results.flatMap(\.timing.stages)
        guard let longest = stages.max(by: { $0.elapsedMillis < $1.elapsedMillis }) else {
            return Timing()
        }
        var merged = longest
        merged.probesSent = stages.reduce(0) { $0 + $1.probesSent }
        merged.repliesSeen = stages.reduce(0) { $0 + $1.repliesSeen }
        merged.hostsFound = hostsFound

        let counters = ProbeCounterSnapshot(
            probesSent: results.reduce(0) { $0 + $1.timing.probesSent },
            repliesSeen: results.reduce(0) { $0 + $1.timing.repliesSeen },
            peakConcurrency: results.map(\.timing.peakConcurrency).max() ?? 0,
            inFlight: 0
        )
        return Timing(stages: [merged], counters: counters)
    }
}

extension HostFacts {
    /// Folds another observation of the same host into this one.
    ///
    /// **This one wins every contested field.** Both engines looked at the same segment
    /// in the same second, so a genuine disagreement about a MAC or a TTL means one of
    /// them is wrong rather than that they should be averaged, and the caller ordered
    /// them by which it trusts. What is merged rather than chosen is the parts that
    /// accumulate: name candidates and port observations are evidence, and evidence
    /// from two sources is more of it.
    ///
    /// Names keep their losers, here as everywhere. Explaining why a device is named
    /// what it is is the product feature, and a merge that kept only winners would
    /// destroy exactly the field the detail view is built out of.
    public func merged(with other: HostFacts) -> HostFacts {
        var seen = Set(allNames)
        var names = allNames
        for candidate in other.allNames where seen.insert(candidate).inserted {
            names.append(candidate)
        }

        var ports = self.ports
        var keys = Set(ports.map { ObservedPort(port: $0.port, proto: $0.proto) })
        for observation in other.ports
        where keys.insert(ObservedPort(port: observation.port, proto: observation.proto)).inserted {
            ports.append(observation)
        }

        return HostFacts(
            ip: ip,
            mac: mac ?? other.mac,
            allNames: names,
            vendor: vendor ?? other.vendor,
            reverseDNS: reverseDNS ?? other.reverseDNS,
            dhcpHostname: dhcpHostname ?? other.dhcpHostname,
            ttl: ttl ?? other.ttl,
            rtt: rtt ?? other.rtt,
            ports: ports,
            // Unioned rather than preferred. Two engines reaching the same host by two
            // routes is the strongest statement a composition can make, and keeping
            // only one of them would throw away the agreement.
            osFingerprint: osFingerprint ?? other.osFingerprint,
            discoveredVia: discoveredVia.union(other.discoveredVia),
            // As a pair: a time from one engine with the other's cold flag is neither.
            firstContact: firstContact ?? other.firstContact,
            firstContactCold: firstContact != nil ? firstContactCold : other.firstContactCold,
            // Found when the first engine found it.
            foundAt: [foundAt, other.foundAt].compactMap(\.self).min()
        )
    }
}

/// The identity of a port observation, for deduplication during a merge.
private struct ObservedPort: Hashable {
    var port: UInt16
    var proto: TransportProtocol
}
