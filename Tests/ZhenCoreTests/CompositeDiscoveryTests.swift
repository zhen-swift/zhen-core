// CompositeDiscoveryTests.swift — the property the whole composite exists to hold.
//
// "Running as root must never find fewer hosts than running unprivileged" is the reason
// `EngineKind.composite` exists and the reason discovery is a protocol. It is also the
// kind of claim that is easy to state and easy to break later, because the obvious
// refactor — one engine chosen by a flag — looks tidier and silently loses every host
// the other one would have reached.
//
// So it is tested here, against stubs, in core. No sockets, no root, no network: the
// merge is composition over the protocol and it should be provable on a machine with no
// interface at all. That is also what lets these run on Linux, where the real engines do
// not exist yet.

import Synchronization
import Testing
@testable import ZhenCore

/// A discovery engine that returns what it was told to, optionally after a delay.
private struct StubEngine: HostDiscovery {
    let descriptor: EngineDescriptor
    let result: DiscoveryResult
    /// Held before returning, so a test can make the engines finish out of order.
    var delay: Duration = .zero

    init(
        name: String,
        kind: EngineKind = .unprivileged,
        capabilities: EngineCapabilities = [],
        result: DiscoveryResult,
        delay: Duration = .zero
    ) {
        self.descriptor = EngineDescriptor(name: name, kind: kind, capabilities: capabilities)
        self.result = result
        self.delay = delay
    }

    func discover(
        _ target: ScanTarget, deadline: Deadline, progress: ProgressSink
    ) async -> DiscoveryResult {
        if delay > .zero { try? await Task.sleep(for: delay) }
        for host in result.hosts { progress(.hostFound(host)) }
        return result
    }

    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent> {
        AsyncStream { $0.finish() }
    }
}

private enum Fixture {
    static func ip(_ last: UInt8) -> IPv4Address { IPv4Address(raw: 0x0A0A_1400 | UInt32(last)) }
    static func mac(_ last: UInt8) -> MACAddress { MACAddress(raw: 0xAA_BB_CC_00_00_00 | UInt64(last)) }

    static var target: ScanTarget {
        ScanTarget(
            network: IPv4Network("10.10.20.0/24")!,
            interface: NetworkInterface(
                name: "en0", address: ip(42), network: IPv4Network("10.10.20.0/24")!
            )
        )
    }

    static func stage(
        elapsed: Double, probes: Int, replies: Int,
        retransmit: Double? = nil, tail: Double? = nil, policy: String? = nil
    ) -> StageTiming {
        StageTiming(
            stage: .discovery, elapsedMillis: elapsed, probesSent: probes,
            repliesSeen: replies, hostsFound: nil,
            retransmitBudgetMillis: retransmit, tailBudgetMillis: tail,
            budgetPolicy: policy
        )
    }

    static func result(
        _ hosts: [HostFacts],
        degradations: [Degradation] = [],
        capabilities: EngineCapabilities = [],
        outcome: Outcome = .complete,
        timing: Timing = Timing()
    ) -> DiscoveryResult {
        DiscoveryResult(
            hosts: hosts, degradations: degradations, usedCapabilities: capabilities,
            outcome: outcome, timing: timing
        )
    }
}

@Suite("Composition never finds fewer hosts than its parts")
struct CompositeDiscoveryTests {
    @Test("The result is the union, not one side or the other")
    func union() async {
        // The failure this exists to prevent: an either/or branch that picks the
        // privileged engine when it is available and thereby loses every host that
        // answers ICMP and not ARP. A user who typed `sudo` to get more would get a
        // different set with a hole in it.
        let arp = StubEngine(
            name: "arp", kind: .privilegedBPF, capabilities: [.arpSweep],
            result: Fixture.result([
                HostFacts(ip: Fixture.ip(1), mac: Fixture.mac(1)),
                HostFacts(ip: Fixture.ip(2), mac: Fixture.mac(2)),
            ], capabilities: [.arpSweep])
        )
        let icmp = StubEngine(
            name: "icmp", capabilities: [.icmpSweep],
            result: Fixture.result([
                HostFacts(ip: Fixture.ip(2)),
                HostFacts(ip: Fixture.ip(3), ttl: 64),
            ], capabilities: [.icmpSweep])
        )

        let composite = CompositeDiscoveryEngine([arp, icmp])
        let result = await composite.discover(
            Fixture.target, deadline: Deadline(after: .seconds(1))
        )

        #expect(result.hosts.map(\.ip) == [Fixture.ip(1), Fixture.ip(2), Fixture.ip(3)])
        // Every host either engine found is present. Stated as a superset rather than
        // as an equality, because that is the property that must not regress.
        let found = Set(result.hosts.map(\.ip))
        #expect(found.isSuperset(of: arp.result.hosts.map(\.ip)))
        #expect(found.isSuperset(of: icmp.result.hosts.map(\.ip)))
        #expect(result.usedCapabilities == [.arpSweep, .icmpSweep])
    }

    @Test("The composition says it is a composition, and what it can do")
    func descriptor() {
        let composite = CompositeDiscoveryEngine([
            StubEngine(name: "arp", kind: .privilegedBPF, capabilities: [.arpSweep],
                       result: Fixture.result([])),
            StubEngine(name: "icmp", capabilities: [.icmpSweep, .neighborTable],
                       result: Fixture.result([])),
        ])
        #expect(composite.descriptor.kind == .composite)
        #expect(composite.descriptor.capabilities == [.arpSweep, .icmpSweep, .neighborTable])
    }

    @Test("Precedence is the array's, and it fills gaps rather than overwriting facts")
    func precedence() {
        let leading = HostFacts(
            ip: Fixture.ip(5), mac: Fixture.mac(5),
            allNames: [NameCandidate(value: "kitchen", source: .mdns)]
        )
        let trailing = HostFacts(
            ip: Fixture.ip(5), mac: Fixture.mac(99),
            allNames: [NameCandidate(value: "KITCHEN", source: .netbios)],
            vendor: "Acme", ttl: 64
        )

        let merged = leading.merged(with: trailing)
        // A contested field goes to the leading engine: a MAC read off an ARP reply
        // this scan provoked beats one read out of a cache that may predate it.
        #expect(merged.mac == Fixture.mac(5))
        // An absent field is filled from whoever has it. Two engines looking at one
        // segment know different things and the union of what they know is the point.
        #expect(merged.vendor == "Acme")
        #expect(merged.ttl == 64)
        // Names accumulate, losers included. Explaining why a device is named what it
        // is *is* the feature, and a merge that kept only winners would destroy the
        // field the detail view is built out of.
        #expect(merged.allNames.count == 2)
        #expect(merged.displayName == "kitchen")
    }

    @Test("Merging is decided by engine order, not by which one finished first")
    func mergeIsDeterministic() async {
        // The leading engine is also the slow one. If precedence followed completion
        // order the result would flip, and two runs of an unchanged network would
        // disagree about a hardware address for no reason a reader could ever find.
        let slowLeader = StubEngine(
            name: "arp", kind: .privilegedBPF, capabilities: [.arpSweep],
            result: Fixture.result([HostFacts(ip: Fixture.ip(7), mac: Fixture.mac(7))]),
            delay: .milliseconds(40)
        )
        let quickFollower = StubEngine(
            name: "icmp", capabilities: [.icmpSweep],
            result: Fixture.result([HostFacts(ip: Fixture.ip(7), mac: Fixture.mac(70))])
        )
        let result = await CompositeDiscoveryEngine([slowLeader, quickFollower]).discover(
            Fixture.target, deadline: Deadline(after: .seconds(2))
        )
        #expect(result.hosts.count == 1)
        #expect(result.hosts[0].mac == Fixture.mac(7))
    }

    @Test("A composition is only as finished as its least finished part")
    func outcomeTakesTheWorst() {
        // Reporting `.complete` over a half-gathered device list would tell a consumer
        // the results are exhaustive when one engine never returned.
        #expect(CompositeDiscoveryEngine.worse(.complete, .deadlineExpired) == .deadlineExpired)
        #expect(CompositeDiscoveryEngine.worse(.deadlineExpired, .complete) == .deadlineExpired)
        #expect(CompositeDiscoveryEngine.worse(.deadlineExpired, .cancelled) == .cancelled)
        #expect(CompositeDiscoveryEngine.worse(.complete, .complete) == .complete)

        let merged = CompositeDiscoveryEngine.merge([
            Fixture.result([HostFacts(ip: Fixture.ip(1))], outcome: .complete),
            Fixture.result([HostFacts(ip: Fixture.ip(2))], outcome: .deadlineExpired),
        ])
        #expect(merged.outcome == .deadlineExpired)
        // And the partial results survive, because a deadline hit is a normal return
        // carrying what was gathered rather than a failure.
        #expect(merged.hosts.count == 2)
    }

    @Test("Every engine's degradations reach the artifact")
    func degradationsAreKept() {
        let merged = CompositeDiscoveryEngine.merge([
            Fixture.result([], degradations: [
                Degradation(stage: .discovery, reason: "one", recoverable: true),
            ]),
            Fixture.result([], degradations: [
                Degradation(stage: .discovery, reason: "two", recoverable: false),
            ]),
        ])
        #expect(merged.degradations.map(\.reason) == ["one", "two"])
    }

    @Test("One discovery stage, summed counts, and the budgets that explain its elapsed time")
    func timingMerge() {
        // Two stages both called `discovery` would leave a consumer no field to tell
        // them apart, so the composite reports one. Counts are sums because they are
        // counts of things that happened; the elapsed time is the maximum because the
        // engines ran at once; and the budgets come from the sweep that took that long,
        // so the schedule reported is the one that explains the number beside it.
        let merged = CompositeDiscoveryEngine.merge([
            Fixture.result(
                [HostFacts(ip: Fixture.ip(1))],
                timing: Timing(
                    stages: [Fixture.stage(elapsed: 120, probes: 700, replies: 9,
                                           retransmit: 30, tail: 250, policy: "split")],
                    counters: ProbeCounterSnapshot(probesSent: 700, repliesSeen: 9,
                                                   peakConcurrency: 128, inFlight: 0)
                )
            ),
            Fixture.result(
                [HostFacts(ip: Fixture.ip(2))],
                timing: Timing(
                    stages: [Fixture.stage(elapsed: 380, probes: 750, replies: 8,
                                           retransmit: 100, tail: 400, policy: "split")],
                    counters: ProbeCounterSnapshot(probesSent: 750, repliesSeen: 8,
                                                   peakConcurrency: 256, inFlight: 0)
                )
            ),
        ])

        #expect(merged.timing.stages.count == 1)
        let stage = merged.timing.stages[0]
        #expect(stage.stage == .discovery)
        #expect(stage.elapsedMillis == 380)
        #expect(stage.probesSent == 1450)
        #expect(stage.repliesSeen == 17)
        #expect(stage.hostsFound == 2)
        #expect(stage.retransmitBudgetMillis == 100)
        #expect(stage.tailBudgetMillis == 400)
        #expect(merged.timing.peakConcurrency == 256)
    }

    @Test("A composition of one is that engine, wearing the composite label")
    func singleEngine() async {
        // What makes the caller's assembly free of "did the privileged engine open?"
        // branches: it builds a composite either way and the shape does not change.
        let only = StubEngine(
            name: "icmp", capabilities: [.icmpSweep],
            result: Fixture.result([HostFacts(ip: Fixture.ip(3))], capabilities: [.icmpSweep])
        )
        let composite = CompositeDiscoveryEngine([only])
        let result = await composite.discover(
            Fixture.target, deadline: Deadline(after: .seconds(1))
        )
        #expect(composite.descriptor.kind == .composite)
        #expect(result.hosts.map(\.ip) == [Fixture.ip(3)])
        #expect(result.usedCapabilities == [.icmpSweep])
    }

    @Test("Both engines feed the live display, even though the artifact does not come from it")
    func progressReachesTheSink() async {
        let seen = EventBox()
        let composite = CompositeDiscoveryEngine([
            StubEngine(name: "arp", kind: .privilegedBPF, capabilities: [.arpSweep],
                       result: Fixture.result([HostFacts(ip: Fixture.ip(1))])),
            StubEngine(name: "icmp", capabilities: [.icmpSweep],
                       result: Fixture.result([HostFacts(ip: Fixture.ip(2))])),
        ])
        _ = await composite.discover(
            Fixture.target, deadline: Deadline(after: .seconds(1)),
            progress: ProgressSink { seen.record($0) }
        )
        #expect(seen.hosts == Set([Fixture.ip(1), Fixture.ip(2)]))
    }

    @Test("Port observations accumulate rather than replacing each other")
    func portsMerge() {
        let left = HostFacts(ip: Fixture.ip(8), ports: [
            PortObservation(port: 80, proto: .tcp, state: .open),
        ])
        let right = HostFacts(ip: Fixture.ip(8), ports: [
            PortObservation(port: 80, proto: .tcp, state: .closed),
            PortObservation(port: 443, proto: .tcp, state: .open),
        ])
        let merged = left.merged(with: right)
        #expect(merged.ports.count == 2)
        // The leading observation of a port wins; the one the other engine also saw is
        // not appended twice.
        #expect(merged.ports.first { $0.port == 80 }?.state == .open)
        #expect(merged.ports.first { $0.port == 443 }?.state == .open)
    }
}

/// Collects what a `ProgressSink` was handed.
private final class EventBox: @unchecked Sendable {
    private let lock = Mutex<Set<IPv4Address>>([])
    func record(_ event: ProbeEvent) {
        guard case .hostFound(let host) = event else { return }
        lock.withLock { $0.insert(host.ip) }
    }
    var hosts: Set<IPv4Address> { lock.withLock { $0 } }
}
