// NameResolver.swift — the naming stage: three sources, one budget, one cascade.
//
// The stage that turns a list of addresses into a list of things a person recognises.
// It owns no sockets and parses no bytes; it decides WHO IS ASKED, IN WHAT ORDER, FOR
// HOW LONG, and what to do when they disagree.
//
// ── Order, and why it is not "run all three" ─────────────────────────────────────
//
// mDNS and SSDP are BROADCAST QUESTIONS. Neither one is asked about a particular host —
// each shouts at the segment and listens — so running them one after the other would
// double the wall clock for exactly the same answers. They use different sockets and
// different protocols and contend for nothing, so they run CONCURRENTLY and each holds
// 70% of the stage budget.
//
// NetBIOS is a POINTED QUESTION, one datagram per host, and it is the weakest source on
// the list: its names are uppercase, fifteen characters, and often manufacturer-
// generated. So it runs LAST, over the hosts the first two failed to name, on the
// remaining 30%. Running it first, or over every host, would spend packets adding a
// worse name to devices that already have a good one.
//
// ── The early exit ───────────────────────────────────────────────────────────────
//
// A browse has no natural end. The sweep can ask "have all 254 addresses answered or
// timed out"; mDNS cannot, because nobody knows how many records exist. So the mDNS
// budget is a CEILING and the actual stop is quiescence: once records have started
// arriving and then stop for `NameBudget.quietPeriod`, the network has said what it is
// going to say and holding the stage open is spending the user's wall clock on nothing.
// It is the same shape as the sweep's adaptive tail — measure, then stop — applied to a
// source that cannot be counted, and it is what makes a six-second ceiling affordable:
// in practice the stage returns in about a second on a quiet network and takes the
// ceiling only when devices really are still answering.
#if canImport(Darwin)

import Darwin
import Foundation
import ZhenCore

/// The Apple-platform naming stage: Bonjour, then UPnP, then NetBIOS.
public struct DarwinNameResolver: NameResolving {
    /// How this stage identifies itself in the artifact.
    ///
    /// No `EngineCapabilities` bit describes naming, and inventing one would put a
    /// value in the wire format that no consumer knows how to read. The name is the
    /// identification.
    public let descriptor = EngineDescriptor(
        name: "darwin-naming", kind: .unprivileged, capabilities: []
    )

    /// Whether to browse Bonjour.
    public var usesMDNS: Bool
    /// Whether to search for UPnP devices.
    public var usesSSDP: Bool
    /// Whether to ask still-unnamed hosts for their NetBIOS node status.
    public var usesNetBIOS: Bool

    /// Creates the resolver.
    ///
    /// The three switches exist for tests and for a future `--no-mdns`, not because any
    /// of them is optional in normal operation.
    public init(usesMDNS: Bool = true, usesSSDP: Bool = true, usesNetBIOS: Bool = true) {
        self.usesMDNS = usesMDNS
        self.usesSSDP = usesSSDP
        self.usesNetBIOS = usesNetBIOS
    }

    /// Names what it can, within its slice of the run's budget.
    public func resolveNames(
        for addresses: [IPv4Address],
        on target: ScanTarget,
        deadline: Deadline,
        progress: ProgressSink
    ) async -> NameResolution {
        progress(.stageStarted(.naming))
        let watch = Stopwatch()
        let budget = NameBudget(within: deadline)
        let failures = DegradationLog()
        // Whether Bonjour actually worked, as opposed to merely being quiet. The
        // denial heuristic below is not allowed to speak without it.
        let health = BrowseHealth()
        let ssdpFailed = FailureFlag()
        let netbiosFailed = FailureFlag()
        // The remap target. This machine's own Bonjour records resolve to 127.0.0.1,
        // and without this its name lands on an address that is in no report.
        var ledger = NameLedger(localAddress: target.interface.address)

        // ── Phase one: the two broadcast questions, together ─────────────────────
        let (sightings, ssdpSightings) = await withTaskGroup(
            of: NameSourceHarvest.self
        ) { group -> ([ServiceSighting], [SSDPSighting]) in
            if usesMDNS {
                group.addTask {
                    .mdns(await Self.browse(
                        interface: target.interface, budget: budget.mdns,
                        failures: failures, health: health
                    ))
                }
            }
            if usesSSDP {
                group.addTask {
                    .ssdp(await Self.search(
                        interface: target.interface, budget: budget.ssdp,
                        failures: failures, failed: ssdpFailed
                    ))
                }
            }
            var bonjour: [ServiceSighting] = []
            var upnp: [SSDPSighting] = []
            for await harvest in group {
                switch harvest {
                case .mdns(let found): bonjour = found
                case .ssdp(let found): upnp = found
                }
            }
            return (bonjour, upnp)
        }

        for sighting in sightings {
            guard let candidate = BonjourVocabulary.candidate(from: sighting) else { continue }
            ledger.record(candidate, for: sighting.ip)
        }
        for sighting in ssdpSightings {
            // A UPnP responder with no description document still contributes nothing a
            // person can read — `SERVER: Linux/4.4 UPnP/1.0` is an HTTP stack, not a
            // name — so it is not offered as a candidate. It is not lost either: the
            // fetch failure is already a degradation.
            guard let name = sighting.friendlyName?.trimmed, !name.isEmpty else { continue }
            ledger.record(
                NameCandidate(value: name, source: .ssdp, model: sighting.modelName?.trimmed),
                for: sighting.ip
            )
        }

        // ── Phase two: the pointed question, only where it is still needed ───────
        var netbiosAsked = 0
        var netbiosAnswered = 0
        // The slice is struck HERE, not at the top of the stage — see `netbiosSlice()`.
        let netbiosDeadline = budget.netbiosSlice()
        if usesNetBIOS, !netbiosDeadline.isExpired, !Task.isCancelled {
            let unnamed = ledger.unnamed(among: addresses)
            netbiosAsked = unnamed.count
            if !unnamed.isEmpty {
                let query = DarwinNetBIOSQuery(failures: failures, failed: netbiosFailed)
                for await sighting in query.nodeStatus(
                    of: unnamed, from: target.interface, deadline: netbiosDeadline
                ) {
                    netbiosAnswered += 1
                    ledger.record(NameCandidate(value: sighting.name, source: .netbios), for: sighting.ip)
                    if let mac = sighting.mac { ledger.record(mac: mac, for: sighting.ip) }
                }
            }
        }

        var degradations = failures.all
        // The silent failure this whole project is shaped around. mDNS, SSDP and NetBIOS
        // all need the Local Network permission on current macOS, and DENIAL RETURNS
        // ZERO RESULTS RATHER THAN AN ERROR — every socket opens, every query goes out,
        // and nothing ever comes back.
        //
        // The inference is built from ONLY the sources that actually ran, and only when
        // none of them reported a failure of its own. Both guards were missing and both
        // made the tool lie: with `--no-ssdp` it named two sources that were never
        // asked, and when mDNSResponder restarted mid-scan it blamed a privacy setting
        // for a browse that had died of something else entirely. The arithmetic and the
        // wording live in core, where they can be tested without a network.
        var activity: [NameSourceActivity] = []
        if usesMDNS {
            activity.append(NameSourceActivity(
                source: .mdns, answered: sightings.count, failed: health.didFail
            ))
        }
        if usesSSDP {
            activity.append(NameSourceActivity(
                source: .ssdp, answered: ssdpSightings.count, failed: ssdpFailed.isRaised
            ))
        }
        if usesNetBIOS, netbiosAsked > 0 {
            activity.append(NameSourceActivity(
                source: .netbios, answered: netbiosAnswered, failed: netbiosFailed.isRaised
            ))
        }
        if let denial = NameSourceSilenceHeuristic.evaluate(
            activity, hostsProbed: addresses.count, advice: .appleForThisProcess
        ) {
            degradations.append(denial)
        }

        let outcome: Outcome = Task.isCancelled ? .cancelled
            : (budget.stage.isExpired ? .deadlineExpired : .complete)
        let timing = StageTiming(
            stage: .naming,
            elapsedMillis: watch.elapsedMillis,
            // A browse is not a probe count in the ICMP sense, so the honest reading is
            // "questions asked" and "records that came back". NetBIOS is the only source
            // that sends one datagram per host; the other two shout once at the segment.
            probesSent: (usesMDNS ? 1 : 0) + (usesSSDP ? 1 : 0) + netbiosAsked,
            repliesSeen: sightings.count + ssdpSightings.count + netbiosAnswered,
            hostsFound: ledger.namedCount,
            // The budget split, reported so the product decision at the top of
            // `NameBudget` can be argued with from the artifact rather than from a
            // comment. Read against `elapsedMillis`: a stage that came in well under its
            // allowance stopped because the network went quiet, and one that spent all
            // of it was cut off with records still arriving.
            nameStageBudgetMillis: budget.stageAllowance.milliseconds,
            nameSourceBudgetMillis: budget.concurrentAllowance.milliseconds
        )
        progress(.stageFinished(timing))
        return NameResolution(
            names: ledger.names,
            hardware: ledger.hardwareAddresses,
            degradations: degradations,
            outcome: outcome,
            timing: timing
        )
    }

    /// Which source a concurrent child produced.
    private enum NameSourceHarvest: Sendable {
        case mdns([ServiceSighting])
        case ssdp([SSDPSighting])
    }

    /// Browses Bonjour until the budget expires or the network goes quiet.
    ///
    /// The quiescence exit is the reason this is not a plain `for await`. Two children
    /// race: one drains the stream, one watches the arrival clock. Whichever finishes
    /// first cancels the other, and the drainer RETURNS WHAT IT HAS on cancellation
    /// rather than discarding it — so stopping early costs no sightings, which is the
    /// only thing that makes stopping early safe.
    private static func browse(
        interface: NetworkInterface, budget: Deadline,
        failures: DegradationLog, health: BrowseHealth
    ) async -> [ServiceSighting] {
        let browser = DarwinServiceBrowser(interface: interface, failures: failures, health: health)
        let stream = browser.browse(deadline: budget)
        let arrivals = ArrivalClock()

        return await withTaskGroup(of: [ServiceSighting].self) { group in
            group.addTask {
                var found: [ServiceSighting] = []
                for await sighting in stream {
                    found.append(sighting)
                    arrivals.touch()
                }
                return found
            }
            group.addTask {
                while !Task.isCancelled, !budget.isExpired {
                    try? await Task.sleep(for: .milliseconds(100))
                    if arrivals.isQuiet(
                        for: NameBudget.quietPeriod, notBefore: NameBudget.quietFloor
                    ) { break }
                }
                return []
            }
            var all: [ServiceSighting] = []
            for await found in group {
                all.append(contentsOf: found)
                // Whoever came back first ends the phase: either the browse finished on
                // its own, or the watchdog decided the network had gone quiet.
                group.cancelAll()
            }
            return all
        }
    }

    /// Searches for UPnP devices and fetches their descriptions.
    ///
    /// No quiescence here, deliberately. SSDP's own budget is already split into a
    /// listen half and a fetch half, and the fetch half only starts when the listen half
    /// is over — so cutting the listen short on quiet would hand time to a phase that
    /// has nothing extra to do with it, while risking the loss of a device that was
    /// about to answer within its `MX` window.
    private static func search(
        interface: NetworkInterface, budget: Deadline,
        failures: DegradationLog, failed: FailureFlag
    ) async -> [SSDPSighting] {
        let discovery = DarwinSSDPDiscovery(failures: failures, failed: failed)
        var found: [SSDPSighting] = []
        for await sighting in discovery.search(from: interface, deadline: budget) {
            found.append(sighting)
        }
        return found
    }
}

/// Records when a stream last delivered something.
///
/// A lock over two fields rather than an actor: it is touched from a tight receive loop
/// and read from a polling watchdog, and an actor hop per sighting would be a hundred
/// times the cost of the thing it protects.
final class ArrivalClock: @unchecked Sendable {
    private let lock = NSLock()
    private let started = MonotonicInstant.now
    private var last: MonotonicInstant?

    /// Notes that something arrived.
    func touch() { lock.withLock { last = .now } }

    /// Whether nothing has arrived for `period`, and the stream has been running for at
    /// least `floor`.
    ///
    /// Both conditions matter. Requiring at least one arrival stops the gap between
    /// "browse started" and "first record" from being read as quiet — on a responder
    /// that is slow to warm up, that gap is the whole answer. The floor covers the same
    /// case from the other side.
    func isQuiet(for period: Duration, notBefore floor: Duration) -> Bool {
        lock.withLock {
            guard let last else { return false }
            let now = MonotonicInstant.now
            guard now.duration(since: started) >= floor else { return false }
            return now.duration(since: last) >= period
        }
    }
}

#endif
