// Timing.swift — the measurement carried in the artifact rather than logged.
//
// A scanner whose selling point is speed has to be able to prove it, and a claim of
// speed that cannot be reproduced from the output artifact is marketing (Antichi et
// al., OSNT, 2014). Putting the numbers in the machine-readable output makes a
// regression a diff instead of a feeling.
//
// Everything here is measured on MonotonicInstant and stored as milliseconds. No
// wall-clock arithmetic reaches this file.

/// What one stage of a scan cost.
public struct StageTiming: Sendable, Hashable, Codable {
    /// Which stage this describes.
    public var stage: Stage
    /// Wall-clock-equivalent elapsed time, measured monotonically, in milliseconds.
    public var elapsedMillis: Double
    /// Probes this stage put on the wire.
    public var probesSent: Int
    /// Replies this stage received. The ratio against `probesSent` is the loss rate,
    /// and a near-zero ratio with a non-empty neighbour cache is the signature of a
    /// denied Local Network permission.
    public var repliesSeen: Int
    /// Hosts this stage found. Absent for stages that do not find hosts.
    ///
    /// Carried alongside the budgets below so the trade between them is legible from
    /// the artifact alone: a shorter tail with fewer hosts is a different outcome from
    /// a shorter tail with the same hosts, and only one of them is an improvement.
    public var hostsFound: Int?
    /// How long an unanswered probe waited before being resent, in milliseconds.
    ///
    /// The cheap half of the sweep's timing. A lost frame costs one packet to resend,
    /// so this is driven from a LOW quantile of observed round trips, and it is paid
    /// once per retransmission per address.
    public var retransmitBudgetMillis: Double?
    /// How long the stage waited at the end before declaring the silent addresses
    /// absent, in milliseconds.
    ///
    /// The expensive half, and it needs the TAIL of the distribution rather than the
    /// middle — but it is asked once, and it overlaps every address at once, so the
    /// whole sweep pays it a single time rather than once per attempt per host.
    public var tailBudgetMillis: Double?
    /// How the transmissions to one address were spread in time: `uniform` when every
    /// gap was the retransmit interval, `spread-into-tail` when the final transmission
    /// was deliberately delayed into the tail window.
    ///
    /// Reported for the same reason the two budgets are. A reader comparing two scans
    /// of the same network needs to know whether they were probed on the same schedule
    /// before concluding anything from a difference in what they found — and correction
    /// C8 in the study is precisely a case where identical budgets and different
    /// spacing produced a nine-point difference in recall.
    public var spacingPolicy: String?
    /// How the sweep's two budgets were chosen: `split` when the retransmit interval
    /// and the tail were decided separately, `shared` when one number answered both,
    /// `fixed-retransmit` when the interval was imposed rather than measured.
    ///
    /// `retransmitBudgetMillis` reports the interval that was used; this reports where
    /// it came from, and those are different facts. An imposed 150 ms and a measured
    /// 150 ms produce identical numbers in every other field and mean opposite things
    /// about the network — one says the operator asked for it, the other says half the
    /// hosts answered inside 75 ms.
    public var budgetPolicy: String?
    /// How far the final transmission was pushed out beyond the retransmit interval,
    /// in milliseconds.
    ///
    /// Zero when the tail window had no headroom to spend, which is the honest report
    /// that C8 was not addressed on that network rather than a silent no-op.
    public var spreadBudgetMillis: Double?
    /// The per-host scatter applied to that gap, as a fraction of it.
    ///
    /// A schedule that varies between hosts is harder to read from the outside, so the
    /// amount of variation is stated rather than inferred.
    public var spacingJitter: Double?
    /// How long the naming stage was ALLOWED, in milliseconds, as opposed to how long it
    /// took.
    ///
    /// Naming's budget is a product decision rather than a measurement — a browse yields
    /// over time and never says it is finished, so somebody has to choose between
    /// listening longer and returning sooner. Reporting the allowance next to the
    /// elapsed time is what makes that choice arguable from the artifact: a stage that
    /// was given 4,500 ms and took 2,680 stopped because the network went quiet, and a
    /// stage that took its whole allowance was cut off.
    ///
    /// Its own field rather than a reuse of `tailBudgetMillis`. Those two describe the
    /// ICMP sweep's retransmit and tail waits specifically, and putting a different
    /// quantity behind the same wire key would mean a consumer had to know which stage
    /// it was reading before it could know what the number meant.
    public var nameStageBudgetMillis: Double?
    /// How long each of the concurrent name sources was allowed, in milliseconds.
    ///
    /// mDNS and SSDP run at the same time, so both hold this much of the stage; NetBIOS
    /// takes what is left afterwards.
    public var nameSourceBudgetMillis: Double?
    /// How many transmissions each address got, for a sweep: the base count, which every
    /// address on the learned path gets. An address a reach plan extended gets more, and
    /// how many is in `run.reach`. The cost model in study 2 needs it per stage.
    public var attempts: Int?
    /// The in-flight window the stage ran with: the most probes it would have outstanding
    /// at once. Configured, not measured — `peak_concurrency` is the measurement.
    public var concurrency: Int?
    /// Replies the sweep decoded as its own kind and could not attribute: a second reply
    /// to a probe already answered, a reply from an address its token wasn't issued for,
    /// or a reply to another sweep's probe. None of them is evidence. Absent for a stage
    /// that sent no echo.
    ///
    /// In the artifact since F9: scans run back to back had a slow host's reply to the
    /// previous scan's probe counted as this scan's first contact, and nothing in the
    /// output could show it.
    public var strayReplies: Int?
    /// Replies that arrived after their probe's window closed and were still attributed
    /// exactly. These hosts were found; a count here says the per-host budgets ran tight.
    /// Absent for a stage that sent no echo.
    public var lateReplies: Int?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        stage: Stage,
        elapsedMillis: Double,
        probesSent: Int = 0,
        repliesSeen: Int = 0,
        hostsFound: Int? = nil,
        retransmitBudgetMillis: Double? = nil,
        tailBudgetMillis: Double? = nil,
        spacingPolicy: String? = nil,
        budgetPolicy: String? = nil,
        spreadBudgetMillis: Double? = nil,
        spacingJitter: Double? = nil,
        nameStageBudgetMillis: Double? = nil,
        nameSourceBudgetMillis: Double? = nil,
        attempts: Int? = nil,
        concurrency: Int? = nil,
        strayReplies: Int? = nil,
        lateReplies: Int? = nil
    ) {
        self.stage = stage
        self.elapsedMillis = elapsedMillis
        self.probesSent = probesSent
        self.repliesSeen = repliesSeen
        self.hostsFound = hostsFound
        self.retransmitBudgetMillis = retransmitBudgetMillis
        self.tailBudgetMillis = tailBudgetMillis
        self.spacingPolicy = spacingPolicy
        self.budgetPolicy = budgetPolicy
        self.spreadBudgetMillis = spreadBudgetMillis
        self.spacingJitter = spacingJitter
        self.nameStageBudgetMillis = nameStageBudgetMillis
        self.nameSourceBudgetMillis = nameSourceBudgetMillis
        self.attempts = attempts
        self.concurrency = concurrency
        self.strayReplies = strayReplies
        self.lateReplies = lateReplies
    }

    /// Explicit keys: renaming the Swift property must never silently rename the
    /// JSON. This rule holds for every type in the wire model.
    public enum CodingKeys: String, CodingKey {
        case stage
        case elapsedMillis = "elapsed_millis"
        case probesSent = "probes_sent"
        case repliesSeen = "replies_seen"
        case hostsFound = "hosts_found"
        case retransmitBudgetMillis = "retransmit_budget_millis"
        case tailBudgetMillis = "tail_budget_millis"
        case spacingPolicy = "spacing_policy"
        case budgetPolicy = "budget_policy"
        case spreadBudgetMillis = "spread_budget_millis"
        case spacingJitter = "spacing_jitter"
        case nameStageBudgetMillis = "name_stage_budget_millis"
        case nameSourceBudgetMillis = "name_source_budget_millis"
        case attempts
        case concurrency
        case strayReplies = "stray_replies"
        case lateReplies = "late_replies"
    }
}

/// The measurement summary for a whole run.
public struct Timing: Sendable, Hashable, Codable {
    /// Per-stage breakdown, in the order the stages ran.
    public var stages: [StageTiming]
    /// Total probes put on the wire.
    public var probesSent: Int
    /// Total replies received.
    public var repliesSeen: Int
    /// The largest number of probes simultaneously in flight. This is the number
    /// Little's law relates to the achieved rate, and the one to move when the rate
    /// disappoints.
    public var peakConcurrency: Int
    /// Probes per second actually achieved over the run.
    public var effectiveProbesPerSecond: Double

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        stages: [StageTiming] = [],
        probesSent: Int = 0,
        repliesSeen: Int = 0,
        peakConcurrency: Int = 0,
        effectiveProbesPerSecond: Double = 0
    ) {
        self.stages = stages
        self.probesSent = probesSent
        self.repliesSeen = repliesSeen
        self.peakConcurrency = peakConcurrency
        self.effectiveProbesPerSecond = effectiveProbesPerSecond
    }

    /// Builds a summary from the stages and a counter snapshot, deriving the rate
    /// rather than letting a caller supply an unaudited number.
    ///
    /// The rate is computed over total elapsed stage time. A run whose stages took
    /// no measurable time reports a rate of zero rather than infinity — dividing by
    /// a zero budget is a measurement artefact, not a very fast scan.
    public init(stages: [StageTiming], counters: ProbeCounterSnapshot) {
        let elapsed = stages.reduce(0) { $0 + $1.elapsedMillis }
        self.stages = stages
        self.probesSent = counters.probesSent
        self.repliesSeen = counters.repliesSeen
        self.peakConcurrency = counters.peakConcurrency
        self.effectiveProbesPerSecond =
            elapsed > 0 ? Double(counters.probesSent) * 1000 / elapsed : 0
    }

    /// Total measured time across all stages, in milliseconds.
    public var totalElapsedMillis: Double { stages.reduce(0) { $0 + $1.elapsedMillis } }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case stages
        case probesSent = "probes_sent"
        case repliesSeen = "replies_seen"
        case peakConcurrency = "peak_concurrency"
        case effectiveProbesPerSecond = "effective_probes_per_second"
    }
}
