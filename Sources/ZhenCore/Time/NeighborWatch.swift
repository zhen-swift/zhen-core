// NeighborWatch.swift — noticing, during a sweep, that the kernel resolved an address.
//
// ── Why the sweep watches the table at all ────────────────────────────────────────
//
// Unprivileged, the wire is gated by kernel ARP. Study 1's captures showed a median of
// 749 `probes_sent` against 19 echo requests actually on the wire: a transmission to an
// address with no complete neighbour entry is an ARP TRIGGER, and the echo goes out only
// once the kernel has an answer. So the first evidence that a slow host exists is often
// not its echo reply but its ARP reply, which the kernel consumes and records as a
// complete entry. Reading the table only before and after the sweep threw away WHEN that
// happened, and called every such host `neighbor_table` alongside entries inherited from
// an hour ago.
//
// ── Why it polls (gate G0) ────────────────────────────────────────────────────────
//
// The brief's first question was whether a `PF_ROUTE` socket delivers a message when an
// ARP entry resolves, to an unprivileged process. On macOS 26.6.2 it does not: eleven
// entries resolved during a listening window and the socket received nothing, though it
// echoed this process's own `RTM_GET` and delivered unrelated `RTM_MISS` broadcasts. The
// kernel clones an llinfo route internally and announces it to nobody. The dumps are in
// `Docs/process/0.8.0-progress.md`, and the spike is beside it.
//
// So the watch re-reads the table on a timer. One read is O(table): on a /24 about 37 KB
// and 0.1 ms, measured. On a /16 the table holds ~65k incomplete entries — ~9 MB a read
// — and a fixed 25 ms poll would copy hundreds of megabytes a second. The interval
// therefore grows in proportion to the target above 1,024 addresses, which keeps the
// bytes copied per second roughly constant at what a /22 costs at 25 ms.
//
// The rules here are portable and pure, so they are tested on Linux. The timer and the
// sysctl are the platform's.

/// How a sweep watches the neighbour table for entries that resolve while it runs.
public enum NeighborWatch {
    /// The poll interval below `scaleAbove` targets.
    ///
    /// 25 ms: the first-contact time is quantised to it, and the testbed's slowest host
    /// takes about 1,000 ms cold, so it is a 2.5% error at the scale being measured.
    public static let baseInterval: Duration = .milliseconds(25)

    /// The target size above which the interval grows in proportion.
    public static let scaleAbove = 1_024

    /// How often to read the table while sweeping `targets` addresses.
    ///
    /// `baseInterval` up to `scaleAbove` targets; above it, scaled by
    /// `targets / scaleAbove`. A /16 polls every 1.6 s.
    public static func interval(targets: Int) -> Duration {
        guard targets > scaleAbove else { return baseInterval }
        return baseInterval * (Double(targets) / Double(scaleAbove))
    }

    /// Entries that are complete now and were not complete when the baseline was taken,
    /// and that the watch has not already reported.
    ///
    /// - Parameters:
    ///   - entries: the table as just read.
    ///   - baseline: addresses complete at the start of the sweep. An entry complete then
    ///     is inherited — `neighbor_table` — and never evidence from this run, even if
    ///     it is refreshed during it.
    ///   - reported: addresses this watch has already reported.
    ///   - network: only addresses inside it are considered.
    /// - Returns: the newly resolved entries, in address order.
    public static func newlyResolved(
        _ entries: [NeighborEntry],
        baseline: Set<IPv4Address>,
        reported: Set<IPv4Address>,
        in network: IPv4Network
    ) -> [NeighborEntry] {
        entries
            .filter {
                $0.isComplete && network.contains($0.ip)
                    && !baseline.contains($0.ip) && !reported.contains($0.ip)
            }
            .sorted { $0.ip < $1.ip }
    }
}

/// What the neighbour watch did during one sweep, for the artifact.
///
/// The study needs to know whether change 1 was on (`--no-neighbor-watch` is the ablation
/// that isolates it) and what it cost, so both are written rather than inferred.
public struct NeighborWatchReport: Sendable, Hashable, Codable {
    /// Whether the sweep watched the table at all.
    public var enabled: Bool
    /// How: `poll` — re-reading the table on a timer. A routing-socket listener would be
    /// `route_socket`; G0 found macOS 26 does not deliver the message it would need.
    public var mechanism: String?
    /// The interval between reads, in milliseconds.
    public var pollIntervalMillis: Double?
    /// How many reads the sweep made.
    public var polls: Int?
    /// The largest single read, in bytes.
    public var largestDumpBytes: Int?
    /// How many addresses resolved during the sweep and were reported as
    /// `neighbor_resolved` at that moment.
    public var resolved: Int?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(
        enabled: Bool, mechanism: String? = nil, pollIntervalMillis: Double? = nil,
        polls: Int? = nil, largestDumpBytes: Int? = nil, resolved: Int? = nil
    ) {
        self.enabled = enabled
        self.mechanism = mechanism
        self.pollIntervalMillis = pollIntervalMillis
        self.polls = polls
        self.largestDumpBytes = largestDumpBytes
        self.resolved = resolved
    }

    /// The watch, switched off.
    public static let disabled = NeighborWatchReport(enabled: false)

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case enabled
        case mechanism
        case pollIntervalMillis = "poll_interval_millis"
        case polls
        case largestDumpBytes = "largest_dump_bytes"
        case resolved
    }
}
