// IPv6WindowReport.swift — `run.ipv6_window`: how long the scan listened for answers to its
// all-nodes echo, and by which rule (the fixes brief's second addendum, F8).

/// How long the scan listened after its `ff02::1` echo, and why that long.
///
/// Study 2 compares wall clocks against nmap, so a scan's wall clock has to be readable
/// as "the v4 sweep" plus "what the IPv6 window added". This is the second half.
public struct IPv6WindowReport: Sendable, Hashable, Codable {
    /// `sweep`, `fixed`, or `off`.
    public var policy: String
    /// How long the window was actually open, in ms. Zero under `off`, and when the echo
    /// could not be sent.
    public var millis: Double
    /// The least it could stay open, in ms. Nil under `off`.
    public var floorMillis: Double?
    /// The most it could stay open, in ms. Nil under `off`.
    public var capMillis: Double?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(policy: String, millis: Double, floorMillis: Double? = nil, capMillis: Double? = nil) {
        self.policy = policy
        self.millis = millis
        self.floorMillis = floorMillis
        self.capMillis = capMillis
    }

    /// The report for a policy and the time the window was open.
    ///
    /// The bounds are the ones the policy asked for, before the scan's deadline shortened
    /// them; `millis` is what it got.
    public init(window: IPv6Window, listened: Duration?) {
        self.init(
            policy: window.name,
            millis: listened?.milliseconds ?? 0,
            floorMillis: window.bounds?.floor.milliseconds,
            capMillis: window.bounds?.cap.milliseconds
        )
    }

    /// Wire keys, spelled out. Renaming a Swift property is then a refactor; renaming a
    /// JSON key is a deliberate breaking change, and the compiler is what tells you so.
    public enum CodingKeys: String, CodingKey {
        case policy
        case millis
        case floorMillis = "floor_millis"
        case capMillis = "cap_millis"
    }
}
