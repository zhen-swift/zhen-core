// IPv6Window.swift — how long a scan listens for answers to its one `ff02::1` echo (the
// fixes brief's second addendum, F8).
//
// The all-nodes echo goes out before the v4 sweep, so its window runs inside the sweep's.
// Until F8 the window was a fixed 2 s, and the scan waited for it: once F7 made a known
// network's sweep end at its learned tail, every scan still lasted about 2 s, and the fix
// never reached the person running it (questions, Q18). Now the window ends when the v4
// sweep ends, floored so a sweep that ends almost at once still hears the slow phone, and
// capped where it always was.

/// How long a scan listens for answers to its all-nodes echo.
public enum IPv6Window: Sendable, Hashable {
    /// The default: until the v4 sweep ends, but never shorter than `floor` and never
    /// longer than `cap`, measured from the echo.
    case sweep(floor: Duration, cap: Duration)
    /// Exactly this long, whenever the sweep ends. `--ipv6-window 2s` is the window before
    /// F8.
    case fixed(Duration)
    /// No all-nodes echo at all. The scan still reads the IPv6 neighbour cache.
    case off

    /// The default: the sweep's end, floored at 500 ms and capped at 2 s.
    ///
    /// 500 ms is 2.5× the slowest all-nodes reply seen in P2 (200 ms, a sleeping phone's
    /// radio). 2 s is the fixed window this replaces.
    public static let `default` = IPv6Window.sweep(floor: .milliseconds(500), cap: .seconds(2))

    /// The wire name: `sweep`, `fixed`, or `off`.
    public var name: String {
        switch self {
        case .sweep: "sweep"
        case .fixed: "fixed"
        case .off: "off"
        }
    }

    /// The least and the most the window stays open. Nil when there is no echo.
    ///
    /// A fixed window is a floor and a cap of the same length, so one listener serves
    /// both policies, and the sweep's end can't move it.
    public var bounds: (floor: Duration, cap: Duration)? {
        switch self {
        case let .sweep(floor, cap): (min(floor, cap), cap)
        case let .fixed(window): (window, window)
        case .off: nil
        }
    }
}
