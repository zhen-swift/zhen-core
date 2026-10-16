// ReachOptions.swift — how long `zhen scan` waits for each address, as flags.
//
// The default needs none of them: history decides, per address, and a network never
// scanned waits long once. They exist for two people. A person who wants to say "wait
// this long for everything" (`--reach 3s`), and the study, which freezes this binary and
// moves every constant from outside it — so every constant in `ReachSettings` is a flag
// here, and every value used is echoed into `run.reach`.

import ArgumentParser
import ZhenCore

/// The reach flags `zhen scan` accepts.
struct ReachOptions: ParsableArguments {
    @Option(
        name: .long,
        help: ArgumentHelp(
            "How long to wait for each address: history (default), learned, or a duration.",
            discussion: """
                history waits longer for the addresses this network's history says \
                usually answer, up to a high percentile of how long they took when \
                nothing was cached, and asks them more often; everything else gets the \
                short wait learned from this scan's replies. A network with too little \
                history waits long everywhere, once. learned is that short wait for \
                every address — how zhen scanned before 0.8.0. A duration (3s, 800ms) \
                waits exactly that long for every address.
                """
        )
    )
    var reach: String?

    @Option(name: .long, help: "With --reach history: the percentile of past first-contact times to wait for, 0–1. Default 0.97.")
    var reachPercentile: Double?

    @Flag(
        name: .long,
        help: ArgumentHelp(
            "Do not watch the neighbour table during the sweep.",
            discussion: """
                An ablation. The sweep normally notices an address resolving while it \
                runs and reports the host at that moment as neighbor_resolved; without \
                the watch it reads the table only before and after, and every host only \
                the table supplied is neighbor_table, as before 0.8.0. With --reach \
                learned this is the mechanism zhen 0.7.0 measured.
                """
        )
    )
    var noNeighborWatch = false

    // ── The study's knobs: every constant in `ReachSettings` ─────────────────────
    //
    // Study 2 freezes this binary and passes what phase 1 learns as flags, so a constant
    // that could only move by rebuilding would end the study. Each value used, flagged or
    // defaulted, is echoed in `run.reach`.

    @Option(name: .long, help: "Wait for an address with no neighbour entry on a network with too little cold history, e.g. 1500ms. Default 1.5s.")
    var firstScanWait: String?

    @Option(name: .long, help: "The longest any expected address waits, e.g. 5s. Default 5s.")
    var reachCap: String?

    @Option(name: .long, help: "First-contact samples of a kind, cold or warm, a network needs before they decide the waits of the addresses they describe. Default 20.")
    var reachMinSamples: Int?

    @Option(name: .long, help: "Each whole step of wait beyond the first earns one more transmission, e.g. 500ms. Default 500ms.")
    var expectedAttemptsStep: String?

    @Option(name: .long, help: "The most transmissions any address gets. Default 8.")
    var expectedAttemptsCap: Int?

    @Option(name: .long, help: "How recently a device must have been seen at an address for the scan to expect it, e.g. 30d. Default 30d.")
    var expectedWindow: String?

    @Flag(
        name: .long,
        help: ArgumentHelp(
            "Neither read nor write history for this scan.",
            discussion: """
                The scan runs as though the network had never been scanned, and leaves \
                no trace. For measuring the first-scan behaviour against a history \
                that exists; ZHEN_HISTORY points a scan at a different file instead.
                """
        )
    )
    var noHistory = false

    /// The constants the flags ask for, every one defaulted from `ReachSettings`.
    func settings() throws(ScanSetupError) -> ReachSettings {
        var settings = ReachSettings()
        if let firstScanWait { settings.firstScanWait = try Self.positive(firstScanWait, "--first-scan-wait") }
        if let reachCap { settings.cap = try Self.positive(reachCap, "--reach-cap") }
        if let expectedAttemptsStep {
            settings.attemptsStep = try Self.positive(expectedAttemptsStep, "--expected-attempts-step")
        }
        if let expectedWindow {
            settings.expectedWindow = try Self.positive(expectedWindow, "--expected-window")
        }
        if let reachMinSamples {
            guard reachMinSamples >= 1 else { throw .badArgument("--reach-min-samples must be at least 1.") }
            settings.minimumSamples = reachMinSamples
        }
        if let expectedAttemptsCap {
            guard expectedAttemptsCap >= settings.baseAttempts else {
                throw .badArgument("--expected-attempts-cap must be at least \(settings.baseAttempts), the attempts every address gets.")
            }
            settings.attemptsCap = expectedAttemptsCap
        }
        return settings
    }

    private static func positive(_ text: String, _ flag: String) throws(ScanSetupError) -> Duration {
        guard let value = Duration(humanReadable: text) else {
            throw .badArgument("\(flag): '\(text)' is not a duration. Try 1500ms or 2s.")
        }
        guard value > .zero else { throw .badArgument("\(flag) must be longer than zero.") }
        return value
    }

    /// The policy the flags ask for.
    ///
    /// `--reach-percentile` is refused with anything but `history` rather than ignored:
    /// a run that was asked for a percentile and did not use one would be measuring
    /// something other than what its artifact says was asked.
    func policy() throws(ScanSetupError) -> SweepReach {
        let percentile = try parsedPercentile()
        switch reach?.lowercased() {
        case nil, "history":
            return .history(percentile: percentile ?? 0.97)
        case "learned":
            guard percentile == nil else {
                throw .badArgument("--reach-percentile applies only to --reach history; --reach learned has no percentile.")
            }
            return .learned
        case let text?:
            guard let wait = Duration(humanReadable: text) else {
                throw .badArgument("'\(text)' is not a reach. Try history, learned, or a duration such as 3s.")
            }
            guard wait > .zero else { throw .badArgument("A reach of \(text) would not wait for anything.") }
            guard percentile == nil else {
                throw .badArgument("--reach-percentile applies only to --reach history; --reach \(text) waits exactly that long.")
            }
            return .fixed(wait)
        }
    }

    private func parsedPercentile() throws(ScanSetupError) -> Double? {
        guard let reachPercentile else { return nil }
        guard reachPercentile > 0, reachPercentile <= 1 else {
            throw .badArgument("--reach-percentile must be above 0 and at most 1; \(reachPercentile) is not.")
        }
        return reachPercentile
    }
}
