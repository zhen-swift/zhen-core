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
