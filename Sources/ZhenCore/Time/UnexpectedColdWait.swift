// UnexpectedColdWait.swift — what an unexpected address with no neighbour entry waits on a
// network zhen already knows (the fixes brief's addendum, F7).

/// What an address history doesn't expect, with no complete neighbour entry, waits while
/// the network's cold samples are too few but the network is known.
///
/// A network is known once history holds `ReachSettings.minimumSamples` first-contact
/// samples of either kind. On such a network the unexpected cold addresses are, almost
/// all, the ones where nothing lives. The first-scan wait exists for a network zhen has
/// never seen and for the sleeping phone history expects. It doesn't exist for ~240 dead
/// addresses on a machine that scans often enough never to gather a cold sample
/// (questions, Q15). On a network zhen doesn't know yet, every cold address still takes
/// the first-scan wait, whichever this is.
///
/// The cost, which study 2 phase 1 measures with both values: a new device, slow on first
/// contact, on a known network, is caught only at the learned tail. It can be missed on
/// its first scan, and is expected from then on.
public enum UnexpectedColdWait: String, Sendable, Hashable, CaseIterable {
    /// The default: the learned tail, as an unexpected warm address already waits.
    case learned = "learned"
    /// The first-scan wait, as F1 had it. The study's alternative arm.
    case firstScan = "first-scan"
}
