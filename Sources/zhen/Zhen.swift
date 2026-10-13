// Zhen.swift — the entry point.
//
// `hosts`, `history`, `events` and `export` arrived with the store on 2026-09-09. Two
// subcommands are still absent rather than stubbed: `watch`, which is a scan loop, and
// `bench`, which needs a committed baseline to compare against. A subcommand that parses
// and then says "not implemented" is worse than one that does not exist — it appears in
// help, gets scripted against, and then changes behaviour.

import ArgumentParser
import ZhenCore

@main
struct Zhen: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "zhen",
        abstract: "Fast native network discovery.",
        discussion: """
            Scans a local network over unprivileged ICMP, reading the kernel's neighbour \
            table alongside it, and reports what answered — with the round trip it \
            answered in.

            JSON goes to stdout and progress to stderr, so redirecting output still \
            leaves a visible scan. A partial result from an expired deadline exits 0: \
            that is the system working as designed, and whether a run was complete is a \
            field in the artifact rather than the exit status.
            """,
        version: Version.current,
        subcommands: [Scan.self, Ports.self, Hosts.self, Events.self, History.self, Export.self],
        defaultSubcommand: Scan.self
    )
}

/// The version, in one place.
///
/// It was in two, and they disagreed: the embedded `Info.plist` was corrected to 0.4.0
/// and this was left at 0.2.0, so `zhen --version` reported two releases behind
/// the binary it was printed by. Nothing failed, which is the whole problem — a version
/// string is only load-bearing when someone is reading it to decide what they are
/// looking at, and that is exactly when nobody is watching the tests.
///
/// The plist cannot reference this constant: it is a static file consumed by the linker
/// via `-sectcreate`. So the two are pinned by a test instead, which is how this project
/// keeps the Bonjour list and the generated project honest as well.
///
/// The value itself now comes from `ZhenCore`, because pinning the pair fixed the
/// pair and left the shape — the app declared its own copy and `CITATION.cff` a third.
/// Core is the only place the command line and the app can both see.
nonisolated enum Version {
    static let current = ZhenVersion.current
}
