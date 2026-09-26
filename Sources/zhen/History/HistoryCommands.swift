// HistoryCommands.swift — reading back what the scans wrote down.
//
// `scan` answers "what is on the network now". These answer "what has been", which is a
// different question and the only reason a store exists. Until now zhen could
// record nothing and therefore could not be asked.
//
// ── Why these share one options group and one store opener ──────────────────────
//
// Three commands that each resolve a path, open a file and decide whether the store is
// empty would be three chances to disagree about what "no history yet" means. It is not
// an error — a first run has none by definition — so all three say so the same way and
// exit 0, because a script asking for events on a fresh machine has not done anything
// wrong.

import ArgumentParser
import Foundation
import ZhenCore

/// Options shared by every command that reads history.
struct HistoryOptions: ParsableArguments {
    @Option(
        name: .long,
        help: "Read a specific history file instead of the default location."
    )
    var store: String?

    @Flag(name: .long, help: "Emit JSON on stdout instead of a table.")
    var json = false

    @Option(
        name: .long,
        help: ArgumentHelp(
            "Only entries newer than this, e.g. 24h or 7d.",
            discussion: """
                Measured back from now rather than from the last scan, because "what \
                changed today" is a question about today and not about when the machine \
                last happened to be awake.
                """
        )
    )
    var since: String?

    /// The store, or nil when there is nowhere to keep one.
    nonisolated func open() throws(ScanSetupError) -> LogHistoryStore? {
        if let store, !store.isEmpty {
            return LogHistoryStore(
                url: URL(fileURLWithPath: (store as NSString).expandingTildeInPath)
            )
        }
        guard let url = HistoryLocation.resolve() else { return nil }
        return LogHistoryStore(url: url)
    }

    /// The cutoff, as an instant.
    nonisolated func cutoff() throws(ScanSetupError) -> Timestamp? {
        guard let since else { return nil }
        guard let window = Duration(humanReadable: since) else {
            throw .badArgument("'\(since)' is not a duration. Try 24h, 7d or 30m.")
        }
        let millis = Timestamp.now.millisecondsSinceEpoch
            - Int64(window.components.seconds * 1_000)
        return Timestamp(millisecondsSinceEpoch: millis)
    }

    /// What to say when there is no store at all, as opposed to an empty one.
    static let noStoreNotice = """
        zhen: no history location could be resolved, so nothing has been recorded. \
        Set \(HistoryLocation.overrideVariable) or pass --store to choose one.

        """
}

// ── zhen hosts ─────────────────────────────────────────────────────────────

/// Everything the scans have seen, present or not.
struct Hosts: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "hosts",
        abstract: "List every device history has seen, present or absent.",
        discussion: """
            Absent is a state, not a deletion. A device that stopped answering keeps its \
            row and its last known address, because "seen two hours ago" is information \
            and dropping it would silently shrink the network.
            """
    )

    @OptionGroup var options: HistoryOptions

    func run() async throws {
        do { try await execute() } catch {
            Out.stderr("zhen: \(error.message)\n")
            throw ExitCode(error.status.rawValue)
        }
    }

    private func execute() async throws(ScanSetupError) {
            guard let store = try options.open() else {
                Out.stderr(HistoryOptions.noStoreNotice)
                return
            }
            let cutoff = try options.cutoff()
            var devices = await store.devices()
            if let cutoff { devices = devices.filter { $0.device.lastSeen >= cutoff } }
            if options.json {
                Out.stdout(HistoryRendering.json(devices: devices))
            } else {
                Out.stdout(HistoryRendering.table(devices: devices))
            }
    }
}

// ── zhen events ────────────────────────────────────────────────────────────

/// What changed between runs, newest first.
struct Events: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "events",
        abstract: "Show what changed between scans, newest first.",
        discussion: """
            A first scan produces no events. Everything is new then, and a page of \
            "appeared" on a fresh machine is noise rather than history.
            """
    )

    @OptionGroup var options: HistoryOptions

    func run() async throws {
        do { try await execute() } catch {
            Out.stderr("zhen: \(error.message)\n")
            throw ExitCode(error.status.rawValue)
        }
    }

    private func execute() async throws(ScanSetupError) {
            guard let store = try options.open() else {
                Out.stderr(HistoryOptions.noStoreNotice)
                return
            }
            let cutoff = try options.cutoff()
            var log = await store.events()
            if let cutoff { log = log.filter { $0.at >= cutoff } }
            if options.json {
                Out.stdout(HistoryRendering.json(events: log))
            } else {
                Out.stdout(HistoryRendering.table(events: log, filtered: cutoff != nil))
            }
    }
}

// ── zhen history <host> ────────────────────────────────────────────────────

/// One device's timeline.
struct History: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "history",
        abstract: "Show one device: what is known about it, and what has happened to it."
    )

    @Argument(help: "An address, a MAC, or part of a name.")
    var host: String

    @OptionGroup var options: HistoryOptions

    func run() async throws {
        do { try await execute() } catch {
            Out.stderr("zhen: \(error.message)\n")
            throw ExitCode(error.status.rawValue)
        }
    }

    private func execute() async throws(ScanSetupError) {
            guard let store = try options.open() else {
                Out.stderr(HistoryOptions.noStoreNotice)
                return
            }
            let devices = await store.devices()
            let matches = devices.filter { HistoryRendering.matches($0.device, query: host) }
            guard let match = matches.first else {
                throw .badArgument("no device in history matches '\(host)'.")
            }
            // Ambiguity is reported rather than resolved. Picking the first of several
            // would answer a question the user did not ask, and they cannot tell from
            // the output that it happened.
            if matches.count > 1 {
                let names = matches.map { $0.device.primaryAddress.description }.joined(separator: ", ")
                throw .badArgument("'\(host)' matches \(matches.count) devices: \(names)")
            }
            let log = await store.events()
                .filter { HistoryRendering.event($0, concerns: match.device) }
            if options.json {
                Out.stdout(HistoryRendering.json(device: match, events: log))
            } else {
                Out.stdout(HistoryRendering.detail(device: match, events: log))
            }
    }
}

// ── zhen export ────────────────────────────────────────────────────────────

/// The whole store as one JSON document.
struct Export: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "export",
        abstract: "Write the whole history to stdout as one JSON document.",
        discussion: """
            The stored file is newline-delimited and append-only, which is right for \
            writing and awkward for handing to something else. This is the same content \
            as one document, so it can be piped into a tool that expects one.
            """
    )

    @OptionGroup var options: HistoryOptions

    func run() async throws {
        do { try await execute() } catch {
            Out.stderr("zhen: \(error.message)\n")
            throw ExitCode(error.status.rawValue)
        }
    }

    private func execute() async throws(ScanSetupError) {
            guard let store = try options.open() else {
                Out.stderr(HistoryOptions.noStoreNotice)
                return
            }
            Out.stdout(HistoryRendering.json(
                devices: await store.devices(),
                events: await store.events(),
                latestRun: await store.latestRun()
            ))
    }
}
