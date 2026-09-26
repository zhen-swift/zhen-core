// ScanCommand.swift — argument parsing, and one structured task tree.
//
// The command owns setup and exit codes; `ScanPipeline` owns the scan. Splitting them
// is what makes the pipeline testable with fake engines, which is the only way to
// exercise paths like a denied Local Network permission without arranging for macOS to
// actually deny one.
//
// Cancellation propagates from the root by construction. An earlier version set a flag
// and checked it inside the event loop, which worked only while events were arriving —
// on a quiet or unroutable network there are none, so the first Ctrl-C printed its
// message and then hung until the deadline expired, which is precisely the situation
// where a user is most likely to be pressing it.

import ArgumentParser
import Foundation
import ZhenCore

struct Scan: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Discover the devices on a network."
    )

    @OptionGroup var options: GlobalOptions

    @Flag(
        name: .long,
        help: """
        Report what is on the network without resolving what it is called. Skips \
        mDNS, SSDP and NetBIOS, so the scan finishes as soon as discovery does.
        """
    )
    var discoveryOnly = false

    @Flag(name: .long, help: "Also probe common TCP ports on the hosts that answered.")
    var deep = false

    @Option(name: .long, help: "Ports for --deep: 22,80,443 or 1-1024 or common, with !135-139 to exclude.")
    var ports: String?

    /// Which mechanism the port stage uses.
    ///
    /// `auto` is what this has always done. The other two exist because connect scan is
    /// the PERMITTED option on a network where sockets are allowed and forged frames
    /// are not, and a tool that reaches it only by failing to find privilege cannot be
    /// asked to measure it.
    @Option(name: .long, help: "Port scan mechanism: syn, connect, or auto.")
    var scanType: PortScanType = .auto

    @Flag(name: .long, help: "Confirm a deep scan large enough to be refused without it.")
    var yes = false

    @Option(
        name: .long,
        help: ArgumentHelp(
            "Pin how long an unanswered probe waits before being resent, e.g. 150ms.",
            discussion: """
                Normally this is measured: half the round trips on the network, \
                doubled, re-derived as replies arrive. Pinning it stops the scan \
                adapting, which is almost never what you want on a real network and \
                is exactly what you want when measuring what the adapting is worth. \
                The artifact records that the interval was imposed rather than chosen.
                """
        )
    )
    var retransmitTimeout: String?

    @Flag(
        name: .long,
        help: ArgumentHelp(
            "Use one budget for both retransmitting and declaring hosts absent.",
            discussion: """
                The scan normally keeps two: a tight interval before asking again, \
                and a longer one, paid once, before calling the silent addresses \
                absent. This collapses them into the longer of the two, which is what \
                the scan did before they were separated. It is slower by construction \
                (every dead address waits out the tail on every attempt) and exists so \
                the split can be measured against its absence.
                """
        )
    )
    var sharedBudget = false

    func run() async throws {
        do {
            let status = try await execute()
            if status != .ok { throw ExitCode(status.rawValue) }
        } catch let error as ScanSetupError {
            // Every setup failure arrives here typed, so the mapping to an exit code is
            // a switch the compiler checks rather than a catch-all that quietly turns a
            // new failure into a usage error.
            Out.stderr("zhen: \(error.message)\n")
            throw ExitCode(error.status.rawValue)
        }
    }

    private func execute() async throws(ScanSetupError) -> ExitStatus {
        let mode = try options.outputMode()
        let budget = try options.parsedDeadline()
        let requestedNetwork = try options.parsedNetwork()
        let portSpec = try parsePorts()
        let budgets = try parseBudgets()
        let scanner = try await PlatformScanner.make(
            concurrencyOverride: options.concurrency, budgets: budgets,
            portScanType: scanType
        )
        let target = try resolveTarget(scanner: scanner, network: requestedNetwork)

        // A target too wide to enumerate is a USAGE error — the user named a network
        // this tool will not sweep in one pass — so it exits 64 and produces no
        // artifact at all. Emitting a report for it, as an earlier version did, meant
        // publishing a document that said `outcome: complete` over zero probes and zero
        // devices: a claim of completeness about a scan that never ran.
        if let refusal = target.resolution.refusal {
            throw ScanSetupError.badArgument(refusal.reason)
        }

        // Nowhere to write history is not a reason to refuse to scan. It is reported
        // once, on stderr so the artifact on stdout stays clean, and the scan runs.
        // The command line shares the file with the app, so whichever runs first after
        // the rename brings the old history across.
        HistoryLocation.migrateLegacyStore(to: HistoryLocation.resolve())
        let historyURL = HistoryLocation.resolve()
        if historyURL == nil {
            Out.stderr(HistoryOptions.noStoreNotice)
        }

        // The deep stage's size, refused before discovery rather than after. A person
        // who typed `--deep --ports all` finds out now, not once the sweep has run and
        // the port stage is already grinding.
        //
        // Hosts are not known yet, so the network's size is the bound. That over-counts
        // — most addresses will not answer — and over-counting is the right direction
        // for a guard: it refuses a scan that might have been survivable rather than
        // starting one that is not.
        if deep {
            let budget = ProbeBudget(
                hosts: target.network.hostCount, ports: portSpec.ports.count,
                concurrency: scanner.concurrency, perHostDeadline: .milliseconds(600))
            if budget.needsConfirmation, !yes {
                throw ScanSetupError.badArgument(
                    budget.refusal(hosts: target.network.hostCount, ports: portSpec.ports.count))
            }
            if budget.needsConfirmation, !options.quiet {
                Out.stderr(budget.announcement(
                    hosts: target.network.hostCount, ports: portSpec.ports.count) + "\n")
            }
        }

        let pipeline = ScanPipeline(
            scanner: scanner,
            renderer: Renderers.make(mode: mode, options: options),
            discoveryOnly: discoveryOnly,
            deep: deep,
            ports: portSpec,
            history: historyURL.map { LogHistoryStore(url: $0) }
        )

        // The scan runs in a child task so the signal handler has something to cancel.
        // Cancelling propagates into every stream's `onTermination`, so the sockets
        // close deterministically and the partial artifact is still produced.
        let work = Task { await pipeline.run(target: target, budget: budget) }
        let signals = SignalHandler {
            Out.stderr("\nInterrupted — committing what has been found.\n")
            work.cancel()
        }
        defer { signals.stop() }

        let completed = await work.value
        // A cancelled run exits 130 whatever else it reported, because the user asked
        // for that and a script should be able to tell.
        return signals.wasInterrupted ? .interrupted : completed.status
    }

    private func resolveTarget(
        scanner: PlatformScanner, network: IPv4Network?
    ) throws(ScanSetupError) -> ScanTarget {
        let interface: NetworkInterface
        do {
            if let name = options.iface {
                let all = try scanner.interfaces.interfaces()
                guard let match = all.first(where: { $0.name == name }) else {
                    throw ScanSetupError.noInterface(
                        "No interface named '\(name)'. Available: \(all.map(\.name).joined(separator: ", "))."
                    )
                }
                interface = match
            } else {
                interface = try scanner.interfaces.primaryInterface()
            }
        } catch let error as PlatformError {
            throw ScanSetupError(error)
        } catch let error as ScanSetupError {
            throw error
        } catch {
            throw ScanSetupError.transient("\(error)")
        }
        return ScanTarget(network: network ?? interface.network, interface: interface)
    }

    /// The sweep's timing policy, from the two flags that can change it.
    ///
    /// The flags are mutually exclusive and rejected rather than silently ordered.
    /// Both are ablations of the same mechanism, and a run that had asked for both
    /// would be measuring neither — whichever the implementation happened to apply
    /// would be the one the artifact reported, which is exactly the kind of quiet
    /// disagreement between what was asked and what was measured that this whole
    /// timing surface exists to make impossible.
    /// Internal rather than private so the exclusion and the rejections can be tested
    /// without a network — the rest of this file needs one, and that is the line this
    /// package's test suite draws.
    func parseBudgets() throws(ScanSetupError) -> SweepBudgets {
        if sharedBudget, retransmitTimeout != nil {
            throw .badArgument("""
                --shared-budget and --retransmit-timeout cannot be combined. \
                --shared-budget removes the separate retransmit interval; \
                --retransmit-timeout pins it. Pick the one you meant to measure.
                """)
        }
        if sharedBudget { return .shared }
        guard let retransmitTimeout else { return .split }
        guard let pinned = Duration(humanReadable: retransmitTimeout) else {
            throw .badArgument("'\(retransmitTimeout)' is not a duration. Try 150ms or 1s.")
        }
        // Zero would resend without waiting at all, which is a flood rather than a
        // scan. There is no upper bound: a deliberately absurd interval is a valid
        // thing to measure, and `--deadline` already stops the scan running forever.
        guard pinned > .zero else {
            throw .badArgument(
                "A retransmit timeout of \(retransmitTimeout) would resend instantly."
            )
        }
        return .fixedRetransmit(pinned)
    }

    /// The spec grammar lives in `ZhenCore` now, so `scan --deep` and `zhen ports`
    /// cannot drift apart on what `1-1024` means.
    private func parsePorts() throws(ScanSetupError) -> PortSpec {
        guard let ports else { return .commonServices }
        let spec: PortSpec
        do { spec = try PortSpec.parse(ports) }
        catch { throw .badArgument(error.message) }
        // Refused rather than ignored. The deep scan's port stage is TCP; accepting `U:`
        // here and probing nothing for it would be a run that measured less than it was
        // asked to and said nothing about it.
        guard spec.udpPorts.isEmpty else {
            throw .badArgument(
                "`zhen scan --deep` probes TCP only. Scan UDP ports on the hosts it finds "
                + "with `zhen ports <hosts> U:\(spec.udpPorts.map(String.init).joined(separator: ","))`.")
        }
        return spec
    }
}
