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
    @OptionGroup var reachOptions: ReachOptions

    @Flag(
        name: .long,
        help: ArgumentHelp(
            "Ask again, for longer, about the devices the last scan expected and did not find.",
            discussion: """
                Sweeps only the latest scan's expected_missing addresses, waiting 10s \
                for each (or --reach <duration>), and adds what answers to that scan \
                rather than starting a new one — so nothing else on the network is \
                marked gone.
                """
        )
    )
    var lookLonger = false

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

    @Option(
        name: .long,
        help: ArgumentHelp(
            "How long to listen after the one IPv6 all-nodes echo: sweep (default), a duration, or 0.",
            discussion: """
                The scan sends one echo to ff02::1 before the IPv4 sweep, and listens \
                while the sweep runs. sweep stops listening when the sweep ends, but \
                never before 500ms or after 2s. A duration (2s) listens exactly that \
                long, which is how scans worked before; 0 sends no echo, and IPv6 \
                hosts come only from the neighbour cache. Recorded as run.ipv6_window.
                """
        )
    )
    var ipv6Window: String?

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
        let policy = try reachOptions.policy()
        let settings = try reachOptions.settings()
        let window = try parseIPv6Window()
        if lookLonger {
            try checkLookLonger(policy: policy, network: requestedNetwork)
            // Look longer sends no all-nodes echo, so a window would go unused while the
            // artifact said it was asked for.
            guard ipv6Window == nil else {
                throw .badArgument("--ipv6-window has nothing to time with --look-longer, which sends no IPv6 echo.")
            }
        }
        let scanner = try await PlatformScanner.make(
            concurrencyOverride: options.concurrency, budgets: budgets,
            portScanType: scanType, neighborWatch: !reachOptions.noNeighborWatch
        )
        // Nowhere to write history is not a reason to refuse to scan. It is reported
        // once, on stderr so the artifact on stdout stays clean, and the scan runs.
        // `--no-history`: neither read nor written, and no notice — nobody is missing a
        // store they asked not to use.
        let historyURL = reachOptions.noHistory ? nil : HistoryLocation.resolve()
        if historyURL == nil, !reachOptions.noHistory {
            Out.stderr(HistoryOptions.noStoreNotice)
        }
        let history = historyURL.map { LogHistoryStore(url: $0) }

        // Before the target: look-longer asks where the latest scan asked, so its
        // interface comes from that run, not from the primary interface (F5).
        if lookLonger {
            return try await executeLookLonger(
                scanner: scanner, history: history,
                policy: policy, settings: settings, mode: mode, budget: budget
            )
        }

        var target = try resolveTarget(scanner: scanner, network: requestedNetwork)

        // A target too wide to enumerate is a USAGE error — the user named a network
        // this tool will not sweep in one pass — so it exits 64 and produces no
        // artifact at all. Emitting a report for it, as an earlier version did, meant
        // publishing a document that said `outcome: complete` over zero probes and zero
        // devices: a claim of completeness about a scan that never ran.
        if let refusal = target.resolution.refusal {
            throw ScanSetupError.badArgument(refusal.reason)
        }

        // ── The reach plan ─────────────────────────────────────────────────────
        //
        // Built before the sweep, from this network's history. The command line keeps
        // history for ever, but only a device seen inside `--expected-window` (30 days)
        // makes its address expected (F3; questions, Q1). With nowhere to keep history
        // there is none to read, and the scan is a first scan every time — which is
        // what that machine's history says.
        target.reach = ReachPlan.make(
            addresses: target.resolvedAddresses, network: target.network,
            devices: await history?.devices() ?? [],
            policy: policy, settings: settings, now: .now
        )

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
            history: history,
            ipv6Window: window
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

    /// The flags `--look-longer` cannot be combined with, refused before anything runs.
    ///
    /// Internal rather than private so the refusals can be tested without a network.
    func checkLookLonger(policy: SweepReach, network: IPv4Network?) throws(ScanSetupError) {
        if deep {
            throw .badArgument("--look-longer only asks whether the missing devices are there; it does not scan ports. Drop --deep.")
        }
        if network != nil {
            throw .badArgument("--look-longer asks again on the network the latest scan covered; --cidr does not apply.")
        }
        if reachOptions.noHistory {
            throw .badArgument("--look-longer extends the latest scan in history; --no-history leaves it nothing to extend.")
        }
        switch policy {
        case .fixed: break
        case .history, .learned:
            if reachOptions.reach != nil || reachOptions.reachPercentile != nil {
                throw .badArgument("--look-longer waits a fixed time for each address; give it as --reach <duration>, e.g. --reach 20s.")
            }
        }
    }

    /// How long `--look-longer` waits for each address when `--reach` does not say.
    ///
    /// Ten seconds: twice the longest wait a plan ever imposes on a scan
    /// (`ReachSettings.cap`), because a person asking "where's my phone?" has already
    /// decided to wait, and a phone in deep power save answers on its own schedule.
    /// Questions, Q6.
    static let lookLongerWait: Duration = .seconds(10)

    /// The interface `--look-longer` asks on: the one the latest scan went out of.
    ///
    /// F5 (questions, Q12). The latest run's network only means something on the link it
    /// was scanned from: asking about `192.168.64.x` through `en0`'s neighbour table
    /// finds nothing, and reports that as though it had looked. So `--iface` is not
    /// needed, and when it names a different interface the two cannot both be meant:
    /// exit 64. An interface the machine no longer has is the ordinary no-such-interface
    /// failure.
    ///
    /// Internal and pure, so the rule is tested without a network.
    func lookLongerInterface(
        latest: ScanRun, available: [NetworkInterface]
    ) throws(ScanSetupError) -> NetworkInterface {
        if let asked = options.iface, asked != latest.interface {
            throw .badArgument(
                "--look-longer asks again where the latest scan asked, on \(latest.interface); "
                    + "--iface \(asked) is a different interface. Drop --iface, or scan on \(asked) first."
            )
        }
        guard let match = available.first(where: { $0.name == latest.interface }) else {
            throw .noInterface(
                "The latest scan went out of \(latest.interface), which this machine does not have now. "
                    + "Available: \(available.map(\.name).joined(separator: ", "))."
            )
        }
        return match
    }

    private func executeLookLonger(
        scanner: PlatformScanner, history: LogHistoryStore?,
        policy: SweepReach, settings: ReachSettings, mode: OutputMode, budget: Duration
    ) async throws(ScanSetupError) -> ExitStatus {
        guard let history else {
            throw .badArgument("--look-longer extends the latest scan in history, and there is nowhere history is kept.")
        }
        guard let latest = await history.latestRun() else {
            throw .badArgument("--look-longer extends the latest scan, and history has none yet. Run `zhen scan` first.")
        }
        let available: [NetworkInterface]
        do {
            available = try scanner.interfaces.interfaces()
        } catch {
            throw ScanSetupError(error)
        }
        let interface = try lookLongerInterface(latest: latest, available: available)
        let wait: Duration
        if case .fixed(let fixed) = policy { wait = fixed } else { wait = Self.lookLongerWait }
        let pipeline = ScanPipeline(
            scanner: scanner,
            renderer: Renderers.make(mode: mode, options: options),
            discoveryOnly: true, deep: false, ports: .commonServices,
            history: history
        )
        let work = Task {
            await pipeline.lookLonger(
                extending: latest, interface: interface, wait: wait, settings: settings,
                budget: max(budget, wait + .seconds(2))
            )
        }
        let signals = SignalHandler {
            Out.stderr("\nInterrupted — committing what has been found.\n")
            work.cancel()
        }
        defer { signals.stop() }
        let completed = await work.value
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
    /// `--ipv6-window`: `sweep`, a duration, or zero for none (F8).
    func parseIPv6Window() throws(ScanSetupError) -> IPv6Window {
        guard let ipv6Window else { return .default }
        if ipv6Window.lowercased() == "sweep" { return .default }
        guard let window = Duration(humanReadable: ipv6Window) else {
            throw .badArgument("--ipv6-window: '\(ipv6Window)' is not sweep, 0 or a duration such as 2s.")
        }
        guard window >= .zero else { throw .badArgument("--ipv6-window cannot be negative.") }
        return window == .zero ? .off : .fixed(window)
    }

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
