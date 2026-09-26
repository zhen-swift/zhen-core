// PortsCommand.swift — port scanning as a capability rather than a flag on discovery.
//
// `zhen scan --deep` scans the ports of hosts THIS RUN's discovery found. That is the
// right shape for "what is on my network and what is it running", and it is the wrong
// shape for two things `PORTS-plan.md` names as gaps:
//
// **G1 — you cannot scan a host you already know about without re-running discovery.**
// A sweep of a /24 to ask one question about one address is a minute of probes and a
// history entry nobody wanted.
//
// **G2 — you cannot scan a host discovery does not find.** A firewalled machine that
// answers no ICMP and no ARP but has 443 open is invisible to the sweep and perfectly
// scannable by address. `PortState.filtered` exists precisely to describe what comes
// back from such a host, and until now nothing in the CLI could reach one.
//
// So targets come from the command line, from a pipe, or from history — and never from
// a sweep. `zhen scan --deep` is untouched.

import ArgumentParser
import Foundation
import ZhenCore

struct Ports: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ports",
        abstract: "Probe TCP and UDP ports on hosts you already have.",
        discussion: """
            Takes addresses rather than a network: one address, a comma list, a CIDR, \
            or `-` to read them from standard input one per line. Discovery is never \
            run, so a host that answers no ping is still scannable by address.

            UDP ports are prefixed `U:` — `zhen ports 10.10.20.1 22,U:53,U:123`. A UDP \
            port that answers is open, one the host refuses with ICMP is closed, and \
            silence is `open_filtered`: an open port ignoring a request it did not \
            understand and a firewall dropping it look the same from here, so the tool \
            says so rather than guess.
            """
    )

    @Argument(help: "Addresses, a comma list, a CIDR, or - to read from stdin.")
    var targets: String

    /// The port spec, as the second thing a person types.
    ///
    /// "Is 22 open on the gateway" is a question with two nouns in it, and it was spelled
    /// `zhen ports 10.10.20.1 --ports 22` — a flag and a value for the second noun.
    ///
    /// **Ambiguity is not a problem in practice.** The first positional is targets, so
    /// `zhen ports 22` resolves targets to "22", fails to parse as an address, and says
    /// so. A person who meant a port on an unstated host gets a sentence about "22" not
    /// being an IPv4 address rather than a scan of something unexpected.
    @Argument(help: "Ports: 22, 22,80,443, 1-1024, common, iana. Defaults to common.")
    var portSpec: String?

    /// The long form, kept.
    ///
    /// A script written against a flag should not break because the flag grew a friendlier
    /// spelling. Both routes reach the same parser; giving both is refused rather than
    /// silently preferring one, because a run that ignored half of what it was told is
    /// the kind of quiet disagreement this tool exists not to produce.
    @Option(name: .long, help: "Ports, as the explicit long form of the second argument.")
    var ports: String?

    @Option(name: .long, help: "Total budget for the scan, e.g. 5s, 500ms, 2m.")
    var deadline: String?

    @Option(name: .long, help: "Port scan mechanism: syn, connect, or auto.")
    var scanType: PortScanType = .auto

    @Flag(name: .long, help: "Confirm a scan large enough to be refused without it.")
    var yes = false

    /// Answer with the exit code and print nothing.
    ///
    /// This is what makes the tool usable inside anything else:
    ///
    ///     if zhen ports "$GATEWAY" 22 --check; then ssh "$GATEWAY"; fi
    ///
    /// A flag rather than implicit behaviour, because "nothing was open" has to stay a
    /// SUCCESS in the default mode — a scan that completed and found nothing worked.
    @Flag(name: .long, help: "Exit 0 if any requested port is open, 1 if none. Prints nothing.")
    var check = false

    @Flag(name: .long, help: "Emit one PortScanReport as JSON on stdout.")
    var json = false

    @Flag(name: .long, help: "Suppress the progress display on stderr.")
    var quiet = false

    @Flag(name: .long, help: "Disable ANSI colour.")
    var noColor = false

    func run() async throws {
        do {
            let status = try await execute()
            if status != .ok { throw ExitCode(status.rawValue) }
        } catch let error as ScanSetupError {
            Out.stderr("zhen: \(error.message)\n")
            throw ExitCode(error.status.rawValue)
        }
    }

    private func execute() async throws(ScanSetupError) -> ExitStatus {
        let addresses = try parsedTargets()
        let spec = try parsedPortSpec()
        let budget = try parsedDeadline()

        let scanner = try await PlatformScanner.make(concurrencyOverride: nil,
                                                     portScanType: scanType)

        // Said before anything is sent, and refused rather than started when it is
        // large. `PortSpec.commonServices` has carried this instinct in its doc comment
        // since it was written and nothing enforced it.
        let size = ProbeBudget(
            hosts: addresses.count, ports: spec.probeCount,
            concurrency: scanner.concurrency, perHostDeadline: .milliseconds(600))
        if size.needsConfirmation, !yes {
            throw .badArgument(size.refusal(hosts: addresses.count, ports: spec.probeCount))
        }
        if size.needsConfirmation, !quiet {
            Out.stderr(size.announcement(hosts: addresses.count, ports: spec.probeCount) + "\n")
        }
        let renderer = PortsRenderer(json: json, quiet: quiet, color: colorOnStdout)

        let work = Task { () -> PortScanResult in
            let deadline = Deadline(after: budget)
            var result = PortScanResult()
            if !spec.ports.isEmpty {
                result = await scanner.ports.scan(
                    addresses,
                    ports: spec,
                    // The same ceiling `scan --deep` uses. The engine narrows it per host
                    // from that host's own measured round trips.
                    perHostDeadline: .milliseconds(600),
                    deadline: deadline,
                    progress: ProgressSink { _ in }
                )
            }
            // A second engine rather than a second transport inside the first: the TCP
            // engine is SYN or connect depending on the helper, the UDP engine is always
            // the same unprivileged one. A full second per probe rather than 600ms,
            // because silence is a verdict here and the resend at 40% needs room.
            if !spec.udpPorts.isEmpty, !Task.isCancelled {
                let udp = await scanner.udpPorts.scan(
                    addresses,
                    ports: spec,
                    perHostDeadline: .seconds(1),
                    deadline: deadline,
                    progress: ProgressSink { _ in }
                )
                result = spec.ports.isEmpty ? udp : result.combined(with: udp)
            }
            return result
        }
        let signals = SignalHandler {
            Out.stderr("\nInterrupted — reporting what has been probed.\n")
            work.cancel()
        }
        defer { signals.stop() }

        let result = await work.value
        if signals.wasInterrupted { return .interrupted }

        // `--check` answers with the code and prints nothing at all, including the
        // degradations the renderer would otherwise put on stderr. A caller using this
        // inside an `if` wants an answer, not a report.
        if check {
            return Self.checkStatus(for: result.ports.values.flatMap { $0 })
        }

        renderer.finish(result, targets: addresses, spec: spec)
        // Scanned fine and found nothing open is a 0. `ExitCodes.swift` reasons this
        // the same way for a partial discovery: only a failure to scan is non-zero, and
        // "no open ports" is an answer rather than a failure.
        return result.outcome == .complete ? .ok : .ok
    }

    /// What `--check` exits with, given everything that was observed.
    ///
    /// **`.open` only.** An `open_filtered` port is the ambiguity itself — a shell `if`
    /// cannot represent "maybe", so rounding it to open would over-report in exactly the
    /// context least able to notice, and rounding it to closed would under-report. The
    /// caller who wants the nuance has the artifact; the caller who wanted a boolean
    /// asked for one and gets the conservative answer.
    ///
    /// A function rather than a closure inline, so the rule can be tested against all
    /// four states. Today a TCP scan never produces `open_filtered` — the UDP engine
    /// that does is stage C3 — so this is the only place the rule is checkable until
    /// then, and leaving it untested until an engine exists is how it would ship wrong.
    static func checkStatus(for observations: [PortObservation]) -> ExitStatus {
        observations.contains { $0.state == .open } ? .ok : .noneOpen
    }

    /// Addresses from argv, from a CIDR, or from stdin.
    /// Internal rather than private so the grammar and its rejections can be tested
    /// without a network — the same line `ScanCommand.parseBudgets` draws.
    func parsedTargets() throws(ScanSetupError) -> [IPv4Address] {
        let text: String
        if targets == "-" {
            var lines: [String] = []
            while let line = readLine(strippingNewline: true) { lines.append(line) }
            text = lines.joined(separator: ",")
            guard !text.isEmpty else {
                throw .badArgument("Nothing arrived on standard input.")
            }
        } else {
            text = targets
        }

        var addresses: [IPv4Address] = []
        var seen: Set<IPv4Address> = []
        for rawPiece in text.split(separator: ",", omittingEmptySubsequences: false) {
            let piece = rawPiece.trimmingCharacters(in: .whitespaces)
            if piece.isEmpty { continue }
            if piece.contains("/") {
                guard let network = IPv4Network(piece) else {
                    throw .badArgument("'\(piece)' is not a network in CIDR form.")
                }
                // A CIDR here is an enumeration, not a sweep — the hosts are probed for
                // ports directly. A /16 is 65,534 hosts times the port set, which is
                // the kind of number `PORTS-plan.md` wants a guard in front of.
                guard network.hostCount <= 1024 else {
                    throw .badArgument(
                        "\(piece) is \(network.hostCount) addresses. `zhen ports` takes "
                        + "hosts you already have; use `zhen scan --deep` to find them first."
                    )
                }
                addresses.append(contentsOf: network.hosts.filter { seen.insert($0).inserted })
            } else {
                guard let address = IPv4Address(piece) else {
                    throw .badArgument("'\(piece)' is not an IPv4 address.")
                }
                if seen.insert(address).inserted { addresses.append(address) }
            }
        }
        guard !addresses.isEmpty else {
            throw .badArgument("No addresses to scan.")
        }
        return addresses
    }

    /// Internal for the same reason as `parsedTargets`.
    func parsedPortSpec() throws(ScanSetupError) -> PortSpec {
        // Both spellings given is a contradiction rather than a preference. Picking one
        // silently means a run measured something other than what it was asked for,
        // which is the failure mode every gate in this project is written against.
        if let ports, let portSpec, ports != portSpec {
            throw .badArgument(
                "Ports were given twice, as '\(portSpec)' and --ports '\(ports)'. "
                + "Use one or the other.")
        }
        guard let spelled = portSpec ?? ports else { return .commonServices }
        do { return try PortSpec.parse(spelled) }
        catch { throw .badArgument(error.message) }
    }

    private func parsedDeadline() throws(ScanSetupError) -> Duration {
        guard let deadline else { return .seconds(20) }
        guard let parsed = Duration(humanReadable: deadline) else {
            throw .badArgument("'\(deadline)' is not a duration. Try 5s, 500ms or 2m.")
        }
        guard parsed > .zero else {
            throw .badArgument("A deadline of \(deadline) leaves no time to scan.")
        }
        return parsed
    }

    /// Colour follows stdout's own state, as it does everywhere else.
    private var colorOnStdout: Bool {
        !noColor && !Terminal.colorDisabledByEnvironment && Terminal.stdoutIsTTY
    }
}
