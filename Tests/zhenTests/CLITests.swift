import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// What can be tested without a network. The scan itself needs one, and that is stated
// rather than faked: a mock socket would test the mock.

@Suite("Exit codes")
struct ExitCodeTests {
    @Test("A partial result from an expired deadline exits zero")
    func partialExitsZero() {
        // The rule a wrapping script depends on. A CI job that treated a busy network
        // as a failure would go red for the wrong reason, and whether a run was
        // complete is a field in the artifact rather than the exit status.
        #expect(Outcome.complete.status == .ok)
        #expect(Outcome.deadlineExpired.status == .ok)
        #expect(Outcome.cancelled.status == .interrupted)
        #expect(ExitStatus.interrupted.rawValue == 130)
    }

    @Test("Every setup failure maps to a documented code")
    func setupErrorsMap() {
        #expect(ScanSetupError.badArgument("x").status == .usage)
        #expect(ScanSetupError.noInterface("x").status == .unavailable)
        #expect(ScanSetupError.denied("x").status == .unavailable)
        #expect(ScanSetupError.unsupportedPlatform("x").status == .unavailable)
        #expect(ScanSetupError.transient("x").status == .temporary)
        #expect(ExitStatus.usage.rawValue == 64)
        #expect(ExitStatus.unavailable.rawValue == 69)
        #expect(ExitStatus.temporary.rawValue == 75)
    }

    @Test("A platform error keeps its kind when it becomes a setup error")
    func platformErrorsPreserveKind() {
        // A denial and a missing interface both exit 69, but a syscall failure is
        // temporary and a script may reasonably retry it. Collapsing them would remove
        // the only signal that says so.
        #expect(ScanSetupError(PlatformError.denied("no")).status == .unavailable)
        #expect(ScanSetupError(PlatformError.notFound("none")).status == .unavailable)
        #expect(ScanSetupError(PlatformError.unavailable("nope")).status == .unavailable)
        #expect(ScanSetupError(.systemError(code: 55, api: "sendto")).status == .temporary)
        #expect(ScanSetupError(.systemError(code: 55, api: "sendto")).message.contains("sendto"))
    }
}

@Suite("Option parsing")
struct OptionTests {
    @Test("Durations parse in the units a person types")
    func durations() {
        #expect(Duration(humanReadable: "500ms") == .milliseconds(500))
        #expect(Duration(humanReadable: "5s") == .seconds(5))
        #expect(Duration(humanReadable: "2m") == .seconds(120))
        #expect(Duration(humanReadable: "1h") == .seconds(3600))
        #expect(Duration(humanReadable: "1.5s") == .milliseconds(1500))
        #expect(Duration(humanReadable: "30") == .seconds(30))
        #expect(Duration(humanReadable: " 250MS ") == .milliseconds(250))
    }

    @Test("Nonsense durations are rejected rather than defaulted")
    func badDurations() {
        // Silently defaulting a typo would give a scan a budget the user did not ask
        // for and never find out about.
        #expect(Duration(humanReadable: "zzz") == nil)
        #expect(Duration(humanReadable: "") == nil)
        #expect(Duration(humanReadable: "5x") == nil)
        #expect(Duration(humanReadable: "nans") == nil)
    }

    @Test("The two machine output modes cannot be combined")
    func modesAreExclusive() throws {
        var options = GlobalOptions()
        options.json = true
        options.ndjson = true
        #expect(throws: ScanSetupError.self) { try options.outputMode() }

        options.ndjson = false
        #expect(try options.outputMode() == .json)
        options.json = false
        #expect(try options.outputMode() == .text)
        options.ndjson = true
        #expect(try options.outputMode() == .ndjson)
    }

    @Test("A malformed CIDR is a usage error, not a default")
    func cidrParsing() throws {
        var options = GlobalOptions()
        options.cidr = "nonsense"
        #expect(throws: ScanSetupError.self) { try options.parsedNetwork() }
        options.cidr = "10.10.20.0/24"
        #expect(try options.parsedNetwork()?.description == "10.10.20.0/24")
        options.cidr = nil
        #expect(try options.parsedNetwork() == nil)
    }

    @Test("A deadline too large to represent is a usage error, not a crash")
    func absurdDeadlineIsRejected() {
        // `Int64(someDouble)` traps when the double is out of range, so this used to
        // kill the process with a fatal error. A number a user typed is input, and
        // input that cannot be used is exit 64.
        #expect(Duration(humanReadable: "1e9h") == nil)
        #expect(Duration(humanReadable: "1e300s") == nil)
        #expect(Duration(humanReadable: "99999999999999999999") == nil)
        #expect(Duration(humanReadable: "-5s") == nil)
        // And the ordinary large-but-representable case still works.
        #expect(Duration(humanReadable: "24h") == .seconds(86_400))
    }

    @Test("A zero or negative budget is refused")
    func zeroDeadline() throws {
        var options = GlobalOptions()
        options.deadline = "0s"
        #expect(throws: ScanSetupError.self) { try options.parsedDeadline() }
    }
}

/// A report to render, built by hand so the renderers can be tested with no network.
func sampleReport(outcome: Outcome = .complete) -> ScanReport {
    let network = IPv4Network("10.10.20.0/24")!
    let devices = [
        HostFacts(ip: IPv4Address("10.10.20.1")!, mac: MACAddress("78:20:51:74:CB:28"),
                  allNames: [NameCandidate(value: "JC\u{2019}s MacBook Pro", source: .mdns)],
                  ttl: 64, rtt: RTTSample(measured: .microseconds(412)),
                  discoveredVia: [.probeReply]),
        // Deliberately the other kind: a host the neighbour table knows and that never
        // answered anything. The two used to be the same shape in this document, which
        // is what made a packet capture and the artifact impossible to reconcile.
        HostFacts(ip: IPv4Address("10.10.20.8")!, discoveredVia: [.neighborTable]),
    ].map { Device(observing: $0, in: network, lastSeen: Timestamp(millisecondsSinceEpoch: 1_756_700_000_000)) }

    return ScanReport(
        run: ScanRun(
            id: UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!,
            startedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_000),
            finishedAt: Timestamp(millisecondsSinceEpoch: 1_756_700_000_240),
            target: network, interface: "en0",
            engine: EngineDescriptor(name: "darwin-unprivileged", kind: .unprivileged,
                                     capabilities: [.icmpSweep, .arpSweep]),
            outcome: outcome,
            timing: Timing(
                stages: [StageTiming(stage: .discovery, elapsedMillis: 240, probesSent: 254, repliesSeen: 2)],
                counters: ProbeCounterSnapshot(probesSent: 254, repliesSeen: 2,
                                               peakConcurrency: 512, inFlight: 0))
        ),
        devices: devices,
        degradations: [Degradation(stage: .naming, reason: "Bonjour is phase three.", recoverable: true)]
    )
}

@Suite("Output goes to the right stream")
struct StreamSplitTests {
    @Test("--json puts the document on stdout and nothing else there")
    func jsonToStdout() throws {
        let captured = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }
        #expect(captured.err.isEmpty)
        let decoded = try ScanReport.decoded(from: Data(captured.out.utf8))
        #expect(decoded.devices.count == 2)
    }

    @Test("A degradation goes to stderr, never into the JSON document on stdout")
    func degradationsToStderr() throws {
        let captured = Out.capturing {
            let renderer = JSONRenderer(quiet: false, color: false)
            renderer.handle(.degraded(Degradation(stage: .discovery, reason: "ARP unreadable.", recoverable: true)))
            renderer.finish(sampleReport())
        }
        #expect(captured.err.contains("ARP unreadable."))
        _ = try ScanReport.decoded(from: Data(captured.out.utf8))
    }

    @Test("The text table goes to stdout so it can be piped")
    func textToStdout() {
        let captured = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport())
        }
        #expect(captured.out.contains("10.10.20.1"))
        #expect(captured.err.isEmpty)
    }
}

@Suite("The JSON artifact, byte for byte")
struct JSONFixtureTests {
    /// The exact bytes a known report encodes to.
    ///
    /// A fixture rather than a round trip. Asserting that a document decodes back to
    /// what it came from passes whether or not keys are sorted, whether or not slashes
    /// are escaped, and whether or not a typographic apostrophe survived — every
    /// property that actually makes the artifact diffable and readable is invisible to
    /// it. This literal fails if any of them changes.
    ///
    /// It earned its keep when `run.mode` was added for `--discovery-only`: the field
    /// is additive and backwards compatible, and this was still the test that noticed
    /// the wire format had moved. Updating it is the deliberate half of that change.
    static let expected = #"""
    {"degradations":[{"reason":"Bonjour is phase three.","recoverable":true,"stage":"naming"}],"devices":[{"addresses":["10.10.20.1"],"discovered_via":["probe_reply"],"first_seen":1756700000000,"identification":"identified","identification_evidence":{"has_distinct_name":true,"has_model":false,"has_os_hint":true,"has_vendor":false,"independent_sources":1,"name_source_is_self_sufficient":true},"identity_stability":"strong","last_seen":1756700000000,"mac":"78:20:51:74:CB:28","names":[{"rank":0,"source":"mdns","value":"JC’s MacBook Pro"}],"ports":[],"rtt":{"millis":0.412,"samples":1},"ttl":64},{"addresses":["10.10.20.8"],"discovered_via":["neighbor_table"],"first_seen":1756700000000,"identification":"minimal","identification_evidence":{"has_distinct_name":false,"has_model":false,"has_os_hint":false,"has_vendor":false,"independent_sources":0,"name_source_is_self_sufficient":false},"identity_stability":"ephemeral","last_seen":1756700000000,"names":[],"ports":[]}],"run":{"engine":{"capabilities":["arp_sweep","icmp_sweep"],"kind":"unprivileged","name":"darwin-unprivileged"},"finished_at":1756700000240,"id":"3F2504E0-4F89-11D3-9A0C-0305E82C3301","interface":"en0","mode":"full","outcome":"complete","started_at":1756700000000,"target":"10.10.20.0/24","timing":{"effective_probes_per_second":1058.3333333333333,"peak_concurrency":512,"probes_sent":254,"replies_seen":2,"stages":[{"elapsed_millis":240,"probes_sent":254,"replies_seen":2,"stage":"discovery"}]}},"schema":3}
    """#

    @Test("The document is byte-identical to the committed fixture")
    func matchesFixture() {
        let produced = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }.out.trimmingCharacters(in: .newlines)
        #expect(produced == Self.expected)
    }

    @Test("Keys are sorted, so two identical scans diff to nothing")
    func keysAreSorted() {
        // Visible in the fixture as `degradations` before `devices` before `run` before
        // `schema`, which is not the declaration order.
        let produced = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }.out
        let keys = ["\"degradations\"", "\"devices\"", "\"run\"", "\"schema\""]
        let positions = keys.compactMap { produced.range(of: $0)?.lowerBound }
        #expect(positions.count == keys.count)
        #expect(positions == positions.sorted())
    }

    @Test("Slashes are not escaped, so a CIDR is readable")
    func slashesAreNotEscaped() {
        let produced = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }.out
        #expect(produced.contains("\"10.10.20.0/24\""))
        #expect(!produced.contains("10.10.20.0\\/24"))
    }

    @Test("A typographic apostrophe survives unescaped")
    func apostropheIsNotEscaped() {
        // Escaping it to \u2019 would be valid JSON and would still round-trip, which
        // is why the round-trip test could not see this.
        let produced = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }.out
        #expect(produced.contains("JC\u{2019}s MacBook Pro"))
        #expect(!produced.lowercased().contains("\\u2019"))
    }

    @Test("Two encodings of the same report are byte-identical")
    func encodingIsStable() {
        let first = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }.out
        let second = Out.capturing {
            JSONRenderer(quiet: true, color: false).finish(sampleReport())
        }.out
        #expect(first == second)
    }
}

@Suite("Colour never reaches a redirected artifact")
struct ColorTests {
    @Test("The table carries no escapes when stdout is not a terminal")
    func noEscapesWhenPiped() {
        // Which is always, under test: stdout is captured, not a tty.
        let out = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: true).finish(sampleReport())
        }.out
        #expect(!out.contains("\u{1B}["))
    }

    @Test("Columns line up whether or not the table is styled")
    func paddingIsIndependentOfStyling() {
        // Padding was computed from the unstyled string while the styled one was
        // emitted, so every escape sequence shifted the rest of its row left by nine
        // characters. Comparing visible column positions catches that; comparing
        // rendered text would not.
        func columnStarts(_ text: String) -> [[Int]] {
            text.split(separator: "\n").map { row in
                let plain = row.replacing(/\u{1B}\[[0-9;]*m/, with: "")
                var starts: [Int] = []
                var index = 0
                var inGap = true
                for character in plain {
                    if character == " " { inGap = true } else {
                        if inGap { starts.append(index) }
                        inGap = false
                    }
                    index += 1
                }
                return starts
            }
        }
        let plain = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport())
        }.out
        let styled = Out.capturing {
            TextRenderer(quiet: true, color: true, progressColor: false).finish(sampleReport())
        }.out
        #expect(styled.contains("\u{1B}["))
        #expect(columnStarts(plain) == columnStarts(styled))
    }

    @Test("NO_COLOR and --no-color both win over a terminal")
    func colorCanBeDisabled() {
        var options = GlobalOptions()
        options.noColor = true
        #expect(!options.colorOnStdout)
        #expect(!options.colorOnStderr)
    }
}

@Suite("Text rendering")
struct TextRendererTests {
    @Test("Every device appears, named or not")
    func rendersDevices() {
        let out = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport())
        }.out
        #expect(out.contains("10.10.20.1"))
        #expect(out.contains("JC\u{2019}s MacBook Pro"))
        // The unidentified device is an ordinary row, not an error and not omitted.
        #expect(out.contains("10.10.20.8"))
        #expect(out.contains("2 devices"))
    }

    @Test("Sub-millisecond RTT is rendered, not rounded away")
    func subMillisecondRTT() {
        let out = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport())
        }.out
        #expect(out.contains("0.41ms"))
    }

    @Test("An incomplete run says so rather than showing a clean summary")
    func partialIsStated() {
        let complete = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport(outcome: .complete))
        }.out
        #expect(!complete.contains("PARTIAL"))
        for outcome in [Outcome.deadlineExpired, .cancelled] {
            let partial = Out.capturing {
                TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport(outcome: outcome))
            }.out
            #expect(partial.contains("PARTIAL"), "\(outcome)")
            #expect(partial.contains(outcome.rawValue))
        }
    }

    @Test("A non-recoverable degradation is stated in the summary")
    func degradedIsStated() {
        var report = sampleReport()
        report.degradations = [Degradation(stage: .discovery, reason: "denied", recoverable: false)]
        let out = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(report)
        }.out
        #expect(out.contains("DEGRADED"))
    }

    @Test("An empty network renders as a sentence, not an empty table")
    func emptyNetwork() {
        var report = sampleReport()
        report.devices = []
        let out = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(report)
        }.out
        #expect(out.contains("No devices answered"))
        #expect(!out.contains("ADDRESS"))
    }

    @Test("No row ends in trailing whitespace")
    func noTrailingWhitespace() {
        let out = Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false).finish(sampleReport())
        }.out
        for line in out.split(separator: "\n") {
            #expect(!line.hasSuffix(" "), "'\(line)'")
        }
    }
}

@Suite("NDJSON streaming")
struct NDJSONTests {
    @Test("Every line is a complete JSON value carrying the schema")
    func linesAreSelfDescribing() throws {
        let captured = Out.capturing {
            let renderer = NDJSONRenderer(quiet: true, color: false)
            renderer.handle(.stageStarted(.discovery))
            renderer.handle(.hostFound(HostFacts(ip: IPv4Address("10.10.20.1")!)))
            renderer.finish(sampleReport())
        }
        let lines = captured.out.split(separator: "\n").map(String.init)
        #expect(lines.count == 3)
        for line in lines {
            let object = try #require(
                try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
            )
            #expect(object["schema"] as? Int == ScanReport.schemaVersion)
            #expect(object["kind"] != nil)
        }
        #expect(lines.last?.contains("\"kind\":\"report\"") == true)
    }

    @Test("Events are tagged, in snake_case, so a consumer switches rather than guesses")
    func eventsAreTagged() {
        let out = Out.capturing {
            NDJSONRenderer(quiet: true, color: false).handle(.stageStarted(.deepScan))
        }.out
        #expect(out.contains("\"kind\":\"event\""))
        #expect(out.contains("\"stage\":\"deep_scan\""))
    }
}

@Suite("Signal handling")
struct SignalTests {
    @Test("The first signal is reported once and the handler tears down cleanly")
    func firstSignalReported() async throws {
        let fired = Counter()
        let handler = SignalHandler { fired.bump() }
        #expect(!handler.wasInterrupted)
        // `kill(getpid(), …)` rather than `raise(…)`: raise is thread-directed, and
        // the kqueue signal filter behind DispatchSourceSignal observes
        // process-directed signals. SIGINT is ignored before the source is installed,
        // so this reaches the source rather than killing the test process.
        kill(getpid(), SIGINT)
        try await Task.sleep(for: .milliseconds(200))
        #expect(handler.wasInterrupted)
        #expect(fired.value == 1)
        handler.stop()
        // stop() restores the previous disposition. Leaving SIGINT on SIG_IGN made the
        // rest of the suite run in a process that could not be interrupted.
        #expect(!SignalHandler.isIgnored(SIGINT))
    }

    nonisolated final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        var value: Int { lock.withLock { count } }
        func bump() { lock.withLock { count += 1 } }
    }
}

// The timing flags go through the real parser rather than a hand-built `Scan`.
// ArgumentParser's property wrappers cannot be read from an instance that was never
// parsed, and going through `parse` is what makes the flag SPELLING part of the test:
// a rename would break these, which is the point, because two of these names are
// written into the study's condition matrix and a silent rename would strand it.
@Suite("The sweep's timing policy, as chosen on the command line")
struct BudgetFlagTests {
    private func budgets(_ arguments: [String]) throws -> SweepBudgets {
        try Scan.parse(arguments).parseBudgets()
    }

    @Test("With neither flag the budgets stay split, which is the adaptive behaviour")
    func defaultsToSplit() throws {
        #expect(try budgets([]) == .split)
    }

    @Test("--shared-budget collapses the two budgets into one")
    func sharedBudget() throws {
        #expect(try budgets(["--shared-budget"]) == .shared)
    }

    @Test("--retransmit-timeout pins the interval to what was asked for")
    func pinnedInterval() throws {
        #expect(try budgets(["--retransmit-timeout", "150ms"])
                == .fixedRetransmit(.milliseconds(150)))
    }

    // The adaptive path clamps its own measurement into 25...150 ms, and an imposed
    // value deliberately does not go through that clamp. A study pinning the interval
    // at 5 ms is measuring what happens at 5 ms; silently giving it 25 would put a
    // number in the artifact that nobody asked for, reported as though they had.
    @Test("An imposed interval outside the adaptive range is honoured, not clamped")
    func imposedValuesAreNotClamped() throws {
        #expect(try budgets(["--retransmit-timeout", "5ms"])
                == .fixedRetransmit(.milliseconds(5)))
        #expect(try budgets(["--retransmit-timeout", "3s"])
                == .fixedRetransmit(.seconds(3)))
    }

    @Test("The two flags are refused together rather than one quietly winning")
    func flagsAreExclusive() {
        #expect(throws: ScanSetupError.self) {
            try budgets(["--shared-budget", "--retransmit-timeout", "150ms"])
        }
    }

    @Test("A nonsense or zero interval is a usage error, not a default")
    func badIntervalsAreRefused() {
        #expect(throws: ScanSetupError.self) {
            try budgets(["--retransmit-timeout", "banana"])
        }
        #expect(throws: ScanSetupError.self) {
            try budgets(["--retransmit-timeout", "0ms"])
        }
    }

    // The name is what reaches the artifact, and a reader comparing two scans has
    // nothing else to tell them apart: every other timing field can be identical
    // between a measured interval and an imposed one that happens to match it.
    @Test("Each policy names itself distinctly for the artifact")
    func policyNames() {
        #expect(SweepBudgets.split.name == "split")
        #expect(SweepBudgets.shared.name == "shared")
        #expect(SweepBudgets.fixedRetransmit(.milliseconds(150)).name
                == "fixed-retransmit")
        let names = Set([SweepBudgets.split, .shared, .fixedRetransmit(.zero)].map(\.name))
        #expect(names.count == 3,
                "two policies sharing a name would be unreadable in the artifact")
    }
}

@Suite("The version cannot drift from the binary that prints it")
struct VersionTests {
    /// The embedded plist, read from source.
    ///
    /// It is `exclude`d from the target — the linker consumes it via `-sectcreate` — so
    /// there is no bundle to ask and the path is derived from this file's own location.
    private func embeddedPlist() throws -> [String: Any] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // zhenTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // zhen
        let url = root.appendingPathComponent("Sources/zhen/Info.plist")
        let data = try Data(contentsOf: url)
        let parsed = try PropertyListSerialization.propertyList(from: data, format: nil)
        return try #require(parsed as? [String: Any])
    }

    @Test("The path resolves, so this test is not silently skipping")
    func plistIsReachable() throws {
        #expect(try !embeddedPlist().isEmpty)
    }

    // These disagreed once: the plist was corrected and `--version` was not, so the
    // binary reported two releases behind itself. Nothing failed, because nothing was
    // checking — and a version string is read precisely when someone is trying to work
    // out what they are looking at.
    @Test("`--version` and the embedded plist say the same thing")
    func versionMatchesPlist() throws {
        let plist = try embeddedPlist()
        let bundled = try #require(plist["CFBundleShortVersionString"] as? String)
        #expect(Zhen.configuration.version == bundled)
        #expect(Version.current == bundled)
        // And both of those now come from core, which is the only declaration.
        #expect(Version.current == ZhenVersion.current)
    }
}

@Suite("Where history is kept, and whose it is")
struct HistoryLocationTests {
    // The spec lists this as a risk and this is the answer to it. `sudo zhen scan`
    // runs as root, every home-directory API answers `/var/root`, and the history would
    // land somewhere the person who typed the command cannot read or find. The scan they
    // ran next without sudo would open an empty store and call every device new.
    /// Root's view of the world during `sudo zhen scan`.
    private static let rootHome = URL(fileURLWithPath: "/var/root")
    private static let rootSupport = URL(
        fileURLWithPath: "/var/root/Library/Application Support"
    )

    @Test("Without sudo, root's own history stays in root's own home")
    func plainRootStaysPut() throws {
        let resolved = try #require(HistoryLocation.resolve(
            environment: [:], home: Self.rootHome, support: Self.rootSupport
        ))
        #expect(resolved.path.hasPrefix("/var/root"))
        #expect(resolved.lastPathComponent == "history.ndjson")
    }

    @Test("Under sudo the file belongs to the user who typed it, not to root")
    func sudoWritesToTheInvokingUsersHome() throws {
        let resolved = HistoryLocation.resolve(
            environment: ["SUDO_USER": NSUserName()],
            home: Self.rootHome, support: Self.rootSupport
        )
        // The function is required to decline rather than guess if the invoking user's
        // home does not resolve, so this asserts only when there is something to assert.
        if let resolved {
            #expect(!resolved.path.hasPrefix("/var/root"),
                    "sudo wrote history where the invoking user cannot reach it")
            #expect(resolved.lastPathComponent == "history.ndjson")
            #expect(resolved.path.contains(HistoryLocation.directoryName))
            // The suffix root would have used is preserved, so the file lands where the
            // platform puts application data rather than loose in a home directory.
            #expect(resolved.path.contains("Library/Application Support"))
        }
    }

    @Test("`SUDO_USER=root` is not a case that needs correcting")
    func sudoAsRootChangesNothing() throws {
        let plain = HistoryLocation.resolve(
            environment: [:], home: Self.rootHome, support: Self.rootSupport
        )
        let asRoot = HistoryLocation.resolve(
            environment: ["SUDO_USER": "root"], home: Self.rootHome, support: Self.rootSupport
        )
        #expect(plain == asRoot)
    }

    @Test("A support directory that is not under the stated home is left alone")
    func mismatchedInputsDecline() throws {
        // Rather than assembling a path from an assumption that has already failed.
        let resolved = try #require(HistoryLocation.resolve(
            environment: ["SUDO_USER": NSUserName()],
            home: URL(fileURLWithPath: "/var/empty"), support: Self.rootSupport
        ))
        #expect(resolved.path.hasPrefix("/var/root"))
    }

    // An override that is not honoured exactly is worse than no override: a caller who
    // names a path and gets a different one has no way to tell.
    @Test("The override is taken verbatim, with no directory or extension added")
    func overrideIsExact() throws {
        let path = "/tmp/zhen-explicit-history.ndjson"
        let resolved = try #require(
            HistoryLocation.resolve(environment: [HistoryLocation.overrideVariable: path])
        )
        #expect(resolved.path == path)
    }

    @Test("An empty override is ignored rather than treated as a path")
    func emptyOverrideIsIgnored() {
        let resolved = HistoryLocation.resolve(
            environment: [HistoryLocation.overrideVariable: ""]
        )
        #expect(resolved?.path.isEmpty != true)
    }
}

@Suite("Reading history back")
struct HistoryReadbackTests {
    private func store() throws -> (LogHistoryStore, URL) {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zhen-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("history.ndjson")
        return (LogHistoryStore(url: url), directory)
    }

    private func device(ip: String, mac: String, name: String? = nil) -> Device {
        var names: [NameCandidate] = []
        if let name { names.append(NameCandidate(value: name, source: .mdns, rank: 1)) }
        return Device(
            observing: HostFacts(
                ip: IPv4Address(ip)!, mac: MACAddress(mac), allNames: names
            ),
            in: IPv4Network("10.10.20.0/24")!, firstSeen: .now, lastSeen: .now
        )
    }

    private func report(_ devices: [Device]) -> ScanReport {
        ScanReport(
            run: ScanRun(
                id: UUID(), startedAt: .now, finishedAt: .now,
                target: IPv4Network("10.10.20.0/24")!, interface: "en0",
                engine: EngineDescriptor(name: "test", kind: .unprivileged, capabilities: []),
                outcome: .complete, timing: Timing()
            ),
            devices: devices
        )
    }

    // The first version of this matched every event whose subject was "Unidentified
    // device" — which is every unnamed device's events — so asking about one host showed
    // the whole network's history. On a discovery-only scan nothing has a name, so that
    // was every host.
    @Test("One device's timeline is its own, not every unnamed device's")
    func timelineIsPerDevice() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        _ = await store.record(report([
            device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1"),
            device(ip: "10.10.20.8", mac: "52:A1:8A:E0:7A:8A"),
        ]))
        _ = await store.record(report([device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1")]))

        let devices = await store.devices()
        let events = await store.events()
        let subject = try #require(devices.first { $0.device.primaryAddress.description == "10.10.20.8" })
        let other = try #require(devices.first { $0.device.primaryAddress.description == "10.10.20.2" })

        let mine = events.filter { HistoryRendering.event($0, concerns: subject.device) }
        #expect(mine.count == 1)
        #expect(mine.first?.kind == .disappeared)
        #expect(events.filter { HistoryRendering.event($0, concerns: other.device) }.isEmpty,
                "a device that never left picked up someone else's disappearance")
    }

    @Test("A query matches an address, a MAC, or part of a name")
    func matching() {
        let named = device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1", name: "Kitchen Speaker")
        #expect(HistoryRendering.matches(named, query: "10.10.20.2"))
        #expect(HistoryRendering.matches(named, query: "c8:69:cd:7f:33:e1"))
        #expect(HistoryRendering.matches(named, query: "kitchen"))
        #expect(!HistoryRendering.matches(named, query: "10.10.20.3"))
        #expect(!HistoryRendering.matches(named, query: "bathroom"))
    }

    @Test("An empty store reads as empty rather than as an error")
    func emptyStoreIsNotAnError() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(await store.devices().isEmpty)
        #expect(HistoryRendering.table(devices: []).contains("No devices in history yet"))
        #expect(HistoryRendering.table(events: []).contains("No events yet"))
        // Filtered-empty is a different fact and says so.
        #expect(HistoryRendering.table(events: [], filtered: true).contains("that window"))
    }

    @Test("The JSON views agree with each other about a device")
    func jsonViewsAgree() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        _ = await store.record(report([device(ip: "10.10.20.2", mac: "C8:69:CD:7F:33:E1")]))
        let devices = await store.devices()

        let fromHosts = HistoryRendering.json(devices: devices)
        let fromExport = HistoryRendering.json(devices: devices, events: [], latestRun: nil)
        let hostsDevices = try devicesArray(in: fromHosts)
        let exportDevices = try devicesArray(in: fromExport)
        #expect(hostsDevices == exportDevices,
                "`hosts --json` and `export` described the same device differently")
    }

    private func devicesArray(in text: String) throws -> NSArray {
        let data = Data(text.utf8)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return try #require(object?["devices"] as? NSArray)
    }
}
