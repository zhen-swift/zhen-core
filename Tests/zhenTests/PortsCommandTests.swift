import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// `zhen ports` — the argument surface, which is the part that can be tested without a
// network. The scan itself needs one, and that is stated rather than faked: a mock
// socket would test the mock.

@Suite("Targets come from the command line, never from a sweep")
struct PortsTargetTests {
    /// Parses through argv, not by default-initialising the command.
    ///
    /// Reading an `@Argument` off an unparsed `ParsableCommand` traps — it is a crash
    /// rather than a failure and it takes the whole suite with it. This suite used to
    /// do exactly that, and adding the port-spec positional is what set it off.
    private func addresses(_ text: String) throws -> [IPv4Address] {
        try Ports.parse([text]).parsedTargets()
    }

    private func rejection(_ text: String) -> String? {
        do { _ = try Ports.parse([text]).parsedTargets(); return nil }
        catch let error as ScanSetupError { return error.message }
        catch { return "\(error)" }
    }

    @Test("One address, several, and a CIDR")
    func theThreeForms() throws {
        #expect(try addresses("10.10.20.1") == [IPv4Address("10.10.20.1")!])
        #expect(try addresses("10.10.20.1,10.10.20.8").count == 2)
        #expect(try addresses(" 10.10.20.1 , 10.10.20.8 ").count == 2)
        // A CIDR here is an enumeration, not a sweep: these hosts are probed for ports
        // directly rather than discovered first.
        #expect(try addresses("10.10.20.0/29").count == 6)
    }

    @Test("An address asked for twice is scanned once, in its first position")
    func duplicatesCollapse() throws {
        let parsed = try addresses("10.10.20.8,10.10.20.1,10.10.20.8")
        #expect(parsed == [IPv4Address("10.10.20.8")!, IPv4Address("10.10.20.1")!])
    }

    @Test("A CIDR big enough to be a sweep is refused, and says what to use instead")
    func oversizedCIDRIsRefused() {
        // `zhen ports` takes hosts you already have. A /16 through here would be a
        // sweep wearing a different command's name, with none of the pacing discovery
        // does.
        let message = rejection("10.10.0.0/16")
        #expect(message?.contains("65534 addresses") == true,
                Comment(rawValue: "got: \(message ?? "accepted")"))
        #expect(message?.contains("zhen scan --deep") == true,
                "the refusal does not say what to use instead")
    }

    @Test("What is refused, and what it says")
    func rejections() {
        #expect(rejection("not-an-address")?.contains("not an IPv4 address") == true)
        #expect(rejection("10.10.20.0/99")?.contains("not a network") == true)
        #expect(rejection("")?.contains("No addresses") == true)
        #expect(rejection(",,")?.contains("No addresses") == true)
    }

    @Test("Every refusal is a whole sentence")
    func messagesAreSentences() {
        // Printed straight after `zhen: `, so a fragment reads as something escaping.
        for bad in ["not-an-address", "10.10.20.0/99", "", "10.10.0.0/16"] {
            let text = rejection(bad)
            #expect(text != nil, Comment(rawValue: "'\(bad)' was accepted"))
            #expect(text?.hasSuffix(".") == true,
                    Comment(rawValue: "'\(bad)' gave \(text ?? "nil")"))
        }
    }
}

@Suite("The port spec reaches the command")
struct PortsSpecTests {
    private func spec(_ text: String?) throws -> PortSpec {
        try Ports.parse(["10.10.20.1"] + (text.map { ["--ports", $0] } ?? []))
            .parsedPortSpec()
    }

    @Test("Absent means the common set, not everything")
    func defaultIsCommon() throws {
        // 65,535 ports as a default is the failure `PortSpec.commonServices` documents.
        #expect(try spec(nil).ports == PortSpec.commonServices.ports)
    }

    @Test("Ranges and exclusions arrive intact")
    func grammarIsWired() throws {
        #expect(try spec("1-100").ports.count == 100)
        #expect(try spec("1-100,!50").ports.contains(50) == false)
        #expect(try spec("common").ports == PortSpec.commonServices.ports)
    }

    @Test("A bad spec is a usage error carrying the parser's own sentence")
    func parserMessagesSurvive() {
        do {
            _ = try Ports.parse(["10.10.20.1", "--ports", "70000"]).parsedPortSpec()
            Issue.record("70000 was accepted")
        } catch let error as ScanSetupError {
            #expect(error.message.contains("ports run from 1 to 65535"),
                    Comment(rawValue: "the parser's message was replaced: \(error.message)"))
            #expect(error.status == .usage, "a bad spec is a usage error")
        } catch {
            Issue.record("wrong error type: \(error)")
        }
    }
}

@Suite("The ports renderer says what was asked as well as what answered")
struct PortsRendererTests {
    private func render(_ hosts: [(IPv4Address, [PortObservation])], spec: PortSpec) -> String {
        var result = PortScanResult()
        for (address, observations) in hosts { result.ports[address] = observations }
        result.outcome = .complete
        return Out.capturing {
            PortsRenderer(json: false, quiet: true, color: false)
                .finish(result, targets: hosts.map(\.0), spec: spec)
        }.out
    }

    @Test("A host with nothing open still reports, and says how much was asked")
    func nothingOpenStillReports() {
        let address = IPv4Address("10.10.20.9")!
        let observations = (1...20).map {
            PortObservation(port: UInt16($0), proto: .tcp, state: .filtered)
        }
        let text = render([(address, observations)], spec: PortSpec((1...20).map(UInt16.init)))
        #expect(text.contains("0 open"))
        #expect(text.contains("20 filtered"))
        // `zhen ports` has no device table above it, so the summary is the only place
        // that says how many hosts and ports were involved.
        #expect(text.contains("1 host · 20 ports"),
                Comment(rawValue: "the summary is missing from:\n\(text)"))
    }

    @Test("Hosts are reported in the order they were asked for")
    func orderFollowsTheUser() {
        // A dictionary yields in whatever order it likes, and output that reorders
        // itself between runs cannot be diffed.
        let first = IPv4Address("10.10.20.50")!, second = IPv4Address("10.10.20.9")!
        let open = [PortObservation(port: 80, proto: .tcp, state: .open)]
        let text = render([(first, open), (second, open)], spec: PortSpec([80]))
        let firstAt = text.range(of: "10.10.20.50")
        let secondAt = text.range(of: "10.10.20.9\n") ?? text.range(of: "10.10.20.9 ")
        #expect(firstAt != nil && secondAt != nil, "a host is missing from the table")
        if let firstAt, let secondAt {
            #expect(firstAt.lowerBound < secondAt.lowerBound,
                    "the table reordered the hosts the user typed")
        }
    }

    @Test("No line carries trailing whitespace")
    func noTrailingWhitespace() {
        let address = IPv4Address("10.10.20.1")!
        let observations = [
            PortObservation(port: 80, proto: .tcp, state: .open),
            PortObservation(port: 443, proto: .tcp, state: .closed),
        ]
        let text = render([(address, observations)], spec: PortSpec([80, 443]))
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            #expect(!line.hasSuffix(" "),
                    Comment(rawValue: "trailing space on: \(String(line).debugDescription)"))
        }
    }
}

@Suite("Asking about a port is two words, and the flag still works")
struct PositionalPortSpecTests {
    private func spec(_ arguments: [String]) throws -> [UInt16] {
        try Ports.parse(arguments).parsedPortSpec().ports
    }

    @Test("The second positional is the port spec")
    func theNewForm() throws {
        #expect(try spec(["10.10.20.1", "22"]) == [22])
        #expect(try spec(["10.10.20.1", "22,80,443"]) == [22, 80, 443])
        #expect(try spec(["10.10.20.1", "1-10"]).count == 10)
        #expect(try spec(["10.10.20.1", "common"]) == PortSpec.commonServices.ports)
    }

    /// **The gate.** A script written against the flag must not break.
    @Test("Every existing flag invocation means exactly what it meant")
    func theFlagFormIsUnchanged() throws {
        // The forms used across this suite and in the man page's examples.
        for value in ["22", "22,80,443", "1-1024", "common", "iana", "1-1024,!135-139",
                      "T:80", "all"] {
            let viaFlag = try spec(["10.10.20.1", "--ports", value])
            let viaPositional = try spec(["10.10.20.1", value])
            #expect(viaFlag == viaPositional,
                    Comment(rawValue: "'\(value)' means something different through the "
                            + "flag than through the positional"))
        }
    }

    @Test("Neither given is still the common set")
    func defaultUnchanged() throws {
        #expect(try spec(["10.10.20.1"]) == PortSpec.commonServices.ports)
    }

    @Test("Both given, and disagreeing, is refused rather than silently resolved")
    func contradictionIsRefused() {
        // Picking one would mean the run measured something other than what it was
        // asked for. Identical values are allowed: saying the same thing twice is
        // redundant, not contradictory.
        var refused: String?
        do { _ = try spec(["10.10.20.1", "22", "--ports", "443"]) }
        catch let error as ScanSetupError { refused = error.message }
        catch { refused = "\(error)" }
        #expect(refused?.contains("given twice") == true,
                Comment(rawValue: "a contradiction was resolved silently: \(refused ?? "accepted")"))
        #expect(refused?.contains("22") == true && refused?.contains("443") == true,
                "the refusal does not name both values")
        let agreeing = try? spec(["10.10.20.1", "22", "--ports", "22"])
        #expect(agreeing == [22], "saying the same thing twice was refused")
    }

    @Test("A port typed where a target belongs fails as a target, and says so")
    func theAmbiguityResolvesByPosition() {
        // `zhen ports 22` resolves targets to "22". The plan says this is fine because
        // the failure is legible; this is what makes that claim checkable.
        var message: String?
        do {
            _ = try Ports.parse(["22"]).parsedTargets()
        } catch let error as ScanSetupError { message = error.message }
        catch { message = "\(error)" }
        #expect(message?.contains("not an IPv4 address") == true,
                Comment(rawValue: "got: \(message ?? "accepted, which is worse")"))
    }
}

@Suite("--check answers with the exit code and says nothing")
struct CheckFlagTests {
    /// The three states an exit code has to keep apart.
    ///
    /// The whole point of the flag is that a broken scan is never mistaken for a closed
    /// port, so these must be three distinct values and 1 must be reachable only here.
    @Test("Open, none open, and could-not-run are three different codes")
    func threeDistinctOutcomes() {
        #expect(zhen.ExitStatus.ok.rawValue == 0)
        #expect(zhen.ExitStatus.noneOpen.rawValue == 1)
        let failures: [zhen.ExitStatus] = [.usage, .unavailable, .temporary, .interrupted]
        for failure in failures {
            #expect(failure.rawValue != 0,
                    Comment(rawValue: "\(failure) is indistinguishable from success"))
            #expect(failure.rawValue != 1,
                    Comment(rawValue: "\(failure) is indistinguishable from 'nothing open', "
                            + "so a broken scan would read as a closed port"))
        }
        #expect(Set(failures.map { $0.rawValue }).count == failures.count,
                "two failure modes share an exit code")
    }

    @Test("The flag parses and is off by default")
    func theFlagExists() throws {
        #expect(try Ports.parse(["10.10.20.1", "22"]).check == false,
                "--check is on by default, so an ordinary scan would exit 1 on a quiet host")
        #expect(try Ports.parse(["10.10.20.1", "22", "--check"]).check)
    }

    @Test("Only a definitely-open port counts as open")
    func onlyOpenCounts() {
        func status(_ states: [PortState]) -> zhen.ExitStatus {
            Ports.checkStatus(for: states.enumerated().map {
                PortObservation(port: UInt16(1 + $0.offset), proto: .tcp, state: $0.element)
            })
        }
        #expect(status([.open]) == .ok)
        #expect(status([.closed, .filtered, .open]) == .ok)
        #expect(status([.closed]) == .noneOpen)
        #expect(status([.filtered]) == .noneOpen)
        #expect(status([]) == .noneOpen)
        // The one the shell cannot represent. Rounding it to open over-reports in the
        // context least able to notice; rounding it to closed under-reports. The
        // conservative answer is the one a boolean can carry honestly.
        #expect(status([.openFiltered]) == .noneOpen,
                "an ambiguous UDP port was reported as definitely open")
        #expect(status([.openFiltered, .closed]) == .noneOpen)
        #expect(status([.openFiltered, .open]) == .ok,
                "a definitely-open port was masked by an ambiguous one")
    }

    /// **Nothing open must stay a SUCCESS without the flag.**
    ///
    /// This is the same reasoning that makes a partial discovery exit 0: a scan that
    /// completed and found nothing is a working scan. If this ever inverts, every
    /// existing script that runs `zhen ports` without `--check` starts seeing failures.
    @Test("Without the flag, a quiet host is still a successful scan")
    func quietIsSuccessByDefault() throws {
        // Asserted at the level the decision is made: `noneOpen` is only ever returned
        // from the `check` branch, so the default path cannot produce it.
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/zhen/PortsCommand.swift"),
            encoding: .utf8)
        let mentions = source.components(separatedBy: ".noneOpen").count - 1
        #expect(mentions == 1,
                Comment(rawValue: "`.noneOpen` is returned from \(mentions) places; it must "
                        + "be reachable only from the --check branch"))
        let checkBranch = source.range(of: "if check {")
        let noneOpen = source.range(of: ".noneOpen")
        #expect(checkBranch != nil && noneOpen != nil)
        if let checkBranch, let noneOpen {
            #expect(checkBranch.lowerBound < noneOpen.lowerBound,
                    "`.noneOpen` is returned before the --check branch is entered")
        }
    }
}
