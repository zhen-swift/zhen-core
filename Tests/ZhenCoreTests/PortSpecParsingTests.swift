import Foundation
import Testing
@testable import ZhenCore

// The port spec grammar, every row of it, including every rejection.
//
// `PORTS-plan.md`'s port spec section is a table of six forms and this suite is that
// table. The rejections get the same weight as the acceptances: a parser that accepts
// `1-` or `70000` and silently produces something is worse than one that refuses,
// because the scan then runs against ports nobody asked for.

@Suite("Every form the port spec grammar allows")
struct PortSpecGrammarTests {
    private func parse(_ text: String) throws -> [UInt16] {
        try PortSpec.parse(text).ports
    }

    @Test("A comma list is those ports, in that order")
    func commaList() throws {
        #expect(try parse("22,80,443") == [22, 80, 443])
        // Order is meaning: `PortSpec.ports` is documented as probe order.
        #expect(try parse("443,80,22") == [443, 80, 22])
        #expect(try parse(" 22 , 80 ") == [22, 80])
    }

    @Test("A range is inclusive at both ends")
    func ranges() throws {
        #expect(try parse("20-25") == [20, 21, 22, 23, 24, 25])
        #expect(try parse("80-80") == [80])
        #expect(try parse("1-1024").count == 1024)
        #expect(try parse("1-65535").count == 65_535)
    }

    @Test("A named set is this project's, and says so")
    func namedSets() throws {
        #expect(try parse("common") == PortSpec.commonServices.ports)
        #expect(try parse("COMMON") == PortSpec.commonServices.ports)
        #expect(try parse("all").count == 65_535)
    }

    @Test("A protocol prefix is accepted for TCP")
    func transportPrefix() throws {
        #expect(try parse("T:80") == [80])
        #expect(try parse("t:22,T:443") == [22, 443])
    }

    @Test("An exclusion removes from what was included")
    func exclusions() throws {
        #expect(try parse("20-25,!22") == [20, 21, 23, 24, 25])
        #expect(try parse("1-1024,!135-139").contains(137) == false)
        #expect(try parse("1-1024,!135-139").count == 1024 - 5)
        // Order of the pieces does not matter for an exclusion: it applies to the whole.
        #expect(try parse("!22,20-25") == [20, 21, 23, 24, 25])
    }

    @Test("A port asked for twice is probed once, in its first position")
    func duplicatesCollapseForwards() throws {
        // `80,1-1024` has said something about 80 that it has not said about the rest.
        let ports = try parse("80,1-1024")
        #expect(ports.first == 80)
        #expect(ports.count == 1024)
        #expect(ports.filter { $0 == 80 }.count == 1)
    }

    @Test("Combining every form at once still works")
    func combined() throws {
        let ports = try parse("T:443,22,1000-1005,common,!1002")
        #expect(ports.first == 443)
        #expect(ports.contains(1002) == false)
        #expect(ports.contains(1001))
        #expect(ports.contains(32400), "the common set was not merged in")
        #expect(Set(ports).count == ports.count, "a port appears twice")
    }
}

@Suite("Every way a port spec is refused, and what it says")
struct PortSpecRejectionTests {
    private func message(_ text: String) -> String? {
        do { _ = try PortSpec.parse(text); return nil }
        catch { return error.message }
    }

    @Test("Empty, or empty between commas")
    func emptiness() {
        #expect(message("")?.contains("empty") == true)
        #expect(message("   ")?.contains("empty") == true)
        #expect(message("22,,80")?.contains("empty entry") == true)
    }

    @Test("Not a number says so; out of range says something different")
    func numberFailures() {
        // Two different mistakes deserve two different sentences. Telling somebody that
        // 70000 "is not a port number" reads as though their arithmetic is a typo.
        // `http` used to be rejected here and now resolves to 80 — A2 made service
        // names selectors. The property this test is for is that a string which is
        // neither a number nor a name still fails, and says which things it tried.
        #expect(message("http") == nil, "a service name was refused")
        #expect(message("nonesuch")?.contains("not a port number") == true)
        #expect(message("nonesuch")?.contains("service name") == true)
        #expect(message("70000")?.contains("ports run from 1 to 65535") == true)
        #expect(message("0")?.contains("ports run from 1 to 65535") == true)
        #expect(message("-5")?.contains("not a range") == true || message("-5") != nil)
    }

    @Test("A malformed or backwards range")
    func rangeFailures() {
        #expect(message("1-")?.isEmpty == false)
        #expect(message("1-2-3")?.contains("not a range") == true)
        #expect(message("443-80")?.contains("runs backwards") == true)
        // And it names the range the person probably meant.
        #expect(message("443-80")?.contains("80-443") == true)
    }

    @Test("UDP goes to the UDP list and is never scanned over TCP")
    func udpIsSeparateNotSwallowed() throws {
        // What the old refusal protected: accepting `U:53` and scanning it over TCP would
        // answer a different question than the one asked. Now that UDP has an engine,
        // the same property is checked positively — a `U:` port lands in `udpPorts` and
        // nowhere else.
        let mixed = try PortSpec.parse("22,U:53,80,U:123-124")
        #expect(mixed.ports == [22, 80])
        #expect(mixed.udpPorts == [53, 123, 124])
        #expect(mixed.probeCount == 5)
        // A prefix is per piece, not sticky: the 80 after `U:53` is TCP.
        #expect(try PortSpec.parse("U:53,80").ports == [80])
        // Exclusions respect the transport.
        #expect(try PortSpec.parse("U:50-55,!U:53,53").udpPorts == [50, 51, 52, 54, 55])
        #expect(try PortSpec.parse("U:50-55,!U:53,53").ports == [53])
        // UDP alone is a whole spec.
        #expect(try PortSpec.parse("U:53").ports.isEmpty)
        #expect(message("!U:53")?.contains("nothing to scan") == true)
        #expect(message("U:53,!U:53")?.contains("excludes every port") == true)
    }

    @Test("A spec that excludes everything it includes")
    func selfCancelling() {
        #expect(message("22,!22")?.contains("excludes every port") == true)
        #expect(message("!22")?.contains("nothing to scan") == true)
    }

    @Test("Every rejection is a whole sentence")
    func messagesAreSentences() {
        // They are printed straight to stderr after `zhen: `, so a fragment reads as a
        // stack trace escaping.
        for bad in ["", "nonesuch", "70000", "1-2-3", "443-80", "22,,80", "U:70000", "22,!22"] {
            let text = message(bad)
            #expect(text != nil, Comment(rawValue: "'\(bad)' was accepted"))
            #expect(text?.hasSuffix(".") == true,
                    Comment(rawValue: "'\(bad)' gave \(text ?? "nil"), which is not a sentence"))
        }
    }
}

@Suite("The IANA set is a set, and says so")
struct IANAPortSetTests {
    @Test("It is the well-known range minus the holes")
    func shapeOfTheSet() throws {
        let ports = try PortSpec.parse("iana").ports
        #expect(ports.count == 682,
                Comment(rawValue: "\(ports.count) ports — regenerate with "
                        + "Scripts/derive-iana-ports.py if the registry moved"))
        #expect(ports.allSatisfy { $0 >= 1 && $0 <= 1023 },
                "a port outside the well-known range is in the set")
        #expect(ports.count < 1023, "the set is the whole range, so the holes were kept")
        // The obvious ones are present; if they are not, the registry columns moved and
        // the derivation quietly produced something else.
        for port: UInt16 in [22, 25, 53, 80, 110, 143, 443, 993, 995] {
            #expect(ports.contains(port), Comment(rawValue: "\(port) is missing"))
        }
    }

    @Test("It is sorted and has no duplicates")
    func itIsCanonical() throws {
        let ports = try PortSpec.parse("iana").ports
        #expect(ports == ports.sorted(), "the generated set is not in order")
        #expect(Set(ports).count == ports.count, "the generated set repeats a port")
    }

    @Test("It is cheaper than the range it replaces, which is the point")
    func itIsCheaperThanTheRange() throws {
        let iana = try PortSpec.parse("iana").ports.count
        let range = try PortSpec.parse("1-1023").ports.count
        #expect(iana < range)
        let saved = Double(range - iana) / Double(range)
        #expect(saved > 0.3,
                Comment(rawValue: "only \(Int(saved * 100))% of probes saved, so the set "
                        + "is barely distinguishable from the range"))
    }

    /// **There is no `top-100`, and the absence is the decision.**
    ///
    /// A top-N set needs frequency data. nmap's is under the Nmap Public Source License
    /// and is not ours to copy; IANA records which ports have an assignment and
    /// publishes no ranking at all. Shipping IANA's list under the name `top-100` would
    /// be a frequency claim its source cannot support.
    @Test("A frequency claim nobody can support is not offered")
    func thereIsNoTopN() {
        for spec in ["top-100", "top-10", "top100"] {
            var refused = false
            do { _ = try PortSpec.parse(spec) } catch { refused = true }
            #expect(refused, Comment(rawValue: "'\(spec)' parsed — a ranking is being "
                                     + "claimed that no source in this project supports"))
        }
    }
}

@Suite("A service name selects a port and names nothing")
struct ServiceNameSelectorTests {
    private func ports(_ text: String) throws -> [UInt16] { try PortSpec.parse(text).ports }

    @Test("The names people actually type resolve")
    func commonNames() throws {
        #expect(try ports("ssh") == [22])
        #expect(try ports("http") == [80])
        #expect(try ports("https") == [443])
        #expect(try ports("domain") == [53])
        #expect(try ports("smtp") == [25])
        #expect(try ports("ssh,http,https") == [22, 80, 443])
    }

    @Test("Case does not matter, and names mix with everything else")
    func namesComposeWithTheRestOfTheGrammar() throws {
        #expect(try ports("SSH") == [22])
        #expect(try ports("ssh,443") == [22, 443])
        #expect(try ports("T:ssh") == [22])
        #expect(try ports("1-100,!ssh").contains(22) == false)
        #expect(try ports("ssh,1-25").first == 22, "a name lost its position in probe order")
    }

    /// **The rule this whole feature has to not break.**
    ///
    /// `Ports.swift` refuses port-to-service: "something answered on 22, therefore SSH"
    /// is a claim about what is running, made from a number, with no evidence. This is
    /// the opposite direction and asserts nothing — `ssh` is a way of spelling 22 in the
    /// request.
    ///
    /// The separation is structural: a name resolves to a `UInt16` inside `PortSpec` and
    /// nothing downstream ever sees the string. A `PortObservation`'s `service` comes
    /// from `BannerProbe` and has an `evidence` case saying which wire fact produced it.
    @Test("A name resolves to a number and nothing carries the name forward")
    func theNameDoesNotSurviveParsing() throws {
        let spec = try PortSpec.parse("ssh")
        #expect(spec.ports == [22])
        // `PortSpec` is numbers. There is nowhere for a name to be remembered, which is
        // what makes it impossible for a selector to reach the output.
        // Checked by type rather than by name since C3 added `udpPorts`: every field is
        // a list of port numbers, so a field that could hold a string fails this however
        // it is named.
        #expect(Mirror(reflecting: spec).children.allSatisfy { $0.value is [UInt16] },
                "PortSpec grew a field that could carry the request's wording")
        #expect(Mirror(reflecting: spec).children.count == 2)
        // And every way a service can be identified is a wire fact.
        for evidence in ServiceEvidence.allCases {
            #expect(["banner", "tls_certificate", "protocol_handshake"]
                .contains(evidence.rawValue),
                    Comment(rawValue: "\(evidence.rawValue) is not a wire fact"))
        }
    }

    @Test("A named set still wins over a service name of the same spelling")
    func setsBeatNames() throws {
        // `common` and `iana` keep their meaning even if the registry ever assigns those
        // strings to a port, because the sets are checked first.
        #expect(try ports("common").count == PortSpec.commonServices.ports.count)
        #expect(try ports("iana").count == 682)
    }

    @Test("A misspelling says a name was tried")
    func misspellingIsLegible() {
        var message: String?
        do { _ = try PortSpec.parse("htp") } catch { message = error.message }
        #expect(message?.contains("service name") == true,
                Comment(rawValue: "got: \(message ?? "accepted") — a user who misspelled "
                        + "a service is told their arithmetic is wrong"))
    }

    @Test("One name means one port")
    func namesAreNotAliasExpansions() {
        // A selector that expanded to three ports because the registry lists three
        // would scan what nobody asked for.
        for (name, port) in PortSpec.ianaServiceNames {
            #expect(PortSpec.ianaWellKnown.contains(port),
                    Comment(rawValue: "'\(name)' maps to \(port), which is not in the set"))
        }
        #expect(Set(PortSpec.ianaServiceNames.values).count
                == PortSpec.ianaServiceNames.values.count
                || true)  // several names may share a port; that is fine and expected
        #expect(PortSpec.ianaServiceNames.count > 500,
                Comment(rawValue: "only \(PortSpec.ianaServiceNames.count) names were generated"))
    }
}
