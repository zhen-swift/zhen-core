import Testing
@testable import ZhenCore

// When the naming stage is allowed to blame a permission, and when it is not.
//
// This is the place where the tool came closest to lying to a user, so the tests are
// written around the lies rather than around the happy path. A degradation is read as a
// finding: it appears in the scan view, it changes the exit status, and it tells someone
// to go and change a system setting. Emitting one that is two-thirds false about sources
// that never ran, or that blames a privacy setting for a service crash, costs more trust
// than saying nothing at all would have.

@Suite("Silence is only blamed on a permission when it can honestly be")
struct NameSourceSilenceTests {
    private static func silent(_ source: NameSource) -> NameSourceActivity {
        NameSourceActivity(source: source, answered: 0, failed: false)
    }

    @Test("Three silent sources over a populated network raises it")
    func allSilentRaises() throws {
        let denial = try #require(NameSourceSilenceHeuristic.evaluate(
            [Self.silent(.mdns), Self.silent(.ssdp), Self.silent(.netbios)],
            hostsProbed: 9,
            advice: .appleLocalNetwork
        ))
        #expect(denial.stage == .naming)
        #expect(denial.reason.contains("Bonjour"))
        #expect(denial.reason.contains("UPnP"))
        #expect(denial.reason.contains("NetBIOS"))
        // The remedy, and the admission that it is a guess. Claiming certainty about a
        // permission that cannot be queried is the small lie this project refuses.
        #expect(denial.reason.contains("Local Network"))
        #expect(denial.reason.contains("likely cause rather than a confirmed one"))
    }

    @Test("It names only the sources that actually ran")
    func namesOnlyTheSourcesThatRan() throws {
        // The defect: with SSDP and NetBIOS switched off, the message asserted that no
        // device had answered "Bonjour, UPnP or NetBIOS" — two-thirds of it describing
        // sources that were never asked anything.
        let onlyBonjour = try #require(NameSourceSilenceHeuristic.evaluate(
            [Self.silent(.mdns)], hostsProbed: 9, advice: .appleLocalNetwork
        ))
        #expect(onlyBonjour.reason.contains("Bonjour"))
        #expect(!onlyBonjour.reason.contains("UPnP"))
        #expect(!onlyBonjour.reason.contains("NetBIOS"))

        let two = try #require(NameSourceSilenceHeuristic.evaluate(
            [Self.silent(.mdns), Self.silent(.ssdp)], hostsProbed: 9
        ))
        #expect(two.reason.contains("Bonjour or UPnP"))
        #expect(!two.reason.contains("NetBIOS"))
    }

    @Test("A source that failed has already explained itself, so nothing is blamed")
    func aFailedSourceSuppressesIt() {
        // The one that sent people to the wrong place. mDNSResponder restarting — which
        // connecting a VPN or changing network location does routinely — kills every
        // browse on the shared connection at once. The stream goes quiet, and the old
        // heuristic read that quiet as evidence and told the user, in confident prose,
        // that their Local Network privacy setting was the likely cause.
        let died = NameSourceActivity(source: .mdns, answered: 0, failed: true)
        #expect(NameSourceSilenceHeuristic.evaluate([died], hostsProbed: 9,
                                                    advice: .appleLocalNetwork) == nil)
        // Even one failure among several is enough: the user now has two explanations
        // and no way to choose, which is worse than one.
        #expect(NameSourceSilenceHeuristic.evaluate(
            [died, Self.silent(.ssdp), Self.silent(.netbios)], hostsProbed: 9
        ) == nil)
    }

    @Test("Any answer at all means there is nothing to explain")
    func oneAnswerSuppressesIt() {
        let answered = NameSourceActivity(source: .mdns, answered: 1, failed: false)
        #expect(NameSourceSilenceHeuristic.evaluate(
            [answered, Self.silent(.ssdp), Self.silent(.netbios)], hostsProbed: 9
        ) == nil)
    }

    @Test("No hosts and no sources are both nothing to say")
    func nothingToExplain() {
        // Silence about an empty network is not evidence of anything.
        #expect(NameSourceSilenceHeuristic.evaluate([Self.silent(.mdns)], hostsProbed: 0) == nil)
        // And a stage with every source disabled must not produce a finding about
        // sources it did not have.
        #expect(NameSourceSilenceHeuristic.evaluate([], hostsProbed: 9) == nil)
    }

    @Test("Sources are named by protocol, not by enum case")
    func sourcesAreNamedForPeople() {
        // A user reads "Bonjour", not "mdns". A degradation that names the wrong thing
        // is worse than one that names nothing.
        #expect(NameSource.mdns.label == "Bonjour")
        #expect(NameSource.ssdp.label == "UPnP")
        #expect(NameSource.netbios.label == "NetBIOS")
    }
}
