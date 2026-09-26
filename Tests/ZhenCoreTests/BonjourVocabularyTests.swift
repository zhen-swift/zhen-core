import Foundation
import Testing
@testable import ZhenCore

// The naming rules, against real strings.
//
// Every rule in `BonjourVocabulary` exists because a real device produces a string that
// breaks the obvious implementation, and none of them can be re-derived by reading the
// DNS-SD specification — the specification permits all of it. So the fixtures carry
// PROVENANCE: which strings came from the reference network, which were read off
// 10.10.20.0/24 while this phase was written, and which are shapes constructed to pin a
// boundary. A test that cannot tell those apart is a test nobody can audit.

/// One instance-name cleaning case from the fixture file.
private struct InstanceCase: Codable {
    var provenance: String
    var serviceType: String
    var raw: String
    var clean: String?
    var note: String?

    enum CodingKeys: String, CodingKey {
        case provenance
        case serviceType = "service_type"
        case raw
        case clean
        case note
    }
}

/// One TXT-model case.
private struct ModelCase: Codable {
    var provenance: String
    var serviceType: String
    var txt: [String: String]
    var model: String?
    var note: String?

    enum CodingKeys: String, CodingKey {
        case provenance
        case serviceType = "service_type"
        case txt
        case model
        case note
    }
}

/// One "which field is the name" case.
private struct NameChoiceCase: Codable {
    var provenance: String
    var serviceType: String
    var instance: String
    var txt: [String: String]
    var name: String
    var note: String?

    enum CodingKeys: String, CodingKey {
        case provenance
        case serviceType = "service_type"
        case instance
        case txt
        case name
        case note
    }
}

private struct BonjourFixtures: Codable {
    var instanceNames: [InstanceCase]
    var txtModels: [ModelCase]
    var nameChoice: [NameChoiceCase]

    enum CodingKeys: String, CodingKey {
        case instanceNames = "instance_names"
        case txtModels = "txt_models"
        case nameChoice = "name_choice"
    }

    static func load() throws -> BonjourFixtures {
        let url = try #require(
            Bundle.module.url(forResource: "Fixtures/bonjour-records", withExtension: "json"),
            "the committed Bonjour fixtures should be in the test bundle"
        )
        return try JSONDecoder().decode(BonjourFixtures.self, from: Data(contentsOf: url))
    }
}

@Suite("Bonjour instance names are cleaned against real strings")
struct InstanceNameTests {
    @Test("Every committed instance name cleans to the recorded result")
    func fixturesClean() throws {
        let fixtures = try BonjourFixtures.load()
        // A guard against the fixture file being silently emptied or renamed: a suite
        // that loads zero cases passes without testing anything.
        #expect(fixtures.instanceNames.count >= 14)
        for testCase in fixtures.instanceNames {
            #expect(
                BonjourVocabulary.cleanInstanceName(testCase.raw) == testCase.clean,
                "\(testCase.provenance) \(testCase.serviceType): '\(testCase.raw)'"
            )
        }
    }

    @Test("The sleep proxy and the companion link name one device two ways, and the clean one wins")
    func sleepProxyLosesToCompanionLink() throws {
        // The reason ranks exist at all. Same device, same instant, two names.
        let proxy = try #require(BonjourVocabulary.candidate(from: ServiceSighting(
            ip: IPv4Address("10.10.20.2")!,
            serviceType: "_sleep-proxy._udp",
            instanceName: "70-35-60-63.1 Sala de entretenimiento"
        )))
        let companion = try #require(BonjourVocabulary.candidate(from: ServiceSighting(
            ip: IPv4Address("10.10.20.2")!,
            serviceType: "_companion-link._tcp",
            instanceName: "Sala de entretenimiento"
        )))
        // Cleaning makes the two agree on the value; the rank is what decides the winner
        // when they do not.
        #expect(proxy.value == "Sala de entretenimiento")
        #expect(companion.rank < proxy.rank)
        #expect([proxy, companion].best == companion)
        // And the loser is still there, which is the whole "Known by" panel.
        #expect([proxy, companion].alternates == [proxy])
    }

    @Test("A name whose case-folding changes its length does not trap")
    func unicodeLengthChangeDoesNotTrap() {
        // The crash. `lowercased()` is not length-preserving: İ (U+0130) folds to two
        // scalars, K (U+212A KELVIN SIGN) to one that encodes shorter, ẞ to ß. A
        // `Range<String.Index>` computed against a lowered copy and used to slice the
        // original is an index into a different string, and on a long enough name it
        // lands past the end and traps — inside a task-group child, on nothing worse
        // than a device with a Turkish name.
        //
        // Every one of these is a call that used to trap. Reaching the expectation at
        // all is most of the test.
        #expect(BonjourVocabulary.cleanInstanceName("İstanbul Ofis._smb._tcp.local.") == "İstanbul Ofis")
        #expect(BonjourVocabulary.cleanInstanceName("K Studio._airplay._tcp.local.") == "K Studio")
        #expect(BonjourVocabulary.cleanInstanceName("ẞ-Server._workstation._tcp.local.") == "ẞ-Server")
        #expect(BonjourVocabulary.cleanInstanceName("Ångström Lab._device-info._tcp.local.") == "Ångström Lab")
        // Long enough that a shifted index is comfortably out of bounds rather than
        // merely wrong.
        let long = String(repeating: "İ", count: 64)
        #expect(BonjourVocabulary.cleanInstanceName(long + "._smb._tcp.local.") == long)
        #expect(BonjourVocabulary.cleanInstanceName(long) == long)
    }

    @Test("A trailing service suffix goes, and a dot inside a name stays")
    func serviceSuffix() {
        #expect(
            BonjourVocabulary.cleanInstanceName("Mac Studio de Jose._raop._tcp.local.")
                == "Mac Studio de Jose"
        )
        // Bonjour instance names may contain dots. Only a real service suffix is cut.
        #expect(BonjourVocabulary.cleanInstanceName("Rev.2 Speaker") == "Rev.2 Speaker")
        #expect(BonjourVocabulary.cleanInstanceName("office.local printer") == "office.local printer")
    }

    @Test("An unknown service type still yields a name, ranked behind every known one")
    func unknownTypeIsNotDiscarded() throws {
        let candidate = try #require(BonjourVocabulary.candidate(from: ServiceSighting(
            ip: IPv4Address("10.10.20.5")!,
            serviceType: "_matter._tcp",
            instanceName: "Kitchen Sensor"
        )))
        #expect(candidate.value == "Kitchen Sensor")
        #expect(candidate.rank == BonjourVocabulary.serviceTypes.count)
    }
}

@Suite("TXT model extraction, including the key that is not a model")
struct TXTModelTests {
    @Test("Every committed TXT record yields the recorded model")
    func fixturesExtract() throws {
        let fixtures = try BonjourFixtures.load()
        #expect(fixtures.txtModels.count >= 12)
        for testCase in fixtures.txtModels {
            #expect(
                BonjourVocabulary.model(fromTXT: testCase.txt, serviceType: testCase.serviceType)
                    == testCase.model,
                "\(testCase.provenance) \(testCase.serviceType): \(testCase.txt)"
            )
        }
    }

    @Test("`md` means the metadata list on _raop and the model everywhere else")
    func mdIsScopedToRAOP() {
        // Stated as its own test rather than left to the fixture loop, because BOTH
        // halves of it are silent data defects and they pull in opposite directions.
        //
        // Read `md` on _raop and every AirPlay speaker gets the model "0,1,2" — short,
        // uniform, plausible enough to survive review. Forbid it everywhere to avoid
        // that, and every Chromecast, Nest and Android TV silently loses the only model
        // string it publishes. The service type is the thing that disambiguates, so the
        // rule is scoped to it.
        for spelling in ["md", "MD", "Md"] {
            #expect(BonjourVocabulary.model(fromTXT: [spelling: "0,1,2"], serviceType: "_raop._tcp") == nil)
            #expect(
                BonjourVocabulary.model(
                    fromTXT: [spelling: "0,1,2", "am": "AppleTV5,3"], serviceType: "_raop._tcp"
                ) == "AppleTV5,3"
            )
            #expect(
                BonjourVocabulary.model(
                    fromTXT: [spelling: "Chromecast Ultra"], serviceType: "_googlecast._tcp"
                ) == "Chromecast Ultra"
            )
        }
        #expect(BonjourVocabulary.forbiddenModelKeys(for: "_raop._tcp").contains("md"))
        #expect(BonjourVocabulary.forbiddenModelKeys(for: "_raop._tcp.local.").contains("md"))
        #expect(BonjourVocabulary.forbiddenModelKeys(for: "_googlecast._tcp").isEmpty)
    }

    @Test("A Chromecast keeps its model through the whole candidate path")
    func googlecastKeepsItsModel() throws {
        // End to end, because the scoping is only useful if `candidate(from:)` passes
        // the service type down — and a signature that let it be omitted is exactly how
        // this regresses.
        let candidate = try #require(BonjourVocabulary.candidate(from: ServiceSighting(
            ip: IPv4Address("10.10.20.31")!,
            serviceType: "_googlecast._tcp",
            instanceName: "Chromecast-6f3a1d9c4b2e8a7f",
            txt: ["fn": "Sala TV", "md": "Chromecast Ultra"]
        )))
        #expect(candidate.value == "Sala TV")
        #expect(candidate.model == "Chromecast Ultra")
    }

    @Test("The model survives on a candidate whose name lost the cascade")
    func modelTravelsOnTheLoser() throws {
        // A source can supply a model without supplying the winning name, which is why
        // the model lives on the candidate rather than on the device.
        let host = HostFacts(
            ip: IPv4Address("10.10.20.2")!,
            allNames: [
                NameCandidate(value: "Sala de entretenimiento", source: .administrative),
                try #require(BonjourVocabulary.candidate(from: ServiceSighting(
                    ip: IPv4Address("10.10.20.2")!,
                    serviceType: "_airplay._tcp",
                    instanceName: "Sala de entretenimiento",
                    txt: ["md": "0,1,2", "am": "AppleTV5,3"]
                ))),
            ]
        )
        #expect(host.displayName == "Sala de entretenimiento")
        #expect(host.displayModel == "AppleTV5,3")
    }
}

@Suite("Which field is the name")
struct FriendlyNameTests {
    @Test("Every committed name-choice case picks the recorded field")
    func fixturesChoose() throws {
        let fixtures = try BonjourFixtures.load()
        #expect(fixtures.nameChoice.count >= 2)
        for testCase in fixtures.nameChoice {
            let candidate = BonjourVocabulary.candidate(from: ServiceSighting(
                ip: IPv4Address("10.10.20.9")!,
                serviceType: testCase.serviceType,
                instanceName: testCase.instance,
                txt: testCase.txt
            ))
            #expect(candidate?.value == testCase.name, "\(testCase.provenance): \(testCase.note ?? "")")
        }
    }

    @Test("Only googlecast reads a friendly TXT key, and it is the cleanest type")
    func onlyGooglecastHasAFriendlyKey() throws {
        let withKey = BonjourVocabulary.serviceTypes.filter { $0.friendlyNameKey != nil }
        #expect(withKey.map(\.name) == ["_googlecast._tcp"])
        #expect(try #require(BonjourVocabulary.serviceType("_googlecast._tcp")).rank == 0)
    }
}

@Suite("The browsed type table is the one contract two files share")
struct ServiceTypeTableTests {
    @Test("Ranks are the table order, dense and unique")
    func ranksAreDense() {
        #expect(BonjourVocabulary.serviceTypes.map(\.rank) == Array(0..<BonjourVocabulary.serviceTypes.count))
    }

    @Test("The types the spec records as worth browsing are all present")
    func specTypesArePresent() {
        // The list is a product decision recorded in the spec's mDNS section. If a type
        // is dropped from the table it must be dropped deliberately, and this is what
        // makes that a failing test rather than a silently narrower scan.
        let required = [
            "_googlecast._tcp", "_companion-link._tcp", "_airplay._tcp", "_homekit._tcp",
            "_device-info._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_esphomelib._tcp",
            "_androidtvremote2._tcp", "_workstation._tcp", "_smb._tcp", "_ssh._tcp",
            "_ipp._tcp", "_printer._tcp", "_hue._tcp", "_raop._tcp", "_sleep-proxy._udp",
        ]
        for type in required {
            #expect(BonjourVocabulary.serviceType(type) != nil, "\(type) should be browsed")
        }
        #expect(BonjourVocabulary.browsedTypes.count == required.count)
    }

    @Test("dns_sd's trailing-dot and domain-suffixed spellings all resolve")
    func typeLookupToleratesDNSSDSpellings() {
        // A browse reply's regtype is `_airplay._tcp.`; a resolve's is sometimes
        // `_airplay._tcp.local.`. A lookup that missed either would rank every sighting
        // as unknown and silently disable the whole ranking mechanism.
        for spelling in ["_airplay._tcp", "_airplay._tcp.", "_airplay._tcp.local", "_airplay._tcp.local."] {
            #expect(BonjourVocabulary.rank(of: spelling) == 3, "\(spelling)")
        }
    }

    @Test("Every browsed type is declared in the CLI's embedded Info.plist")
    func plistDeclaresEveryBrowsedType() throws {
        // A type that is browsed but NOT listed under NSBonjourServices returns nothing,
        // silently, which is indistinguishable from a device that is not present. The
        // two files are a contract and nothing but a test enforces it.
        let plist = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // ZhenCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // zhen
            .appendingPathComponent("Sources/zhen/Info.plist")
        guard let data = try? Data(contentsOf: plist) else {
            // The CLI is a separate package and may not be checked out beside this one.
            // Skipping is honest; asserting against a file that is not there is not.
            return
        }
        let declared = try #require(
            (try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any])?["NSBonjourServices"] as? [String]
        )
        for type in BonjourVocabulary.browsedTypes {
            #expect(declared.contains(type), "\(type) is browsed but not declared in Info.plist")
        }
    }
}

@Suite("The naming budget is a stated trade")
struct NameBudgetTests {
    @Test("A generous run budget is capped rather than spent")
    func ceilingBinds() {
        // The product decision: naming yields almost everything it will yield in the
        // first seconds, so a 60-second run must not mean a minute of listening.
        let budget = NameBudget(within: Deadline(after: .seconds(60)))
        #expect(budget.stageAllowance <= NameBudget.ceiling)
        #expect(budget.stageAllowance == NameBudget.ceiling)
    }

    @Test("A short run budget gives naming a proportional slice, not the floor")
    func shareBindsOnAShortRun() {
        let budget = NameBudget(within: Deadline(after: .seconds(20)))
        // 40% of 20s is 8s, which the ceiling cuts to 6s.
        #expect(budget.stageAllowance == NameBudget.ceiling)
        let tight = NameBudget(within: Deadline(after: .seconds(5)))
        // 40% of 5s is 2s, between the floor and the ceiling, so it is taken as-is.
        #expect(tight.stageAllowance > NameBudget.floor)
        #expect(tight.stageAllowance < NameBudget.ceiling)
    }

    @Test("No sub-budget can outlive the run")
    func everySliceIsClamped() {
        let parent = Deadline(after: .milliseconds(400))
        let budget = NameBudget(within: parent)
        // The floor asks for 1.5s and the run has 400ms. The clamp is what stops the
        // stage from outliving the scan that spawned it.
        #expect(budget.stage.instant <= parent.instant)
        #expect(budget.mdns.instant <= parent.instant)
        #expect(budget.ssdp.instant <= parent.instant)
        #expect(budget.netbiosSlice().instant <= parent.instant)
    }

    @Test("NetBIOS's slice is struck when it starts, not when the stage began")
    func netbiosSliceIsLate() async throws {
        // The bug this method exists to prevent: NetBIOS runs after a concurrent phase
        // that may take 70% of the stage, so a deadline struck up front for 30% of the
        // stage has already expired by the time NetBIOS is reached — and the source is
        // never asked, silently, with the stage still reporting success.
        let budget = NameBudget(within: Deadline(after: .seconds(20)))
        try await Task.sleep(for: .milliseconds(250))
        let slice = budget.netbiosSlice()
        #expect(slice.remaining > .milliseconds(100))
        #expect(slice.instant <= budget.stage.instant)
    }
}

@Suite("The ledger keeps everything and remaps the local machine")
struct NameLedgerTests {
    private static let local = IPv4Address("10.10.20.8")!

    @Test("A loopback sighting is remapped onto this machine's own address")
    func loopbackRemap() {
        // The local responder answers its own address query from the loopback record, so
        // this machine's Bonjour name arrives attached to 127.0.0.1 — an address in no
        // report. Without the remap, the machine running the scan is the one device the
        // scan cannot name.
        var ledger = NameLedger(localAddress: Self.local)
        ledger.record(NameCandidate(value: "JC’s MacBook Pro", source: .mdns, rank: 1),
                      for: IPv4Address("127.0.0.1")!)
        #expect(ledger.names[Self.local]?.first?.value == "JC’s MacBook Pro")
        #expect(ledger.names[IPv4Address("127.0.0.1")!] == nil)
    }

    @Test("With no local address known, a loopback sighting is dropped rather than misfiled")
    func loopbackWithoutARemapTarget() {
        var ledger = NameLedger()
        ledger.record(NameCandidate(value: "somebody", source: .mdns), for: IPv4Address("127.0.0.1")!)
        #expect(ledger.names.isEmpty)
    }

    @Test("Losing candidates are kept and exact repeats are not")
    func keepsLosersDropsRepeats() {
        var ledger = NameLedger(localAddress: Self.local)
        let ip = IPv4Address("10.10.20.2")!
        let clean = NameCandidate(value: "Sala de entretenimiento", source: .mdns, rank: 1)
        let raop = NameCandidate(value: "Sala de entretenimiento", source: .mdns, rank: 15)
        ledger.record(clean, for: ip)
        ledger.record(raop, for: ip)
        // The same browse reply arrives again when mDNSResponder refreshes its cache.
        ledger.record(clean, for: ip)
        #expect(ledger.names[ip]?.count == 2)
        #expect(ledger.names[ip]?.best == clean)
    }

    @Test("NetBIOS is asked only about hosts nothing self-sufficient has named")
    func unnamedGating() {
        var ledger = NameLedger(localAddress: Self.local)
        let named = IPv4Address("10.10.20.2")!
        let weaklyNamed = IPv4Address("10.10.20.3")!
        let unnamed = IPv4Address("10.10.20.12")!
        ledger.record(NameCandidate(value: "Sala de entretenimiento", source: .mdns, rank: 1), for: named)
        // Reverse DNS routinely returns a name derived from the address itself, which
        // looks like a name and identifies nothing — so it does not stop NetBIOS.
        ledger.record(NameCandidate(value: "10-10-20-3.lan", source: .dns), for: weaklyNamed)
        #expect(ledger.unnamed(among: [named, weaklyNamed, unnamed]) == [weaklyNamed, unnamed])
    }
}
