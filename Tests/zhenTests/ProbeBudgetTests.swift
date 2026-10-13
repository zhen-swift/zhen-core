import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// The probe-count guard, stage 8.
//
// `PortSpec.commonServices` has carried this instinct in its doc comment since it was
// written — *"a deep scan is a deliberate act, not the default, and 65,535 ports across
// a /24 is 16 million probes for almost no additional information"* — and nothing
// enforced it. This is the enforcement.

@Suite("A scan says how big it is before it runs")
struct ProbeBudgetTests {
    private func budget(hosts: Int, ports: Int, concurrency: Int = 512) -> ProbeBudget {
        ProbeBudget(hosts: hosts, ports: ports, concurrency: concurrency,
                    perHostDeadline: .milliseconds(600))
    }

    @Test("The count is hosts times ports, and nothing is rounded away")
    func theCount() {
        #expect(budget(hosts: 254, ports: 65_535).probes == 16_645_890)
        #expect(budget(hosts: 1, ports: 65_535).probes == 65_535)
        #expect(budget(hosts: 254, ports: 36).probes == 9_144)
    }

    /// **The threshold has to sit in a specific gap, and the first version did not.**
    ///
    /// Above every scan this tool is built for, below the smallest one a person would
    /// regret. It was 200,000 to begin with — above `all` on a single host — so the doc
    /// comment describing the gap and the number underneath it disagreed, and a
    /// single-host `all` would have started 65,535 probes without a word.
    @Test("The threshold separates the widest deliberate scan from the smallest regret")
    func theThresholdSitsInTheGap() {
        let widestDeliberate = budget(hosts: 254, ports: PortSpec.commonServices.ports.count)
        let smallestRegret = budget(hosts: 1, ports: 65_535)
        #expect(!widestDeliberate.needsConfirmation,
                Comment(rawValue: "`common` across a /24 is \(widestDeliberate.probes) probes "
                        + "and asks for confirmation — the threshold is below the scans this "
                        + "tool is for"))
        #expect(smallestRegret.needsConfirmation,
                Comment(rawValue: "`all` on one host is \(smallestRegret.probes) probes and "
                        + "runs without a word — the threshold is above the smallest accident"))
        #expect(widestDeliberate.probes < ProbeBudget.confirmationThreshold)
        #expect(ProbeBudget.confirmationThreshold < smallestRegret.probes)
    }

    @Test("The refusal carries the number it refused")
    func theRefusalSaysTheNumber() {
        // The gate in the plan: "`all` on a /24 refuses and prints the count it
        // refused". A refusal that says only "too many" leaves the person guessing at
        // which part of their command was the expensive one.
        let large = budget(hosts: 254, ports: 65_535)
        let text = large.refusal(hosts: 254, ports: 65_535)
        #expect(text.contains("16,645,890"),
                Comment(rawValue: "the count is missing from: \(text)"))
        #expect(text.contains("65,535") && text.contains("254"),
                "the refusal does not break the count into ports and hosts")
        #expect(text.contains("--yes"), "the refusal does not say how to proceed")
        #expect(text.hasSuffix("."), "the refusal is not a sentence")
    }

    /// The floor is a floor, not an estimate.
    ///
    /// A real duration estimate needs the network's round trips, which is the thing the
    /// scan is about to measure — so it would be a guess printed beside a count that is
    /// not one. What a floor promises is checkable: the scan cannot beat it.
    @Test("The floor falls as concurrency rises, and never claims to be a prediction")
    func theFloorIsAFloor() {
        let narrow = budget(hosts: 254, ports: 65_535, concurrency: 64)
        let wide = budget(hosts: 254, ports: 65_535, concurrency: 4_096)
        #expect(narrow.floor > wide.floor,
                "the floor ignores how many probes can be in flight")
        // One probe at a time is one per-host deadline per probe, exactly.
        let serial = budget(hosts: 1, ports: 10, concurrency: 1)
        #expect(serial.floor == .milliseconds(6_000))
    }

    @Test("A scan small enough to be ordinary says nothing at all")
    func smallScansAreSilent() {
        // The guard must not become a thing people learn to ignore.
        for (hosts, ports) in [(1, 36), (10, 36), (254, 36), (1, 1024), (10, 1024)] {
            #expect(!budget(hosts: hosts, ports: ports).needsConfirmation,
                    Comment(rawValue: "\(hosts) hosts x \(ports) ports asks for confirmation"))
        }
    }
}

@Suite("--yes is how a large scan gets to run")
struct ConfirmationFlagTests {
    @Test("Both commands take it, and neither assumes it")
    func theFlagExists() throws {
        let scan = try Scan.parse([])
        let ports = try Ports.parse(["10.10.20.1"])
        #expect(scan.yes == false, "scan assumes confirmation")
        #expect(ports.yes == false, "ports assumes confirmation")
        #expect(try Scan.parse(["--yes"]).yes)
        #expect(try Ports.parse(["10.10.20.1", "--yes"]).yes)
    }
}
