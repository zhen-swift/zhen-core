// LookLongerInterfaceTests.swift — F5 of the fixes brief (questions, Q12).
//
// `--look-longer` asks on the interface the latest scan went out of. Without `--iface`
// it takes that one; with an `--iface` that disagrees it refuses with exit 64; with an
// interface the machine no longer has, it says so. That `run.interface` survives history
// is `RunInterfaceTests`, in core, so it runs on Linux.

import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

@Suite("Look longer asks on the latest scan's interface (F5)")
struct LookLongerInterfaceTests {
    static let en0 = FakeInterfaces.en0
    static let bridge = NetworkInterface(
        name: "bridge100", address: IPv4Address("192.168.64.1")!,
        network: IPv4Network("192.168.64.0/24")!, hardwareAddress: nil
    )

    static func run(on interface: String) -> ScanRun {
        ScanRun(
            id: UUID(), startedAt: Timestamp(millisecondsSinceEpoch: 1_790_000_000_000),
            target: IPv4Network("192.168.64.0/24")!, interface: interface,
            engine: EngineDescriptor(name: "fixture", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing()
        )
    }

    @Test("Without --iface: the latest scan's interface, not the primary one")
    func takesTheRunsInterface() throws {
        let chosen = try Scan.parse(["--look-longer"]).lookLongerInterface(
            latest: Self.run(on: "bridge100"), available: [Self.en0, Self.bridge]
        )
        #expect(chosen == Self.bridge)
        // The same interface named explicitly is not a disagreement.
        let named = try Scan.parse(["--look-longer", "--iface", "bridge100"]).lookLongerInterface(
            latest: Self.run(on: "bridge100"), available: [Self.en0, Self.bridge]
        )
        #expect(named == Self.bridge)
    }

    @Test("An --iface that disagrees with the latest scan is refused, exit 64")
    func disagreementIsUsage() throws {
        let scan = try Scan.parse(["--look-longer", "--iface", "en0"])
        var status: zhen.ExitStatus?
        do {
            _ = try scan.lookLongerInterface(
                latest: Self.run(on: "bridge100"), available: [Self.en0, Self.bridge]
            )
        } catch {
            status = error.status
            #expect(error.message.contains("bridge100") && error.message.contains("en0"))
        }
        #expect(status == .usage)
        #expect(zhen.ExitStatus.usage.rawValue == 64)
    }

    @Test("An interface the machine no longer has is the no-such-interface failure")
    func goneIsUnavailable() throws {
        let scan = try Scan.parse(["--look-longer"])
        var status: zhen.ExitStatus?
        do {
            _ = try scan.lookLongerInterface(
                latest: Self.run(on: "bridge100"), available: [Self.en0]
            )
        } catch {
            status = error.status
        }
        #expect(status == .unavailable)
    }
}
