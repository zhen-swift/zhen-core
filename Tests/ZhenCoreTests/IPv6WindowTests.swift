// IPv6WindowTests.swift — F8 of the fixes brief's second addendum, the portable half.
//
// The window after the all-nodes echo closes when the scan says the v4 sweep has ended,
// never before its floor and never after its cap. Real time, in short spans with wide
// margins, because the rule is about when a wait ends; nothing here is a measurement.

import Foundation
import Testing
@testable import ZhenCore

@Suite("The IPv6 window closes with the sweep, floored and capped (R8, portable)")
struct IPv6WindowTests {
    static let floor = Duration.milliseconds(100)
    static let cap = Duration.milliseconds(500)

    /// Opens a window, closes it `after` in (or never), and returns how long it was open.
    private func open(closingAfter after: Duration?, floor: Duration = floor, cap: Duration = cap,
                      finishOnly: Bool = false) async -> Duration {
        let (closing, close) = AsyncStream<Void>.makeStream()
        let closer = Task {
            guard let after else { return }
            try? await Task.sleep(for: after)
            if !finishOnly { close.yield() }
            close.finish()
        }
        let listened = await ListenWindow.wait(floor: floor, cap: cap, closing: closing)
        closer.cancel()
        return listened
    }

    @Test("A sweep that ends at once is held to the floor")
    func heldToTheFloor() async {
        let listened = await open(closingAfter: .zero)
        #expect(listened >= Self.floor && listened < .milliseconds(300), "\(listened)")
    }

    @Test("A sweep that ends between floor and cap closes the window when it ends")
    func closesWithTheSweep() async {
        let listened = await open(closingAfter: .milliseconds(250))
        #expect(listened >= .milliseconds(250) && listened < .milliseconds(450), "\(listened)")
    }

    @Test("A sweep that outlasts the cap doesn't hold the window open")
    func cappedWithoutASignal() async {
        let never = await open(closingAfter: nil)
        #expect(never >= Self.cap && never < .milliseconds(700), "\(never)")
        let late = await open(closingAfter: .milliseconds(900))
        #expect(late >= Self.cap && late < .milliseconds(700), "\(late)")
    }

    @Test("The stream finishing closes the window as a signal does")
    func finishCloses() async {
        let listened = await open(closingAfter: .milliseconds(150), finishOnly: true)
        #expect(listened >= .milliseconds(150) && listened < .milliseconds(350), "\(listened)")
    }

    @Test("A floor above the cap is the cap")
    func floorAboveCap() async {
        let listened = await open(closingAfter: .zero, floor: .milliseconds(400), cap: .milliseconds(150))
        #expect(listened >= .milliseconds(150) && listened < .milliseconds(350), "\(listened)")
    }

    @Test("The policies: sweep is 500 ms to 2 s, fixed is one length, off has no window")
    func policies() throws {
        let sweep = try #require(IPv6Window.default.bounds)
        #expect(sweep.floor == .milliseconds(500) && sweep.cap == .seconds(2))
        #expect(IPv6Window.default.name == "sweep")
        let fixed = try #require(IPv6Window.fixed(.seconds(2)).bounds)
        #expect(fixed.floor == .seconds(2) && fixed.cap == .seconds(2))
        #expect(IPv6Window.fixed(.seconds(2)).name == "fixed")
        #expect(IPv6Window.off.bounds == nil && IPv6Window.off.name == "off")
    }

    @Test("run.ipv6_window: its keys, and a run written before F8 has none")
    func wire() throws {
        let report = IPv6WindowReport(window: .default, listened: .milliseconds(512))
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        #expect(object["policy"] as? String == "sweep")
        #expect(object["millis"] as? Double == 512)
        #expect(object["floor_millis"] as? Double == 500)
        #expect(object["cap_millis"] as? Double == 2_000)
        let off = IPv6WindowReport(window: .off, listened: nil)
        #expect(off == IPv6WindowReport(policy: "off", millis: 0))
        let offText = String(decoding: try JSONEncoder().encode(off), as: UTF8.self)
        #expect(!offText.contains("floor_millis") && !offText.contains("cap_millis"))

        let run = ScanRun(
            id: UUID(), startedAt: Timestamp(millisecondsSinceEpoch: 1), target: IPv4Network("10.10.20.0/24")!,
            interface: "en0", engine: EngineDescriptor(name: "fake", kind: .unprivileged, capabilities: []),
            outcome: .complete, timing: Timing(stages: [], counters: ProbeCounterSnapshot(
                probesSent: 0, repliesSeen: 0, peakConcurrency: 0, inFlight: 0)),
            ipv6Window: report
        )
        let data = try JSONEncoder().encode(run)
        #expect(try JSONDecoder().decode(ScanRun.self, from: data) == run)
        var object2 = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object2["ipv6_window"] != nil)
        object2["ipv6_window"] = nil
        let old = try JSONDecoder().decode(ScanRun.self, from: JSONSerialization.data(withJSONObject: object2))
        #expect(old.ipv6Window == nil)
    }
}
