// IPv6WindowPipelineTests.swift — F8 of the fixes brief's second addendum, through the
// pipeline: the all-nodes window closes when the v4 sweep ends, `--ipv6-window` sets or
// removes it, and `run.ipv6_window` says what happened.

import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

/// A sweep that takes `sweep` and notes when it ended.
nonisolated final class TimedDiscovery: HostDiscovery, @unchecked Sendable {
    let descriptor = EngineDescriptor(name: "fake", kind: .unprivileged, capabilities: [.icmpSweep])
    let sweep: Duration
    let hosts: [HostFacts]
    // Guards `endedAt`, written by the sweep and read by the test after the run.
    private let lock = NSLock()
    private var endedAt: MonotonicInstant?

    init(sweep: Duration, hosts: [HostFacts] = []) {
        self.sweep = sweep
        self.hosts = hosts
    }

    var ended: MonotonicInstant? { lock.withLock { endedAt } }

    func discover(_ target: ScanTarget, deadline: Deadline, progress: ProgressSink) async -> DiscoveryResult {
        try? await Task.sleep(for: sweep)
        lock.withLock { endedAt = .now }
        return DiscoveryResult(
            hosts: hosts, usedCapabilities: [.icmpSweep],
            timing: Timing(stages: [StageTiming(stage: .discovery, elapsedMillis: sweep.milliseconds, probesSent: 254)])
        )
    }

    func stream(_ target: ScanTarget, deadline: Deadline) -> AsyncStream<ProbeEvent> {
        AsyncStream { $0.finish() }
    }
}

/// An all-nodes echo that listens by F8's rule, and records what it was asked and when
/// the scan closed its window.
nonisolated final class WindowRecordingMulticast: IPv6MulticastEcho, @unchecked Sendable {
    struct Call: Sendable { var floor: Duration; var cap: Duration; var closedAt: MonotonicInstant? }
    // Guards `log`, written inside the solicitation task and read by the test afterwards.
    private let lock = NSLock()
    private var log: [Call] = []

    var calls: [Call] { lock.withLock { log } }

    func solicitAllNodes(on interface: String, within window: Duration) async -> IPv6Solicitation {
        await solicitAllNodes(on: interface, floor: window, cap: window, closing: AsyncStream { _ in })
    }

    func solicitAllNodes(
        on interface: String, floor: Duration, cap: Duration, closing: AsyncStream<Void>
    ) async -> IPv6Solicitation {
        let index = lock.withLock { log.append(Call(floor: floor, cap: cap)); return log.count - 1 }
        // Splits the stream: the first element is noted, then passed on to the real wait.
        let (relay, forward) = AsyncStream<Void>.makeStream()
        let watcher = Task {
            for await _ in closing { break }
            lock.withLock { log[index].closedAt = .now }
            forward.yield()
            forward.finish()
        }
        let listened = await ListenWindow.wait(floor: floor, cap: cap, closing: relay)
        watcher.cancel()
        return IPv6Solicitation(responders: [], sent: 1, listened: listened)
    }

    func echo(_ address: IPv6Address, on interface: String, within budget: Duration) async -> Bool { false }
}

/// Wall-clock bounds here are loose on purpose: the whole suite runs in parallel, and a
/// tight one measured the machine's load (it failed at 876 ms for a 20 ms sweep under the
/// full run, and passed alone). What F8 claims is that the scan no longer waits out the 2 s
/// cap; the window's own length, `run.ipv6_window.millis`, is held to tight bounds.
@Suite("The IPv6 window in the pipeline (R8, fixture)")
struct IPv6WindowPipelineWallClockTests {
    private func scan(
        sweep: Duration, window: IPv6Window, multicast: any IPv6MulticastEcho = WindowRecordingMulticast(),
        budget: Duration = .seconds(5)
    ) async -> (report: ScanReport, discovery: TimedDiscovery, wall: Duration) {
        let discovery = TimedDiscovery(sweep: sweep)
        let pipeline = ScanPipeline(
            scanner: PlatformScanner(
                interfaces: FakeInterfaces(), discovery: discovery, ports: FakePorts(), udpPorts: FakePorts(),
                ipv6Neighbors: FixedIPv6Neighbors(entries: []), ipv6Multicast: multicast,
                naming: FakeNaming(), descriptorLimit: 92_160, concurrency: 512, notices: []),
            renderer: RecordingRenderer(), discoveryOnly: true, deep: false, ports: .commonServices,
            ipv6Window: window
        )
        let watch = Stopwatch()
        let report = await pipeline.run(target: ScanTarget(scanning: FakeInterfaces.en0), budget: budget).report
        return (report, discovery, watch.elapsed)
    }

    @Test("By default the window closes when the sweep ends, and is asked for 500 ms to 2 s")
    func closesWithTheSweep() async throws {
        let multicast = WindowRecordingMulticast()
        let (report, discovery, wall) = await scan(sweep: .milliseconds(700), window: .default, multicast: multicast)
        let call = try #require(multicast.calls.first)
        #expect(call.floor == .milliseconds(500) && call.cap == .seconds(2))
        let closed = try #require(call.closedAt)
        let ended = try #require(discovery.ended)
        #expect(closed >= ended, "closed before the sweep had ended")
        let window = try #require(report.run.ipv6Window)
        #expect(window.policy == "sweep" && window.floorMillis == 500 && window.capMillis == 2_000)
        #expect(window.millis >= 700 && window.millis < 1_000, "\(window.millis)")
        #expect(wall < .seconds(2), "the scan waited out the cap: \(wall)")
    }

    @Test("A sweep that ends at once still listens for the 500 ms floor")
    func floor() async throws {
        let (report, _, wall) = await scan(sweep: .milliseconds(20), window: .default)
        let window = try #require(report.run.ipv6Window)
        #expect(window.millis >= 500 && window.millis < 800, "\(window.millis)")
        #expect(wall >= .milliseconds(500) && wall < .seconds(2), "\(wall)")
    }

    @Test("--ipv6-window <duration> listens exactly that long, whenever the sweep ends")
    func fixed() async throws {
        let multicast = WindowRecordingMulticast()
        let (report, _, _) = await scan(sweep: .milliseconds(20), window: .fixed(.milliseconds(700)), multicast: multicast)
        let call = try #require(multicast.calls.first)
        #expect(call.floor == .milliseconds(700) && call.cap == .milliseconds(700))
        let window = try #require(report.run.ipv6Window)
        #expect(window.policy == "fixed" && window.floorMillis == 700 && window.capMillis == 700)
        #expect(window.millis >= 700 && window.millis < 1_000, "\(window.millis)")
    }

    @Test("--ipv6-window 0 sends no echo and says so; the cache is still read")
    func off() async throws {
        let multicast = WindowRecordingMulticast()
        let (report, _, wall) = await scan(sweep: .milliseconds(20), window: .off, multicast: multicast)
        #expect(multicast.calls.isEmpty)
        #expect(report.run.ipv6Window == IPv6WindowReport(policy: "off", millis: 0))
        #expect(report.run.timing.stages.first?.probesSent == 254, "no all-nodes packet counted")
        #expect(wall < .seconds(2), "\(wall)")
    }

    @Test("The scan's deadline shortens floor and cap")
    func deadline() async throws {
        let multicast = WindowRecordingMulticast()
        _ = await scan(sweep: .milliseconds(20), window: .default, multicast: multicast, budget: .milliseconds(300))
        let call = try #require(multicast.calls.first)
        #expect(call.cap <= .milliseconds(300) && call.floor <= .milliseconds(300))
    }

    @Test("No IPv6 engine, no run.ipv6_window — so the artifact baselines don't move")
    func noEngine() async throws {
        let (report, _, _) = await scan(sweep: .milliseconds(5), window: .default, multicast: NoIPv6MulticastEcho())
        #expect(report.run.ipv6Window == nil)
        let text = String(decoding: try report.encoded(), as: UTF8.self)
        #expect(!text.contains("ipv6_window"))
    }

    @Test("--ipv6-window parses sweep, durations and 0, and refuses the rest")
    func parsing() throws {
        #expect(try Scan.parse([]).parseIPv6Window() == .default)
        #expect(try Scan.parse(["--ipv6-window", "SWEEP"]).parseIPv6Window() == .default)
        #expect(try Scan.parse(["--ipv6-window", "2s"]).parseIPv6Window() == .fixed(.seconds(2)))
        #expect(try Scan.parse(["--ipv6-window", "750ms"]).parseIPv6Window() == .fixed(.milliseconds(750)))
        for zero in ["0", "0ms", "0s"] {
            #expect(try Scan.parse(["--ipv6-window", zero]).parseIPv6Window() == .off)
        }
        for bad in ["-1s", "soon", "forever"] {
            var refused = false
            do { _ = try Scan.parse(["--ipv6-window", bad]).parseIPv6Window() } catch { refused = true }
            #expect(refused, "accepted \(bad)")
        }
    }
}
