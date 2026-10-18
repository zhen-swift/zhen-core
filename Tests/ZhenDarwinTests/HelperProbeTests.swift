// Apple-only, like the target it tests.
#if canImport(Darwin)
import Foundation
import Synchronization
import Testing
@testable import ZhenDarwin
@testable import ZhenPrivilege

// The composition-time helper check, bounded.
//
// Building a scanner asks whether a capture device can be had, and with the helper policy
// that means asking the helper. A registration launchd cannot start accepts the connection
// and never answers, and the check waited out the full acquisition timeout: 3.2 s on every
// engine build, measured inside the app on the Mac with a stale registration. From a test
// process the same registration reports "absent" in a millisecond, so the wait cannot be
// reproduced here — what is tested is the bound itself, and which bound the probe uses.
@Suite("A helper that never answers costs the probe a short bound")
struct HelperProbeTests {
    @Test("The probe's bound is well under the acquisition timeout")
    func boundIsShorter() {
        #expect(HelperClient.probeTimeout < HelperClient.acquisitionTimeout)
        #expect(HelperClient.probeTimeout <= .milliseconds(1_000))
    }

    @Test("The composition-time probe hands the helper the short bound; a scan, the long one")
    func probeUsesTheShortBound() async {
        let seen = Mutex<[Duration]>([])
        let source = CaptureSource { _, _, timeout in
            seen.withLock { $0.append(timeout) }
            return .failure(.helperAbsent)
        }
        _ = await source.probe(interface: "en0")
        _ = try? await source.open(interface: "en0", filter: BPFFilter.arp())
        #expect(seen.withLock { $0 } == [HelperClient.probeTimeout, HelperClient.acquisitionTimeout])
    }
}

@Suite("A helper that never answers costs the probe a short bound, against the wall clock")
struct HelperProbeWallClockTests {
    @Test("A request nobody answers is given up on at its bound, and the give-up runs")
    func silenceEndsAtTheBound() async {
        let gaveUp = Mutex(false)
        let clock = ContinuousClock()
        let start = clock.now
        let value = await HelperClient.answer(within: .milliseconds(150), otherwise: "nobody") { _ in
            { gaveUp.withLock { $0 = true } }
        }
        let elapsed = clock.now - start
        #expect(value == "nobody")
        #expect(elapsed < .milliseconds(1_000), "waited \(elapsed) on a 150 ms bound")
        #expect(gaveUp.withLock { $0 }, "the connection would have been left open")
    }

    @Test("An answer before the bound wins, and the bound does not fire over it")
    func answerWins() async {
        let gaveUp = Mutex(false)
        let value = await HelperClient.answer(within: .milliseconds(150), otherwise: "nobody") { done in
            done.finish("helper")
            return { gaveUp.withLock { $0 = true } }
        }
        try? await Task.sleep(for: .milliseconds(300))
        #expect(value == "helper")
        #expect(!gaveUp.withLock { $0 }, "the give-up ran after an answer had already won")
    }
}

#endif
