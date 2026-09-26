import Foundation
import Testing
@testable import ZhenCore
@testable import zhen

// `--scan-type`, stage 7.
//
// The mechanism used to be chosen for you: half-open where a capture device opened, a
// full connection where it did not. That is the right default and it made one thing
// impossible — asking for a connect scan ON PURPOSE. Connect scan is not merely the
// fallback: it is the permitted option on a network where sockets are allowed and
// forged frames are not, and a tool that reaches it only by failing to find privilege
// cannot be asked to measure it.
//
// ── The gate is on the wire, not here ─────────────────────────────────────────
//
// What this file can check is the argument surface. That the flag CHANGES THE
// MECHANISM is proven by `Scripts/verify-syn-scan.sh --scan-type-gate`, which runs both
// scans as root — privilege constant, flag the only variable — and reads the frames:
//
//     root --scan-type connect   20 SYNs, 20 distinct source ports, 11 handshakes
//     root --scan-type syn       26 SYNs from ONE source port,       0 handshakes
//
// One socket per probe against one hand-written source port and no ACK ever sent. An
// artifact cannot claim itself into either shape.

@Suite("The scan mechanism can be asked for")
struct ScanTypeArgumentTests {
    @Test("auto is the default on both commands")
    func autoIsDefault() throws {
        let scan = try Scan.parse([])
        let ports = try Ports.parse(["10.10.20.1"])
        #expect(scan.scanType == .auto)
        #expect(ports.scanType == .auto)
    }

    @Test("Each value parses, on both commands")
    func allValuesParse() throws {
        for value in PortScanType.allCases {
            let scan = try Scan.parse(["--scan-type", value.rawValue])
            let ports = try Ports.parse(["10.10.20.1", "--scan-type", value.rawValue])
            #expect(scan.scanType == value)
            #expect(ports.scanType == value)
        }
    }

    @Test("A value that is not a mechanism is refused")
    func nonsenseIsRefused() {
        var rejected = false
        do { _ = try Scan.parse(["--scan-type", "halfopen"]) } catch { rejected = true }
        #expect(rejected, "'halfopen' was accepted as a scan mechanism")
    }

    @Test("The three mechanisms are distinct and spelled as the wire spells them")
    func rawValues() {
        // The artifact's capability list carries these words, so a rename here is a
        // wire change and the compiler should be the one to say so.
        #expect(PortScanType.syn.rawValue == "syn")
        #expect(PortScanType.connect.rawValue == "connect")
        #expect(PortScanType.auto.rawValue == "auto")
        #expect(Set(PortScanType.allCases.map(\.rawValue)).count == 3)
    }
}

@Suite("Forcing a mechanism that is unavailable refuses rather than downgrades")
struct ScanTypeRefusalTests {
    /// **The property that makes the flag worth having.**
    ///
    /// A flag that says "use SYN" and silently runs connect is worse than no flag: the
    /// run reports a measurement of a mechanism it was not using. That is the defect
    /// the artifact's capability list exists to prevent, and this is the same defect one
    /// level up, in the request rather than the report.
    ///
    /// Checked as an integration behaviour rather than a unit, because the refusal comes
    /// from the platform layer deciding no capture device opened. Unprivileged is the
    /// condition under test and is the condition `swift test` runs in.
    @Test("--scan-type syn without a capture device is an error, not a quiet connect scan")
    func synWithoutCaptureRefuses() async throws {
        #expect(!isRunningAsRoot,
                "this test asserts the UNPRIVILEGED refusal and is running as root")
        do {
            _ = try await PlatformScanner.make(concurrencyOverride: 1, portScanType: .syn)
            Issue.record("forcing syn without a capture device was accepted")
        } catch {
            // `PlatformScanner.make` uses typed throws, so `error` is already a
            // `ScanSetupError`. Re-casting it crashes the 6.2 compiler outright.
            #expect(error.message.contains("--scan-type syn"),
                    Comment(rawValue: "the refusal does not name the flag: \(error.message)"))
            #expect(error.message.contains("--scan-type connect"),
                    Comment(rawValue: "the refusal does not say what to use instead: \(error.message)"))
            // Its own sentence, not the ARP sweep's. The capture refusal is phrased for
            // discovery and reads as a paragraph about the wrong stage when pasted here.
            #expect(!error.message.contains("ARP sweep"),
                    Comment(rawValue: "the refusal borrowed discovery's wording: \(error.message)"))
        }
    }

    @Test("connect and auto are always available")
    func connectNeverRefuses() async throws {
        // Connect needs no privilege by construction, and `auto` degrades to it — which
        // is the behaviour that must not change, since every existing run relies on it.
        for mechanism in [PortScanType.connect, .auto] {
            _ = try await PlatformScanner.make(concurrencyOverride: 1, portScanType: mechanism)
        }
    }

    private var isRunningAsRoot: Bool { getuid() == 0 }
}
