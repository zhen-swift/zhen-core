// Apple-only, like the target it tests.
#if canImport(Darwin)
import Foundation
import Testing
@testable import ZhenDarwin
import ZhenCore

// Which Apple remedy a process gives is decided by whether it is an app.
@Suite("The Local Network remedy is chosen by the running bundle")
struct PermissionAdviceChoiceTests {
    @Test("An app bundle gets the in-app remedy")
    func appBundle() {
        #expect(ProbePermissionAdvice.apple(bundleURL: URL(fileURLWithPath: "/Applications/Zhen.app"),
                                                osHasLocalNetworkPrivacy: true)
                == .appleLocalNetworkInApp)
    }

    @Test("A bare executable gets the command-line remedy it has always printed")
    func commandLine() {
        #expect(ProbePermissionAdvice.apple(bundleURL: URL(fileURLWithPath: "/usr/local/bin"),
                                                osHasLocalNetworkPrivacy: true)
                == .appleLocalNetwork)
    }

    @Test("Without the permission (macOS 14), neither process is told to go and grant it")
    func noPermissionNoRemedy() {
        for path in ["/Applications/Zhen.app", "/usr/local/bin"] {
            #expect(ProbePermissionAdvice.apple(bundleURL: URL(fileURLWithPath: path),
                                                osHasLocalNetworkPrivacy: false) == .unspecified)
        }
    }

    @Test("This test process is not an app, so the sweep keeps the command-line text")
    func thisProcess() {
        let expected: ProbePermissionAdvice =
            ProbePermissionAdvice.osHasLocalNetworkPrivacy ? .appleLocalNetwork : .unspecified
        #expect(ProbePermissionAdvice.appleForThisProcess == expected)
        #expect(ICMPSweepEngine().advice == expected)
    }
}

#endif
