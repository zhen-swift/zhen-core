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
        #expect(ProbePermissionAdvice.apple(bundleURL: URL(fileURLWithPath: "/Applications/Zhen.app"))
                == .appleLocalNetworkInApp)
    }

    @Test("A bare executable gets the command-line remedy it has always printed")
    func commandLine() {
        #expect(ProbePermissionAdvice.apple(bundleURL: URL(fileURLWithPath: "/usr/local/bin"))
                == .appleLocalNetwork)
    }

    @Test("This test process is not an app, so the sweep keeps the command-line text")
    func thisProcess() {
        #expect(ProbePermissionAdvice.appleForThisProcess == .appleLocalNetwork)
        #expect(ICMPSweepEngine().advice == .appleLocalNetwork)
    }
}

#endif
