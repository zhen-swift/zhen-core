import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

// Opt-in, like the real-store test: a live link-local neighbour to ping.
//   ZHEN_VERIFY_V6_TARGET=fe80::82f:e557:372d:c208%en0
private let liveTarget = ProcessInfo.processInfo.environment["ZHEN_VERIFY_V6_TARGET"]

@Suite("ICMPv6 echo, unprivileged")
struct ICMPv6EchoSocketTests {
    @Test("The datagram socket opens without privilege and binds to a link-local address")
    func opensUnprivileged() throws {
        let socket = try ICMPv6Socket(interface: "lo0")
        #expect(socket.local.isLinkLocal)
        #expect(socket.local.zone == "lo0")
        socket.stop()
    }

    // No loopback "answers" test, deliberately. With the application firewall in
    // stealth mode and blocking all incoming — JC's machine — nothing local answers an
    // echo: `ping6 ::1` itself loses 2 of 2. A test that needs a permissive firewall
    // would fail on the machine that matters or be skipped everywhere. The answering path
    // is proved against a real neighbour by the opt-in test below.

    @Test("An address nobody holds does not answer, and does not pretend to")
    func silenceIsNil() async throws {
        let rtt = await ICMPv6Ping.echo(IPv6Address("fe80::dead:beef:dead:beef%lo0")!,
                                        interface: "lo0", within: .milliseconds(300))
        #expect(rtt == nil)
    }

    @Test("A real link-local neighbour answers", .enabled(if: liveTarget != nil))
    func liveNeighbourAnswers() async throws {
        let text = try #require(liveTarget)
        let target = try #require(IPv6Address(text))
        let zone = try #require(target.zone, "give the target with its %interface")
        let answered = await ICMPv6Ping.echo(target, interface: zone, within: .seconds(2))
        let rtt = try #require(answered)
        print("live: \(target) answered in \(rtt)")
    }
}
