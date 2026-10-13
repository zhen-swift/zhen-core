import Testing
@testable import ZhenCore

// A reply captured off JC's network on 2026-09-26: the Apple TV at
// fe80::82f:e557:372d:c208 (MAC c8:69:cd:7f:33:e1) answering an echo request from this
// Mac's en0 link-local address. Its checksum was computed by the Apple TV's stack, not by
// anything in this repository, which is what makes it a test of the pseudo-header rather
// than of this code agreeing with itself. 21 bytes, so the odd-length padding rule is in
// play as well.
private let capturedReply: [UInt8] = hex("8100308a7a6800017a68656e2d64312d70726f6265")
private let appleTV = IPv6Address("fe80::82f:e557:372d:c208")!
private let thisMac = IPv6Address("fe80::10fe:8abd:76f3:5a11")!

private func hex(_ text: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        bytes.append(UInt8(text[index..<next], radix: 16)!)
        index = next
    }
    return bytes
}

@Suite("ICMPv6's checksum covers a pseudo-header, and a real packet says so")
struct ICMPv6ChecksumTests {
    @Test("The captured reply verifies over its pseudo-header")
    func capturedReplyVerifies() {
        #expect(ICMPv6Echo.verifies(capturedReply, source: appleTV, destination: thisMac))
    }

    @Test("Recomputing it gives the other stack's exact value")
    func recomputesTheSameValue() {
        var zeroed = capturedReply
        zeroed[2] = 0; zeroed[3] = 0
        #expect(ICMPv6Echo.checksum(zeroed, source: appleTV, destination: thisMac) == 0x308A)
    }

    @Test("The ICMPv4 computation, with no pseudo-header, gets it wrong")
    func v4StyleIsWrong() {
        var zeroed = capturedReply
        zeroed[2] = 0; zeroed[3] = 0
        #expect(InternetChecksum.compute(zeroed) != 0x308A)
        let v4Verifies = InternetChecksum.verifies(capturedReply.span)
        #expect(!v4Verifies)
    }

    @Test("The addresses are part of it, though not their order")
    func addressesMatter() {
        // Swapping source and destination does NOT fail: one's-complement addition is
        // commutative, so the pseudo-header sums the same either way. Stated so nobody
        // mistakes this for a check of direction.
        #expect(ICMPv6Echo.verifies(capturedReply, source: thisMac, destination: appleTV))
        let stranger = IPv6Address("fe80::1")!
        #expect(!ICMPv6Echo.verifies(capturedReply, source: stranger, destination: thisMac))
    }

    @Test("A request we build verifies, and decodes as ours once turned into a reply")
    func requestRoundTrip() throws {
        let request = ICMPv6Echo.request(sequence: 7, token: 0xDEADBEEF, source: thisMac, destination: appleTV)
        #expect(request[0] == ICMPv6Echo.requestType)
        #expect(ICMPv6Echo.verifies(request, source: thisMac, destination: appleTV))
        #expect(ICMPv6Echo.decodeReply(request) == nil, "a request is not a reply")
        var reply = request
        reply[0] = ICMPv6Echo.replyType
        let decoded = try #require(ICMPv6Echo.decodeReply(reply))
        #expect(decoded.sequence == 7 && decoded.token == 0xDEADBEEF)
        // The captured reply is somebody's echo but not ours — no magic — and is refused.
        #expect(ICMPv6Echo.decodeReply(capturedReply) == nil)
    }
}
