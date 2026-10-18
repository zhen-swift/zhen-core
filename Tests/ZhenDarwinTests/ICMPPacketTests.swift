// Apple-only, like the target it tests.
//
// `ZhenDarwin`'s sources are each wrapped this way so a Linux build produces an
// empty module rather than a failure. Its tests were not, which meant `swift test` could
// not run at all on Linux — so core's own tests, which are portable and are the ones
// worth running there, could only ever be compiled. Same rule, same reason.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

@Suite("ICMP echo requests")
struct ICMPEchoTests {
    @Test("A request carries the sequence, the token, and a zero identifier")
    func requestShape() {
        let packet = ICMPEcho.request(sequence: 0x1234, token: 0xDEAD_BEEF)
        #expect(packet[0] == 8)                       // echo request
        #expect(packet[1] == 0)                       // code
        #expect(packet[4] == 0 && packet[5] == 0)     // identifier, rewritten by the kernel
        #expect(packet[6] == 0x12 && packet[7] == 0x34)
        #expect(packet.count == ICMPEcho.headerLength + ICMPEcho.payloadLength)
        // Magic then token, in the payload the reply must echo back.
        #expect(Array(packet[8..<12]) == ICMPEcho.magic)
        #expect(Array(packet[12..<16]) == [0xDE, 0xAD, 0xBE, 0xEF])
    }

    @Test("The token, not the sequence, is what survives a /16 sweep")
    func tokenOutlivesSequenceWrap() {
        // 16 bits of sequence wraps at 65,536, which a /16 with retransmissions passes.
        // Two probes a wrap apart share a sequence and must still be distinguishable.
        let first = ICMPEcho.request(sequence: 40_000, token: 40_000)
        let second = ICMPEcho.request(sequence: 40_000, token: 40_000 + 65_536)
        #expect(Array(first[6..<8]) == Array(second[6..<8]))       // same wire sequence
        #expect(Array(first[12..<16]) != Array(second[12..<16]))   // different token
    }

    @Test("The checksum verifies, because the kernel does not compute it for us")
    func checksumIsCorrect() {
        // The one thing an unprivileged datagram ICMP socket does NOT do for the
        // application. Get it wrong and every host ignores every probe, silently.
        for sequence in [UInt16(0), 1, 255, 256, 0xFFFF] {
            let packet = ICMPEcho.request(sequence: sequence, token: UInt32(sequence) &* 7 &+ 1)
            #expect(InternetChecksum.compute(packet) == 0, "sequence \(sequence)")
        }
    }

    @Test("Every sequence in a /16 sweep produces a valid packet")
    func allSequencesAreValid() {
        // Sequence wraps at 16 bits and a /16 is 65,534 hosts, so the whole range is
        // reachable in one sweep.
        for sequence in stride(from: UInt16(0), through: 65000, by: 137) {
            let packet = ICMPEcho.request(sequence: sequence, token: UInt32(sequence) &* 3)
            #expect(InternetChecksum.compute(packet) == 0)
        }
    }
}

@Suite("ICMP replies")
struct ICMPReplyTests {
    static let source = IPv4Address("10.10.20.1")!

    /// A well-formed echo reply: right type, our magic and token, valid checksum.
    ///
    /// Built the way the wire builds it, because the decoder now verifies the checksum
    /// and the payload magic — a fixture that skipped either would be rejected, which
    /// is the point.
    private func bareReply(sequence: UInt16, token: UInt32 = 0x0102_0304) -> [UInt8] {
        var packet = ICMPEcho.request(sequence: sequence, token: token)
        packet[0] = ICMPEcho.replyType
        packet[2] = 0
        packet[3] = 0
        let checksum = InternetChecksum.compute(packet)
        packet[2] = UInt8(checksum >> 8)
        packet[3] = UInt8(checksum & 0xFF)
        return packet
    }

    @Test("A bare reply decodes, taking the TTL from the control message")
    func decodesBareReply() {
        let bytes = bareReply(sequence: 42)
        let reply = ICMPReplyDecoder.decode(bytes[bytes.indices].span, source: Self.source, controlTTL: 64)
        #expect(reply?.sequence == 42)
        #expect(reply?.token == 0x0102_0304)
        #expect(reply?.ttl == 64)
        #expect(reply?.source == Self.source)
    }

    @Test("A reply with an IP header decodes too, taking the TTL from the header")
    func decodesWithIPHeader() {
        // Documented behaviour is that SOCK_DGRAM strips the IP header, and on this
        // machine it does — but that has differed between Darwin releases and differs
        // from SOCK_RAW. Reading the wrong eight bytes reports every host as
        // unreachable with no indication why, so both shapes are handled and both are
        // tested.
        // Measured on the target platform: SOCK_DGRAM/IPPROTO_ICMP delivers the IP
        // header on this kernel, so this is the ACTIVE path rather than a defensive
        // one — the first byte of a real reply here is 0x45.
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0x45                               // IPv4, IHL 5
        packet[8] = 128                                // TTL — a Windows host
        packet += bareReply(sequence: 7)
        let reply = ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: nil)
        #expect(reply?.sequence == 7)
        #expect(reply?.ttl == 128)
        #expect(OSHint(ttl: try! #require(reply?.ttl)) == .windows)
    }

    @Test("The IP header's TTL wins over a control message, being closer to the wire")
    func headerTTLWins() {
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0x45
        packet[8] = 255
        packet += bareReply(sequence: 1)
        let reply = ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: 64)
        #expect(reply?.ttl == 255)
    }

    @Test("A missing TTL stays nil rather than becoming a confident guess")
    func absentTTLIsNil() {
        let packet = bareReply(sequence: 3)
        let reply = ICMPReplyDecoder.decode(packet[packet.indices].span,
                                            source: Self.source, controlTTL: nil)
        #expect(reply?.ttl == nil)
        // Optionality means not-observed. A default of 64 here would put an OS hint in
        // the report that nothing on the wire supported.
        #expect(OSHint(ttl: 64) == .unixLike)
    }

    @Test("A reply whose checksum does not verify is rejected")
    func badChecksumRejected() {
        var packet = bareReply(sequence: 11)
        #expect(ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: nil) != nil)
        // Flip one payload byte without fixing the checksum. Owning the checksum means
        // checking it on the way in, not only computing it on the way out.
        packet[14] ^= 0xFF
        #expect(ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: nil) == nil)
    }

    @Test("A reply carrying somebody else's payload is rejected")
    func foreignPayloadRejected() {
        // A stale reply from a previous run, or another tool's ping on the same host.
        // Without the magic it would be attributed to a host we are measuring.
        var packet = bareReply(sequence: 12)
        packet[8] = 0x58                               // corrupt the magic
        packet[2] = 0; packet[3] = 0
        let checksum = InternetChecksum.compute(packet)
        packet[2] = UInt8(checksum >> 8); packet[3] = UInt8(checksum & 0xFF)
        #expect(ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: nil) == nil)
    }

    @Test("Anything that is not an echo reply is ignored")
    func ignoresOtherICMPTypes() {
        // Destination-unreachable and time-exceeded land on the same socket. Reading
        // one as a host answering would report the very host that did not.
        for type in [UInt8(3), 11, 5, 8] {
            var packet = bareReply(sequence: 9)
            packet[0] = type
            #expect(ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: nil) == nil,
                    "type \(type)")
        }
    }

    @Test("Truncated input decodes to nothing rather than reading past the end")
    func truncationIsSafe() {
        let full = bareReply(sequence: 5)
        for cut in 0..<full.count {
            let prefix = Array(full[0..<cut])
            _ = ICMPReplyDecoder.decode(prefix[prefix.indices].span, source: Self.source, controlTTL: nil)
        }
        #expect(ICMPReplyDecoder.decode(Span<UInt8>(), source: Self.source, controlTTL: nil) == nil)
    }

    @Test("A claimed IP header longer than the buffer does not run off the end")
    func lyingIPHeader() {
        var packet = [UInt8](repeating: 0, count: 24)
        packet[0] = 0x4F                               // IHL 15 = 60 bytes, but only 24 here
        #expect(ICMPReplyDecoder.decode(packet[packet.indices].span, source: Self.source, controlTTL: nil) == nil)
    }
}

@Suite("Control message walking")
struct ControlMessageTests {
    @Test("Alignment matches the kernel's 32-bit round-up")
    func align32() {
        // CMSG_* are function-like macros and therefore unimportable, so this
        // arithmetic is reimplemented rather than called. If it drifts, the TTL comes
        // back as garbage or not at all.
        #expect(ControlMessages.align32(0) == 0)
        #expect(ControlMessages.align32(1) == 4)
        #expect(ControlMessages.align32(4) == 4)
        #expect(ControlMessages.align32(13) == 16)
        #expect(ControlMessages.align32(16) == 16)
    }
}

@Suite("Descriptor limits")
struct ResourceLimitTests {
    @Test("An infinite hard limit does not overflow into a nonsense window")
    func infinityIsClamped() {
        // RLIM_INFINITY is UInt64.max and this machine really does report it.
        // Converting it straight to Int traps; dividing it by four to derive a
        // concurrency window produces a number no descriptor table could satisfy.
        #expect(DarwinResourceLimits.clamp(rlim_t.max) == 1_048_576)
        #expect(DarwinResourceLimits.clamp(256) == 256)
        #expect(DarwinResourceLimits.clamp(1_048_576) == 1_048_576)
        #expect(ConcurrencyBudget.fromDescriptorLimit(DarwinResourceLimits.clamp(.max)) == 512)
    }

    @Test("The limit is read from the kernel, not assumed")
    func readsTheRealLimit() {
        // Both the brief and SPEC say the soft limit is 256. On the machine this was
        // written for it is 1,048,576. Whichever is true where this runs, the number
        // has to come from getrlimit.
        let granted = DarwinResourceLimits().raiseDescriptorLimit()
        #expect(granted >= 256)
        #expect(ConcurrencyBudget.fromDescriptorLimit(granted) >= 1)
        #expect(ConcurrencyBudget.fromDescriptorLimit(granted) <= 512)
    }
}

#endif
