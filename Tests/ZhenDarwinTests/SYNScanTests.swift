// SYNScanTests.swift — the parts of a half-open scan that can be checked without root.
//
// A malformed SYN is not rejected, it is ignored: a bad checksum, a wrong total length
// or a missing pseudo-header all produce a segment every stack silently discards, which
// presents as a scan where every port is filtered. That is indistinguishable from a
// firewall, so nothing fails and the wrong answer looks like a real one. These are the
// tests that stop that.
//
// The expected bytes below are written out from RFC 791 and RFC 793 rather than
// produced by calling the builder. A test that asks the builder what it built checks
// nothing, which is the same trap the BPF header-length bug went through last week.
// macOS only, like the sources it tests (see their guards): iPadOS has none of them.
#if os(macOS)

import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

@Suite("A SYN is built to the letter, or it is silently discarded")
struct SYNFrameTests {
    static let ourMAC = MACAddress(raw: 0x0A_1B_2C_3D_4E_5F)
    static let theirMAC = MACAddress(raw: 0xAA_BB_CC_DD_EE_01)
    static let ourIP = IPv4Address("10.10.20.131")!
    static let target = IPv4Address("10.10.20.7")!

    static func frame(port: UInt16 = 443, sourcePort: UInt16 = 45_000, id: UInt16 = 0x1234) -> [UInt8] {
        IPv4Packet.syn(
            target: target, targetMAC: theirMAC, port: port,
            senderMAC: ourMAC, senderIP: ourIP,
            sourcePort: sourcePort, identifier: id
        )
    }

    @Test("The Ethernet and IPv4 headers match the RFC field for field")
    func headerBytes() {
        let frame = Self.frame()
        #expect(frame.count == 54)   // 14 Ethernet + 20 IP + 20 TCP

        // Ethernet: unicast to the target's hardware address, not broadcast. A SYN
        // broadcast to ff:ff:ff:ff:ff:ff would be put in front of every host on the
        // segment by the switch.
        #expect(Array(frame[0..<6]) == [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01])
        #expect(Array(frame[6..<12]) == [0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F])
        #expect(Array(frame[12..<14]) == [0x08, 0x00])   // ethertype IPv4

        #expect(frame[14] == 0x45)                        // version 4, 5-word header
        #expect(Array(frame[16..<18]) == [0x00, 0x28])    // total length 40, NOT 54
        #expect(Array(frame[18..<20]) == [0x12, 0x34])    // identification
        #expect(Array(frame[20..<22]) == [0x40, 0x00])    // Don't Fragment
        #expect(frame[22] == 64)                          // TTL
        #expect(frame[23] == 6)                           // protocol TCP
        #expect(Array(frame[26..<30]) == [10, 10, 20, 131])  // source
        #expect(Array(frame[30..<34]) == [10, 10, 20, 7])    // destination
    }

    @Test("The IPv4 total length covers IP and TCP and excludes the Ethernet header")
    func totalLengthExcludesEthernet() {
        // Counting the Ethernet header into `total length` is the classic off-by-14:
        // the receiving stack then reads fourteen bytes past the segment, which on a
        // padded frame is trailing zeros and produces a checksum failure rather than a
        // crash — so it fails silently, on every probe, and every port reads filtered.
        let frame = Self.frame()
        let total = UInt16(frame[16]) << 8 | UInt16(frame[17])
        #expect(Int(total) == IPv4Packet.ipHeaderLength + IPv4Packet.tcpHeaderLength)
        #expect(Int(total) == frame.count - IPv4Packet.ethernetHeaderLength)
    }

    @Test("The TCP header carries exactly SYN, and a window a stack will honour")
    func tcpHeaderBytes() {
        let frame = Self.frame(port: 443, sourcePort: 45_000)
        let tcp = 34
        #expect(Array(frame[tcp..<(tcp + 2)]) == [0xAF, 0xC8])    // source port 45000
        #expect(Array(frame[(tcp + 2)..<(tcp + 4)]) == [0x01, 0xBB])  // dest port 443
        #expect(Array(frame[(tcp + 8)..<(tcp + 12)]) == [0, 0, 0, 0]) // ack is zero
        #expect(frame[tcp + 12] == 0x50)                          // 5 words, no options
        #expect(frame[tcp + 13] == 0x02)                          // SYN alone
        #expect(Array(frame[(tcp + 14)..<(tcp + 16)]) == [0xFF, 0xFF])
        #expect(Array(frame[(tcp + 18)..<(tcp + 20)]) == [0, 0])  // urgent pointer
    }

    @Test("Both checksums verify, which is the only reason the far side answers")
    func checksumsVerify() {
        // A checksum verifies when the sum over the region, INCLUDING the checksum
        // field as written, folds to zero. Recomputing it and comparing would only
        // prove the function agrees with itself.
        let frame = Self.frame()
        let ip = Array(frame[14..<34])
        #expect(InternetChecksum.compute(ip) == 0, "the IPv4 header checksum does not verify")

        let pseudoAndSegment = IPv4Packet.tcpChecksum(
            frame: frame, tcpOffset: 34, tcpLength: 20,
            source: Self.ourIP, destination: Self.target
        )
        // `tcpChecksum` sums the pseudo-header plus the segment. Run over a frame whose
        // checksum field is already filled, that sum must fold to zero too.
        #expect(pseudoAndSegment == 0, "the TCP checksum does not verify over the pseudo-header")
    }

    @Test("The TCP checksum covers the pseudo-header, so a stack does not discard it")
    func checksumIncludesPseudoHeader() {
        // The pseudo-header is not transmitted; it exists so a segment delivered to the
        // wrong host fails its checksum instead of being accepted. Omitting it is the
        // single most common way a hand-built SYN goes unanswered, and the symptom is
        // every port reporting filtered — which looks exactly like a firewall.
        var frame = Self.frame()
        let withPseudo = UInt16(frame[50]) << 8 | UInt16(frame[51])
        frame[50] = 0; frame[51] = 0
        let segmentOnly = InternetChecksum.compute(Array(frame[34..<54]))
        #expect(withPseudo != segmentOnly,
                "the checksum is the same with and without the pseudo-header, so it cannot include one")
    }

    @Test("Varying any field the cookie covers changes the sequence number")
    func cookieDiscriminates() {
        let a = IPv4Packet.cookie(target: Self.target, port: 22)
        let b = IPv4Packet.cookie(target: Self.target, port: 443)
        let c = IPv4Packet.cookie(target: IPv4Address("10.10.20.8")!, port: 22)
        #expect(a != b)
        #expect(a != c)
        // Deterministic, because that is what lets a reply be matched with no table.
        #expect(a == IPv4Packet.cookie(target: Self.target, port: 22))
        // Never zero: a zero sequence makes `ack == 1`, which is also what a stack
        // answering a probe we did not send produces.
        #expect(a != 0 && b != 0 && c != 0)
    }

    @Test("The salt is what stops two scans sending identical sequence numbers")
    func saltSeparatesScans() {
        // Found in a capture, not in a test: two privileged runs minutes apart sent
        // byte-identical sequences to every port, because the cookie was a pure
        // function of the target and the port. A reply arriving late from the first run
        // would then match a probe in the second and decide a port that never answered.
        let unsalted = IPv4Packet.cookie(target: Self.target, port: 443)
        let salted = IPv4Packet.cookie(target: Self.target, port: 443, salt: 0xDEAD_BEEF)
        #expect(unsalted != salted)

        // Still deterministic *within* a scan, which is the whole matching mechanism:
        // the reply names its own probe and no per-probe table is kept.
        #expect(salted == IPv4Packet.cookie(target: Self.target, port: 443, salt: 0xDEAD_BEEF))

        // And the frame carries it, so the salt reaches the wire rather than only the
        // bookkeeping.
        let frame = IPv4Packet.syn(
            target: Self.target, targetMAC: Self.theirMAC, port: 443,
            senderMAC: Self.ourMAC, senderIP: Self.ourIP,
            sourcePort: 45_000, identifier: 1, salt: 0xDEAD_BEEF
        )
        var sequence: UInt32 = 0
        for index in 38..<42 { sequence = (sequence << 8) | UInt32(frame[index]) }
        #expect(sequence == salted)
    }
}

@Suite("Reading the answer to a SYN")
struct SYNReplyTests {
    static func reply(
        from source: IPv4Address, sourcePort: UInt16, to destinationPort: UInt16,
        ack: UInt32, flags: UInt8, headerWords: UInt8 = 5
    ) -> [UInt8] {
        let headerLength = Int(headerWords) * 4
        var frame = [UInt8](repeating: 0, count: 14 + headerLength + 20)
        frame[12] = 0x08; frame[13] = 0x00
        frame[14] = 0x40 | headerWords
        frame[23] = 6
        let octets = source.octets
        frame[26] = octets.0; frame[27] = octets.1; frame[28] = octets.2; frame[29] = octets.3
        let tcp = 14 + headerLength
        frame[tcp] = UInt8(sourcePort >> 8); frame[tcp + 1] = UInt8(sourcePort & 0xFF)
        frame[tcp + 2] = UInt8(destinationPort >> 8); frame[tcp + 3] = UInt8(destinationPort & 0xFF)
        for index in 0..<4 { frame[tcp + 8 + index] = UInt8(truncatingIfNeeded: ack >> (24 - 8 * index)) }
        frame[tcp + 12] = headerWords << 4
        frame[tcp + 13] = flags
        return frame
    }

    @Test("SYN-ACK is open, RST is closed, and the two are never collapsed")
    func verdicts() throws {
        let host = IPv4Address("10.10.20.7")!
        let synAck = Self.reply(from: host, sourcePort: 443, to: 45_000, ack: 99, flags: 0x12)
        let reset = Self.reply(from: host, sourcePort: 22, to: 45_000, ack: 99, flags: 0x14)

        // Bound before the macro: `#require` captures its argument expression and a
        // `Span` is non-escapable, so the parse lands in an ordinary optional first.
        let openParse = IPv4Packet.parse(synAck[synAck.indices].span)
        let open = try #require(openParse)
        #expect(open.isSynAck)
        #expect(!open.isReset)
        #expect(open.sourcePort == 443)

        let closedParse = IPv4Packet.parse(reset[reset.indices].span)
        let closed = try #require(closedParse)
        #expect(closed.isReset)
        #expect(!closed.isSynAck)
        // A RST means the host is THERE and said no. Positive information, and strictly
        // more than silence — collapsing it into "not open" throws away the only signal
        // separating a live host behind a firewall from a dead address.
    }

    @Test("The IPv4 header length is read, not assumed, so a packet with options parses")
    func honoursHeaderLength() throws {
        // A stack that sets a timestamp or a record-route option answers with a header
        // longer than twenty bytes, and every TCP field moves with it. Reading them at
        // a fixed offset yields a port number out of the middle of an option — which is
        // a plausible-looking number, not an error.
        let host = IPv4Address("10.10.20.9")!
        let withOptions = Self.reply(
            from: host, sourcePort: 8080, to: 45_000, ack: 1234, flags: 0x12, headerWords: 7
        )
        let parsed = IPv4Packet.parse(withOptions[withOptions.indices].span)
        let segment = try #require(parsed)
        #expect(segment.sourcePort == 8080)
        #expect(segment.destinationPort == 45_000)
        #expect(segment.acknowledgement == 1234)
        #expect(segment.isSynAck)
    }

    @Test("Anything that is not IPv4 TCP is refused")
    func refusesForeignFrames() {
        func refuses(_ bytes: [UInt8]) -> Bool { IPv4Packet.parse(bytes[bytes.indices].span) == nil }
        let host = IPv4Address("10.10.20.7")!
        var frame = Self.reply(from: host, sourcePort: 443, to: 45_000, ack: 9, flags: 0x12)

        var notIP = frame
        notIP[12] = 0x08; notIP[13] = 0x06       // ARP
        #expect(refuses(notIP))

        var notTCP = frame
        notTCP[23] = 17                          // UDP
        #expect(refuses(notTCP))

        var badVersion = frame
        badVersion[14] = 0x65                    // version 6 in an IPv4 ethertype
        #expect(refuses(badVersion))

        var shortHeader = frame
        shortHeader[14] = 0x44                   // 4 words: impossible
        #expect(refuses(shortHeader))

        frame.removeLast(4)                      // truncated before the TCP header ends
        #expect(refuses(frame))
    }

    @Test("A reply only decides the probe it actually answers")
    func matchingIsByCookieAndSource() async {
        // The acknowledgement recovers the cookie and the cookie names the probe, but a
        // 32-bit hash over a larger space can collide — so the source address and port
        // are checked too. Without that, a segment from an unrelated host whose ack
        // happened to collide would decide a port on a host it has nothing to do with.
        let host = IPv4Address("10.10.20.7")!
        let impostor = IPv4Address("10.10.20.8")!
        let state = SYNScanState(
            targets: [host], ports: [443], attempts: 2,
            counters: ProbeCounters(), budgets: .split
        )
        let now = MonotonicInstant.now
        await state.recordSends([SYNProbe(ip: host, port: 443)], at: now)

        let cookie = IPv4Packet.cookie(target: host, port: 443)
        // Right cookie, wrong sender.
        await state.record(IPv4Packet.Segment(
            source: impostor, sourcePort: 443, destinationPort: 45_000,
            acknowledgement: cookie &+ 1, flags: [.syn, .ack]
        ), at: now)
        var verdicts = await state.observations()
        #expect(verdicts[host]?.first?.state == nil || verdicts[host]?.first?.state == .filtered,
                "a reply from another host decided a port")

        // Right cookie, wrong source port — the reply must come from the port probed.
        await state.record(IPv4Packet.Segment(
            source: host, sourcePort: 80, destinationPort: 45_000,
            acknowledgement: cookie &+ 1, flags: [.syn, .ack]
        ), at: now)
        verdicts = await state.observations()
        #expect(verdicts[host]?.first?.state != .open, "a reply from another port decided this one")

        // And the genuine article.
        await state.record(IPv4Packet.Segment(
            source: host, sourcePort: 443, destinationPort: 45_000,
            acknowledgement: cookie &+ 1, flags: [.syn, .ack]
        ), at: now)
        verdicts = await state.observations()
        #expect(verdicts[host]?.first?.state == .open)
    }

    @Test("A probe that was never sent has no verdict, and one that was has filtered")
    func silenceAndAbsenceAreDifferent() async {
        // "Not asked" and "asked and heard nothing" are different facts and only one of
        // them is evidence about the port. Reporting the first as `.filtered` would put
        // a positive claim in the artifact that nothing supports.
        let host = IPv4Address("10.10.20.7")!
        let state = SYNScanState(
            targets: [host], ports: [22, 80], attempts: 1,
            counters: ProbeCounters(), budgets: .split
        )
        await state.recordSends([SYNProbe(ip: host, port: 22)], at: .now)
        let verdicts = await state.observations()
        #expect(verdicts[host]?.count == 1)
        #expect(verdicts[host]?.first?.port == 22)
        #expect(verdicts[host]?.first?.state == .filtered)
    }
}

@Suite("The kernel filter accepts what the engine needs and nothing else")
struct BPFFilterTests {
    @Test("The ARP program is the four instructions tcpdump emits for `arp`")
    func arpProgram() {
        let program = BPFFilter.arp()
        #expect(program.count == 4)
        #expect(program[0].code == UInt16(BPF_LD | BPF_H | BPF_ABS))
        #expect(program[0].k == 12)                       // the ethertype
        #expect(program[1].code == UInt16(BPF_JMP | BPF_JEQ | BPF_K))
        #expect(program[1].k == 0x0806)
        #expect(program[2].k == BPFFilter.acceptWholeFrame)
        #expect(program[3].k == 0)                        // reject
    }

    @Test("The TCP program matches tcpdump's, including the two things reasoning missed")
    func tcpProgramIsIndexed() {
        let program = BPFFilter.tcpDestinedTo(port: 45_000)
        #expect(program.count == 11)
        #expect(program[1].k == 0x0800)                   // IPv4
        #expect(program[3].k == 6)                        // TCP

        // A non-first IP fragment carries no TCP header, so the bytes at the port's
        // offset are payload — and a payload byte pair is a plausible port number, not
        // an error. The first version of this filter had no fragment check at all.
        #expect(program[4].code == UInt16(BPF_LD | BPF_H | BPF_ABS))
        #expect(program[4].k == 20)                       // flags + fragment offset
        #expect(program[5].code == UInt16(BPF_JMP | BPF_JSET | BPF_K))
        #expect(program[5].k == 0x1FFF)

        // BPF_MSH is the other thing a constant offset gets wrong: it loads the low
        // nibble of byte 14, multiplies by four and puts it in the index register.
        // Without it every reply carrying IP options is dropped.
        #expect(program[6].code == UInt16(BPF_LDX | BPF_B | BPF_MSH))
        #expect(program[6].k == 14)
        #expect(program[7].code == UInt16(BPF_LD | BPF_H | BPF_IND))
        #expect(program[7].k == 16)                       // dest port, from the TCP header
        #expect(program[8].k == 45_000)
        #expect(program[9].k == BPFFilter.acceptWholeFrame)
        #expect(program[10].k == 0)
    }

    @Test("Every branch that should reject lands on the reject, not on the accept")
    func branchesLandOnReject() {
        // The bug this test was written for and immediately found: a `jf` is a count of
        // instructions to skip from the NEXT one, not an index. The first version used
        // indices, so every frame that failed the ethertype or protocol test fell
        // through into `ret #262144` — the filter admitted precisely what it existed to
        // exclude, and on a quiet segment that is invisible.
        let program = BPFFilter.tcpDestinedTo(port: 45_000)
        let reject = program.count - 1
        // A false branch from a `jeq` means "did not match", which must reject.
        #expect(1 + 1 + Int(program[1].jf) == reject, "ethertype mismatch does not reject")
        #expect(3 + 1 + Int(program[3].jf) == reject, "protocol mismatch does not reject")
        #expect(8 + 1 + Int(program[8].jf) == reject, "port mismatch does not reject")
        // `jset` is the other way round: the TRUE branch means "fragment bits set".
        #expect(5 + 1 + Int(program[5].jt) == reject, "a later fragment does not reject")

        let arp = BPFFilter.arp()
        #expect(1 + 1 + Int(arp[1].jf) == arp.count - 1, "a non-ARP frame does not reject")
    }
}

#endif
