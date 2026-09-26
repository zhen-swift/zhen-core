// BPFFilter.swift — the programs the kernel runs on our behalf, written out.
//
// A BPF device with no filter copies every frame on the segment into our buffer. On an
// idle home LAN that is a few hundred frames a second of other people's traffic; on a
// busy one it is the whole sweep's budget spent parsing video. The filter is not an
// optimisation, it is the difference between reading the replies we asked for and
// reading the network.
//
// These are written as instruction arrays rather than compiled from a pcap expression
// string, because there is no `pcap_compile` without linking libpcap and the programs
// are four and eleven instructions. Each one below is the output `tcpdump -d` gives for
// the expression in its doc comment, and that is how they were checked — not by
// reasoning about them, which produced two bugs in the TCP program before the
// comparison was made.
//
// ── The one that is easy to get wrong ───────────────────────────────────────────
//
// The TCP filter cannot use a constant offset for the port. An IPv4 header is twenty
// bytes *usually* — the length is in the low nibble of byte 14, in four-byte units, and
// a packet with options is longer. `BPF_LDX|BPF_B|BPF_MSH` exists for exactly this: it
// loads that nibble, multiplies by four, and puts it in the index register, after which
// the TCP fields are addressed indirectly. A filter that assumed twenty would read the
// wrong two bytes of any packet carrying options and silently drop the reply.
#if canImport(Darwin)

import Darwin
import ZhenCore

/// A classic-BPF program, as the instruction words the kernel executes.
enum BPFFilter {
    // Opcodes, spelled out. The Darwin headers define these as bare macros that do
    // import, but writing `0x28` in an array of four-tuples is unreadable and writing
    // `BPF_LD | BPF_H | BPF_ABS` is the thing the manual says.
    private static let loadHalfwordAbsolute = UInt16(BPF_LD | BPF_H | BPF_ABS)      // 0x28
    private static let loadByteAbsolute = UInt16(BPF_LD | BPF_B | BPF_ABS)          // 0x30
    private static let loadHalfwordIndexed = UInt16(BPF_LD | BPF_H | BPF_IND)       // 0x48
    private static let loadIPHeaderLength = UInt16(BPF_LDX | BPF_B | BPF_MSH)       // 0xb1
    private static let jumpIfEqual = UInt16(BPF_JMP | BPF_JEQ | BPF_K)              // 0x15
    private static let jumpIfBitsSet = UInt16(BPF_JMP | BPF_JSET | BPF_K)           // 0x45
    private static let returnConstant = UInt16(BPF_RET | BPF_K)                     // 0x06

    /// How much of an accepted frame to copy. Larger than any frame this engine reads,
    /// so nothing it accepts is ever truncated.
    static let acceptWholeFrame: UInt32 = 262_144

    /// Offset of the ethertype in an Ethernet II header.
    static let ethertypeOffset: UInt32 = 12
    /// Offset of the IPv4 protocol byte: 14 bytes of Ethernet, then 9 into the IP header.
    private static let ipProtocolOffset: UInt32 = 23
    /// Where the IPv4 header starts, which is what `BPF_MSH` is pointed at.
    private static let ipHeaderOffset: UInt32 = 14
    /// Offset of the TCP destination port from the start of the IP header.
    private static let tcpDestinationPortOffset: UInt32 = 16
    /// Offset of the IPv4 flags-and-fragment-offset halfword: 14 + 6.
    private static let ipFragmentOffset: UInt32 = 20
    /// The fragment-offset bits of that halfword. Non-zero means this is not the first
    /// fragment, so it carries no TCP header.
    private static let fragmentOffsetMask: UInt32 = 0x1FFF

    /// `arp` — accept ARP and nothing else.
    ///
    /// **Untagged frames only.** An 802.1Q tag moves the ethertype from offset 12 to
    /// 16, so on a tagged segment this matches nothing. That is visible as a sweep that
    /// sends and hears nothing, and the engine says so rather than half-working.
    static func arp() -> [bpf_insn] {
        [
            bpf_insn(code: loadHalfwordAbsolute, jt: 0, jf: 0, k: ethertypeOffset),
            bpf_insn(code: jumpIfEqual, jt: 0, jf: 1, k: UInt32(ARPFrame.ethertype)),
            bpf_insn(code: returnConstant, jt: 0, jf: 0, k: acceptWholeFrame),
            bpf_insn(code: returnConstant, jt: 0, jf: 0, k: 0),
        ]
    }

    /// `ip and tcp and dst port N` — accept TCP segments addressed to one local port.
    ///
    /// The SYN scan sends every probe from a single source port, so this is the whole
    /// of what it needs to hear and nothing else on the segment gets copied. Matching
    /// on the port rather than on the flags is deliberate: a closed port answers with a
    /// RST and an open one with SYN-ACK, and both are evidence, so filtering on SYN
    /// would throw away half the result.
    ///
    /// This is `tcpdump -d 'ip and tcp and dst port N'` instruction for instruction,
    /// and it is written that way because the first version of it was written from
    /// first principles and was wrong twice:
    ///
    ///   * **The false branches landed on `accept`.** A `jf` is a count of instructions
    ///     to skip from the *next* one, not an index, so every frame that failed the
    ///     ethertype or protocol test fell through into the accept. The filter admitted
    ///     everything it was written to exclude.
    ///
    ///   * **There was no fragment check.** A non-first IP fragment carries no TCP
    ///     header, so the two bytes at the port's offset are payload — and reading them
    ///     yields a plausible port number rather than an error. Instructions 4 and 5
    ///     reject anything with a non-zero fragment offset.
    ///
    ///     (000) ldh      [12]
    ///     (001) jeq      #0x800           jt 2   jf 10
    ///     (002) ldb      [23]
    ///     (003) jeq      #0x6             jt 4   jf 10
    ///     (004) ldh      [20]
    ///     (005) jset     #0x1fff          jt 10  jf 6
    ///     (006) ldxb     4*([14]&0xf)
    ///     (007) ldh      [x + 16]
    ///     (008) jeq      #N               jt 9   jf 10
    ///     (009) ret      #262144
    ///     (010) ret      #0
    static func tcpDestinedTo(port: UInt16) -> [bpf_insn] {
        [
            bpf_insn(code: loadHalfwordAbsolute, jt: 0, jf: 0, k: ethertypeOffset),
            bpf_insn(code: jumpIfEqual, jt: 0, jf: 8, k: UInt32(IPv4Packet.ethertype)),
            bpf_insn(code: loadByteAbsolute, jt: 0, jf: 0, k: ipProtocolOffset),
            bpf_insn(code: jumpIfEqual, jt: 0, jf: 6, k: UInt32(IPv4Packet.protocolTCP)),
            // A non-first fragment has no TCP header. Without this the port is read out
            // of payload and the answer looks like a port number.
            bpf_insn(code: loadHalfwordAbsolute, jt: 0, jf: 0, k: ipFragmentOffset),
            bpf_insn(code: jumpIfBitsSet, jt: 4, jf: 0, k: fragmentOffsetMask),
            // The index register becomes 4 × the IPv4 header length in words, so every
            // offset after this one is relative to the start of the TCP header.
            bpf_insn(code: loadIPHeaderLength, jt: 0, jf: 0, k: ipHeaderOffset),
            bpf_insn(code: loadHalfwordIndexed, jt: 0, jf: 0, k: tcpDestinationPortOffset),
            bpf_insn(code: jumpIfEqual, jt: 0, jf: 1, k: UInt32(port)),
            bpf_insn(code: returnConstant, jt: 0, jf: 0, k: acceptWholeFrame),
            bpf_insn(code: returnConstant, jt: 0, jf: 0, k: 0),
        ]
    }
}

#endif
