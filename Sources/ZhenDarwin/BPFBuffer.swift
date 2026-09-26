// BPFBuffer.swift — walking the records a single BPF read returns.
//
// **One `read` returns many packets.** This is the thing about BPF that is easiest to
// get subtly wrong, because getting it wrong does not produce an error: the buffer is a
// run of records, each one a `struct bpf_hdr` followed by that packet's captured bytes,
// and each record starts at a `BPF_WORDALIGN` boundary. Advance by
// `bh_hdrlen + bh_caplen` without rounding and the cursor lands one to three bytes
// early; every subsequent header is then read out of the middle of the previous packet,
// and what comes back is a stream of plausible garbage — ARP replies from addresses
// that do not exist, with hardware addresses assembled out of somebody's payload.
//
// It is the same shape of hazard `RouteMessages.swift` handles for the routing socket:
// packed, variable-length, kernel-filled records that a struct cast would read as
// aligned. It is handled the same way — explicit byte offsets over a bounds-checked
// span, one parser, one file, exercised against a recorded buffer rather than a
// hand-built one.
//
// Two differences from that parser, both deliberate:
//
//   * The offsets are not written down here. `bh_caplen` and friends are located by
//     `offsetof` in `CBPFShim`, so the walk reads what the SDK says rather than what a
//     comment remembers. Measured on macOS 26.5 they are 8, 12 and 16 in a 20-byte
//     header; a future SDK that moves one moves this with it.
//
//   * `bh_hdrlen` is used for the step to the packet, and is NOT compared against
//     `sizeof(struct bpf_hdr)`. Those two are different numbers on this platform and
//     assuming otherwise is a bug that shipped: the struct pads to 20, its fields end
//     at 18, and the kernel writes 18. An earlier version of this file required
//     `bh_hdrlen >= sizeof(struct bpf_hdr)` and so rejected the first record of every
//     read — the sweep sent 759 ARP requests, nine hosts answered, and it reported an
//     empty segment. Nothing threw; a segment with nothing on it produces exactly the
//     same output. It was found by capturing beside a live run, which is the only thing
//     that could have found it.
//
// The header's integers are NATIVE order, not wire order — they were written by the
// kernel for this machine, not sent by a peer. That is the opposite of `ARPFrame`,
// which combines its bytes big-endian because they came off a wire, and the two must
// not be copied into each other.
#if canImport(Darwin)

import CBPFShim
import Darwin
import ZhenCore

/// The records in one BPF read.
enum BPFBuffer {
    /// Where one captured packet sits inside the buffer.
    struct Record: Sendable, Hashable {
        /// The captured bytes, as a range into the buffer that produced them.
        var packet: Range<Int>
        /// How long the packet was on the wire. Larger than `packet.count` when the
        /// snap length cut it short.
        var wireLength: Int
        /// The kernel's capture timestamp, seconds since the epoch. Carried because it
        /// is free and a capture without one is harder to argue with; nothing in the
        /// sweep's timing reads it, which is deliberate — see `BPFSweep.swift` on why
        /// an ARP reply is not timed.
        var timestampSeconds: Int64

        /// Whether the snap length truncated this packet.
        var isTruncated: Bool { wireLength > packet.count }
    }

    /// The smallest a record's header may be: the end of the last field it carries.
    ///
    /// Eighteen on macOS 26.5, against a `sizeof(struct bpf_hdr)` of twenty. Using the
    /// struct size here is the bug described at the top of this file.
    static let minimumHeaderLength = Int(ns_bpf_hdr_min_length())
    /// `sizeof(struct bpf_hdr)`, which is the padded C type and **not** the length of
    /// a record's header. Exposed so a test can pin the difference between the two.
    static let structSize = Int(ns_bpf_hdr_size())
    private static let capturedOffset = Int(ns_bpf_hdr_off_caplen())
    private static let wireOffset = Int(ns_bpf_hdr_off_datalen())
    private static let headerLengthOffset = Int(ns_bpf_hdr_off_hdrlen())
    private static let timestampOffset = Int(ns_bpf_hdr_off_tstamp_sec())

    /// Every complete record in `bytes`, in the order the kernel wrote them.
    ///
    /// **Truncation ends the walk rather than failing it.** A read returns whole
    /// records, but a caller that hands over a short buffer — a partial read, a fixture
    /// cut on purpose, a device that returned fewer bytes than a record needs — gets
    /// back what parsed cleanly. That is the same rule `RouteMessageParser.parse` uses
    /// and for the same reason: the records before the damage are real observations and
    /// discarding them would lose live hosts to a byte count.
    ///
    /// A record whose header is impossible — a `bh_hdrlen` smaller than a header can
    /// be, or an advance of zero — stops the walk too. The cursor cannot be trusted
    /// past it and continuing would manufacture packets.
    static func records(in bytes: Span<UInt8>) -> [Record] {
        var found: [Record] = []
        var offset = 0
        while offset + minimumHeaderLength <= bytes.count {
            let captured = Int(hostU32(bytes, offset + capturedOffset))
            let wire = Int(hostU32(bytes, offset + wireOffset))
            let headerLength = Int(hostU16(bytes, offset + headerLengthOffset))

            // A header too short to hold its own fields means the cursor is no longer
            // on a record boundary. Nothing after it can be read.
            guard headerLength >= minimumHeaderLength else { break }
            let packetStart = offset + headerLength
            guard packetStart >= offset, captured >= 0 else { break }
            // The last record of a short read: the header is there and its packet is
            // not. Stop; everything before it stands.
            guard packetStart <= bytes.count, captured <= bytes.count - packetStart else {
                break
            }

            found.append(Record(
                packet: packetStart..<(packetStart + captured),
                wireLength: wire,
                timestampSeconds: Int64(hostU32(bytes, offset + timestampOffset))
            ))

            let step = Int(ns_bpf_wordalign(UInt(headerLength + captured)))
            // Zero would loop forever, and a step that does not clear the header we
            // just read means the alignment arithmetic disagrees with the kernel's.
            guard step >= headerLength, step > 0 else { break }
            offset += step
        }
        return found
    }

    // MARK: - Native-order scalars
    //
    // Assembled rather than loaded, so no `unsafe` marker is needed and no alignment
    // is assumed — the same trade `InternetChecksum.swift` documents. The order is
    // decided once, from the machine, rather than asserted in a comment: Darwin ships
    // only on little-endian architectures today, and a check that costs one predictable
    // branch is cheaper than a caveat that would be wrong somewhere nobody tested.

    private static let isLittleEndian = (1 as UInt32).littleEndian == 1

    private static func hostU32(_ bytes: Span<UInt8>, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= bytes.count else { return 0 }
        var value: UInt32 = 0
        if isLittleEndian {
            for index in stride(from: 3, through: 0, by: -1) {
                value = (value << 8) | UInt32(bytes[offset + index])
            }
        } else {
            for index in 0..<4 { value = (value << 8) | UInt32(bytes[offset + index]) }
        }
        return value
    }

    private static func hostU16(_ bytes: Span<UInt8>, _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= bytes.count else { return 0 }
        return isLittleEndian
            ? UInt16(bytes[offset + 1]) << 8 | UInt16(bytes[offset])
            : UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
}

#endif
