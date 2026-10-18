// InternetChecksum.swift — the one's-complement sum, and why it is ours to compute.
//
// macOS gives an unprivileged process `SOCK_DGRAM`/`IPPROTO_ICMP`, which is the entire
// reason host discovery here needs no root — a real advantage over nmap on this
// platform. The kernel rewrites the identifier field on the way out, but it does NOT
// compute the checksum. The application does.
//
// The bypass considered and rejected: use a raw socket and let the kernel do it. That
// needs root, which forfeits the unprivileged default that makes this tool pleasant to
// use. Computing sixteen-bit sums is cheaper than asking a user for a password.
//
// This is a per-probe cost paid up to 25,000 times, so the accumulation is in a
// `UInt32` with a single fold at the end rather than a fold per word.
//
// ── Why Span<UInt8> and not RawSpan ──────────────────────────────────────────────
//
// The brief calls for `RawSpan` on anything touching wire bytes, for the right reason:
// a borrowed, bounds-checked, zero-copy view that cannot outlive its buffer, which is
// what lets a received packet pass through the layers without a copy. But `RawSpan`'s
// only load operation is `unsafeLoadUnaligned(fromByteOffset:as:)`, and it is `@unsafe`
// because it will happily reinterpret arbitrary bytes as any type, including ones with
// invalid bit patterns. Under `.strictMemorySafety()` that requires an `unsafe` marker,
// and this package's acceptance criterion is no `unsafe` in core at all.
//
// `Span<UInt8>` gives the same borrowed zero-copy view with a bounds-checked subscript
// that is safe, so nothing here needs a marker. (An array's span is spelled
// `bytes[bytes.indices].span` everywhere in this package. `Array.span` is macOS 26+,
// while `ArraySlice.span` is back-deployed, and the floor is 14 — see Package.swift.
// Through the slice it is the same borrowed view and no copy.) Two bytes are combined explicitly
// rather than loaded as a `UInt16`, which is also the more honest code: wire data is
// unaligned and big-endian, and `loadUnaligned(as: UInt16.self)` on a little-endian
// machine gets the byte order wrong in a way that happens not to matter for a
// one's-complement sum and would matter for anything else. Writing the combination out
// means the next parser copied from this file starts correct.
//
// A platform target holding a received datagram can produce a `Span<UInt8>` exactly as
// cheaply as a `RawSpan`, so nothing is given up.

/// The internet checksum (RFC 1071).
public enum InternetChecksum {
    /// Computes the one's-complement sum of 16-bit words with carries folded back in.
    ///
    /// Byte pairs are combined big-endian. The result is byte-order independent by
    /// construction — swapping the two bytes of every word swaps the two bytes of the
    /// sum — but being explicit costs nothing and removes a question.
    ///
    /// An odd trailing byte is padded on the right with zero, per RFC 1071. Getting
    /// this wrong produces a checksum that is correct for every even-length packet and
    /// wrong for every odd-length one, which is the kind of bug that survives a test
    /// suite built only from realistic ICMP echo headers.
    ///
    /// - Parameter bytes: the buffer to sum, with its checksum field already zeroed.
    /// - Returns: the value to write into the checksum field, in host order.
    public static func compute(_ bytes: Span<UInt8>) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum &+= UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count {
            // Odd tail: the final byte is the HIGH byte of a word padded with zero.
            sum &+= UInt32(bytes[index]) << 8
        }
        // Fold the carries. Twice is enough for any input: the first fold can itself
        // carry, but only by one, and the second cannot.
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) &+ (sum >> 16)
        }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    /// Convenience over an array, for tests and for callers that already own a buffer.
    public static func compute(_ bytes: [UInt8]) -> UInt16 {
        compute(bytes[bytes.indices].span)
    }

    /// Whether a buffer that already carries its checksum verifies.
    ///
    /// Summing a correct packet including its checksum field yields zero. That is the
    /// receive-side check, and it is one line because of the property rather than in
    /// spite of it.
    public static func verifies(_ bytes: Span<UInt8>) -> Bool {
        compute(bytes) == 0
    }
}

/// Decodes a value from wire bytes.
///
/// Every packet and every variable-length kernel structure goes through a conformance
/// of this, so parsing lives in one auditable place per format instead of being
/// open-coded at each use.
///
/// Taking a borrowed `Span<UInt8>` rather than an `UnsafeRawBufferPointer` means bounds
/// are checked and no pointer can escape its buffer's lifetime — which matters most for
/// the case that motivated it: a `sockaddr_dl` inside a routing-socket message is
/// variable-length and unaligned, and `bindMemory` on it is alignment undefined
/// behaviour that works on one machine and crashes on another. Explicit byte offsets
/// over a bounds-checked span have no such failure mode.
///
/// Returning an Optional rather than throwing: a malformed packet is a normal event on
/// a network and not an exceptional one, and a parser that throws invites a call site
/// that catches and continues, which is the same thing with more code.
public protocol WireDecodable {
    /// What this decodes to.
    associatedtype Decoded

    /// Decodes, or returns nil if the bytes are not a well-formed instance.
    static func decode(_ bytes: Span<UInt8>) -> Decoded?
}
