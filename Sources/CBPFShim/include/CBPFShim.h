// CBPFShim.h — the BPF constants ClangImporter cannot see, and nothing else.
//
// `BIOCSETIF` and its siblings are function-like macros over `sizeof(struct ifreq)`:
//
//     #define BIOCSETIF  _IOW('B', 108, struct ifreq)
//
// `_IOW` computes a request number from the size of a type, and ClangImporter will not
// evaluate that — it reports `macro 'BIOCSETIF' unavailable: structure not supported`
// and the symbol simply does not exist in Swift. Same for `BPF_ALIGNMENT`, which is
// `sizeof(int32_t)`. So the values are computed here, by the C compiler, on the SDK
// being built against.
//
// **This wraps no syscall.** Every function below returns a number. `ioctl`, `read`
// and `write` are called from Swift against the Darwin overlay's own non-variadic
// `ioctl(_:_:UnsafeMutableRawPointer)` — wrapping those as well would add a layer that
// can disagree with the platform, and the platform is the thing being described.
//
// The offset accessors exist for the same reason and are used the same way. A BPF read
// returns records behind a `struct bpf_hdr` whose fields have to be located by byte
// offset, because the buffer is packed, unaligned kernel output and a struct cast over
// it is alignment undefined behaviour — the same hazard `RouteMessages.swift` handles
// for `sockaddr_dl`, and it is handled the same way. Rather than writing the offsets
// into a Swift comment and trusting them, `offsetof` computes them here and the walk
// reads what the compiler says. Measured on macOS 26.5 they are 0, 8, 12, 16 with a
// 20-byte header; if a future SDK moves one, the walk moves with it and no test has to
// be told.
#ifndef ZHEN_CBPF_SHIM_H
#define ZHEN_CBPF_SHIM_H

#include <stddef.h>

#if defined(__APPLE__)

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>

// ── ioctl request numbers ────────────────────────────────────────────────────────

/// `BIOCGBLEN` — read the buffer length the device will use.
static inline unsigned long ns_bpf_gblen(void) { return BIOCGBLEN; }
/// `BIOCSBLEN` — request a buffer length. Must be set *before* `BIOCSETIF`.
static inline unsigned long ns_bpf_sblen(void) { return BIOCSBLEN; }
/// `BIOCSETIF` — bind the device to an interface, by name in a `struct ifreq`.
static inline unsigned long ns_bpf_setif(void) { return BIOCSETIF; }
/// `BIOCIMMEDIATE` — deliver each packet as it arrives instead of when the buffer
/// fills. Without it a reply sits in the kernel until enough other traffic arrives to
/// flush it, which on a quiet segment is never.
static inline unsigned long ns_bpf_immediate(void) { return BIOCIMMEDIATE; }
/// `BIOCSETF` — install a filter program.
static inline unsigned long ns_bpf_setf(void) { return BIOCSETF; }
/// `BIOCFLUSH` — discard whatever is already buffered.
static inline unsigned long ns_bpf_flush(void) { return BIOCFLUSH; }
/// `BIOCSHDRCMPLT` — the application supplies the link-level source address. We build
/// the whole Ethernet header, so the kernel must not rewrite it.
static inline unsigned long ns_bpf_hdrcmplt(void) { return BIOCSHDRCMPLT; }
/// `BIOCSSEESENT` — whether reads also return locally generated traffic. Turned off,
/// so the sweep does not spend its budget reading back its own requests.
static inline unsigned long ns_bpf_seesent(void) { return BIOCSSEESENT; }
/// `BIOCGDLT` — the data-link type, which must be `DLT_EN10MB` for the frames this
/// engine builds to mean anything.
static inline unsigned long ns_bpf_gdlt(void) { return BIOCGDLT; }
/// `BIOCPROMISC` — promiscuous mode. Deliberately never called: an ARP reply to our
/// own request is unicast to our own hardware address, so there is nothing to gain and
/// a segment's whole traffic to read if we asked for it.
static inline unsigned long ns_bpf_promisc(void) { return BIOCPROMISC; }

// ── alignment ───────────────────────────────────────────────────────────────────

/// `BPF_ALIGNMENT` — four on every Darwin, but computed rather than assumed.
static inline unsigned long ns_bpf_alignment(void) { return (unsigned long)BPF_ALIGNMENT; }

/// `BPF_WORDALIGN(x)` — the step from one record to the next.
///
/// This is the single arithmetic operation that a BPF walk gets wrong. Advancing by
/// `bh_hdrlen + bh_caplen` unrounded desynchronises the cursor by one to three bytes
/// and every subsequent record is read from the middle of the previous packet, which
/// yields plausible garbage rather than an error.
static inline unsigned long ns_bpf_wordalign(unsigned long value) {
    return (unsigned long)BPF_WORDALIGN(value);
}

// ── struct geometry, from offsetof rather than from memory ──────────────────────

/// `sizeof(struct bpf_hdr)`. Not the same as `bh_hdrlen`, which is the *actual*
/// header length of a given record including any padding the kernel inserted, and is
/// what the walk must use.
static inline size_t ns_bpf_hdr_size(void) { return sizeof(struct bpf_hdr); }
/// Offset of `bh_tstamp.tv_sec`.
static inline size_t ns_bpf_hdr_off_tstamp_sec(void) {
    return offsetof(struct bpf_hdr, bh_tstamp);
}
/// Offset of `bh_caplen` — how many bytes of the packet the kernel actually stored.
static inline size_t ns_bpf_hdr_off_caplen(void) {
    return offsetof(struct bpf_hdr, bh_caplen);
}
/// Offset of `bh_datalen` — how long the packet was on the wire. Larger than
/// `bh_caplen` when the snap length truncated it.
static inline size_t ns_bpf_hdr_off_datalen(void) {
    return offsetof(struct bpf_hdr, bh_datalen);
}
/// Offset of `bh_hdrlen` — the distance from the start of this record to its packet.
static inline size_t ns_bpf_hdr_off_hdrlen(void) {
    return offsetof(struct bpf_hdr, bh_hdrlen);
}
/// The smallest a record's `bh_hdrlen` can legitimately be.
///
/// **Not `sizeof(struct bpf_hdr)`, and the difference is a real bug that shipped.**
/// The struct is padded to 20 bytes by the compiler; the fields end at 18, and the
/// kernel writes 18 into `bh_hdrlen` on every record macOS 26.5 produces. A walk that
/// required `bh_hdrlen >= sizeof(struct bpf_hdr)` therefore rejected the first record
/// of every read and reported a segment with nothing on it — which is exactly what a
/// segment with nothing on it looks like, so nothing failed and no test noticed until
/// a capture was taken beside a live sweep.
///
/// The minimum a header must be is the end of the last field it carries, which is what
/// this computes.
static inline size_t ns_bpf_hdr_min_length(void) {
    return offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(u_short);
}

/// `sizeof(struct ifreq)`, for the buffer `BIOCSETIF` writes a name into.
static inline size_t ns_bpf_ifreq_size(void) { return sizeof(struct ifreq); }
/// `IFNAMSIZ` — the interface-name field's capacity, including its terminator.
static inline size_t ns_bpf_ifnamsiz(void) { return (size_t)IFNAMSIZ; }

#endif /* __APPLE__ */

#endif /* ZHEN_CBPF_SHIM_H */
