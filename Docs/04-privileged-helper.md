# 04 — The privileged helper

**Status: built.** The Developer ID certificate arrived and the helper exists. This
document was written before it did, and the design it describes is the design that
shipped; what follows records where it was right, where it was changed on contact, and
what is still missing.

## What changed from the design below

**The seam held.** `BPFDevice`'s initializer never cared where its descriptor came
from, so the helper needed one more way to reach it and no new layer. `BPFSweep`,
`SYNScan` and `OSFingerprintProbe` were not modified beyond taking a `CaptureSource` —
a closure in a box rather than an enum, because an enum with a `.helper` case would put
the word in three engines that must never branch on it.

**The order was reversed.** This document said try the helper first. The code tries a
direct open first, so a `sudo` run acquires no dependency on a daemon it does not need
and the path `Scripts/verify-privileged.sh` has always measured stays the path that
runs.

**It is opt-in per caller.** The command line asks for `.directOnly` and gets exactly
the composition it had before the helper existed, because it is the binary study 2
measures and that study's gate requires the unprivileged discovery path unchanged. A
helper probe on every scan's startup is a change to that path whether or not it finds
anything.

**The descriptor-passing shape was chosen**, and the `BIOCLOCK` problem below is real
and unmitigated except by the client check — which is now mandatory, checked in
`shouldAcceptNewConnection` before an interface name is read, and refused outright on a
system too old to perform it.

## What it is verified to do

`Scripts/verify-helper.sh`, from the wire:

```
app, sweep off (ZHEN_CAPTURE=direct)   206 requests / 204 targets = 1.01 per address
app, sweep on via the helper                804 requests / 254 targets = 3.17 per address
privileged command line, for comparison    1001 requests / 253 targets = 3.96 per address
```

The kernel resolves each address once; the sweep asks each up to three times. An app
running as an ordinary user reproduces the `sudo` signature, which is the claim the
whole design rests on.

**Frame length does not identify our packets.** An earlier version of that script
claimed ours were 42 bytes and the kernel's padded to 60. The kernel does not pad on
this interface: an unprivileged scan that cannot open a capture device at all emitted
250 ARP requests, every one of them 42 bytes. Volume against a same-binary baseline is
the method that works.

## What is still missing

**Notarization.** The app is Developer ID signed and not notarized, and `spctl` says so:

```
build/Zhen.app: rejected
source=Unnotarized Developer ID
```

It runs here because a locally built bundle carries no quarantine attribute. On any
other Mac it is blocked on first open, and a person who cannot open the app cannot reach
the button that installs the helper. That is the next thing to do and it needs no code.

---

## What problem the helper solves

Today the privileged capabilities — `arp_sweep`, `syn_scan`, `os_fingerprint` — need
`sudo zhen`. That works and it is honest, and it costs three things:

- **A password every scan.** There is no way around it, and this project will not try
  to find one.
- **The history splits.** A root-run scan is written to the invoking user's history
  by deliberate design (see `FILES` in the manual), but every other root-owned side
  effect is a trap waiting to be stepped on.
- **The Local Network grant follows the terminal.** A bare binary has no bundle, so
  the grant attaches to whatever launched it. Under `sudo` that is a different
  security context again.

A helper fixes the first, which is the one that stops people using the privileged
path at all.

---

## The seam, which already exists

Exactly one function in this codebase acquires a privileged resource:

```swift
// Sources/ZhenDarwin/BPFDevice.swift
static func open(interface: String, filter: [bpf_insn]) throws(BPFUnavailable) -> BPFDevice
```

Everything privileged flows from what it returns. The ARP sweep, the half-open SYN
scan and the stack fingerprint all reach the wire through a `BPFDevice`, and a
`BPFDevice` is a descriptor plus a buffer length:

```swift
private init(fd: Int32, bufferLength: Int, devicePath: String, interfaceName: String)
```

That initializer does not care where `fd` came from. It was written that way because
the walk over `/dev/bpf*` and the configuration of a descriptor were already two
separate concerns, and the result is that the helper does not need a new abstraction
layer — it needs one more way to reach that initializer.

So the change, when the certificate exists, is:

1. Make the private initializer accessible to a descriptor that arrived over XPC.
2. Add a second acquisition path beside `open`, taking a descriptor from the helper.
3. Try the helper first in `DarwinScanner`, fall back to the direct open, fall back
   to unprivileged. Three rungs instead of two.

Nothing else moves. `BPFSweep`, `SYNScan` and `OSFingerprintProbe` do not learn that
a helper exists, which is the property worth protecting.

### What does *not* change

`BPFDevice.probe(interface:)` stays as it is, and selection stays by attempt rather
than by `geteuid()`. A helper is one more thing that can be absent, busy, unregistered
or refused by the user, and every one of those is discovered by trying — which is the
same argument that rejected the euid check in the first place.

---

## What the helper would be

A `SMAppService.daemon`, registered from the app bundle, running as root, speaking
one XPC protocol with one method:

```
openCaptureDevice(interface: String) -> (descriptor, bufferLength) | refusal
```

It opens `/dev/bpf*`, applies the same `BIOCSETIF` / `BIOCIMMEDIATE` /
`BIOCSHDRCMPLT` / `BIOCSETF` configuration the in-process path applies, and passes
the descriptor back over the connection. It parses nothing, sends nothing, and holds
no state between calls. The whole of its privileged surface is "open one capture
device on one named interface".

### The security property it cannot have, and what that costs

On FreeBSD a handed-over BPF descriptor can be made immutable with `BIOCLOCK`, so a
helper can guarantee the client only ever sees the filtered traffic the helper chose.
**Darwin has no `BIOCLOCK`.** The ioctl list in `net/bpf.h` ends at `BIOCSETFNR`;
there is nothing that freezes a descriptor's configuration.

This matters. A BPF descriptor handed to an unprivileged process is a capability that
process can re-aim: it can `BIOCSETF` a new filter, `BIOCPROMISC` the interface and
read every packet on the segment. Handing one out is therefore not "lending the ARP
sweep a device", it is "granting full local packet capture, permanently, to whatever
is on the other end of that connection".

Two honest designs follow from that, and the choice between them is the real decision
this document defers:

- **Hand over the descriptor.** Small helper, all the parsing stays in the main
  binary where it is tested, and the privilege boundary is weak: anything that can
  talk to the helper gets promiscuous capture. Acceptable only with a strict
  code-signing requirement on the client, checked per connection — and a signing
  requirement is exactly the thing that is missing today.
- **Keep the descriptor in the helper.** The helper runs the sweep and returns
  results, so the boundary is strong and narrow: the client can ask for an ARP sweep
  of a named interface and gets hosts back, never packets. The cost is that
  `BPFSweep`, `SYNScan` and the fingerprint probe move across the boundary into
  privileged code, roughly tripling what runs as root and putting the tested parsing
  on the wrong side of the line.

The first is the smaller change and the weaker guarantee. The second is the stronger
guarantee and a substantially larger helper. Deciding between them without being able
to sign, register or capture from either one would be picking an answer by taste.

---

## What had to be true before this was built

1. A Developer ID Application certificate, because `SMAppService` will not register
   an unsigned daemon. **Present**, team `S8662L649U`.
2. An app bundle to register it from. `Scripts/build-app.sh` already produces one.
3. A code-signing requirement string for the client, and a per-connection check of it
   in the helper. Without this, the descriptor-passing design is not defensible.
4. **A capture that proves it.** `Scripts/verify-privileged.sh` compares the wire for
   a privileged and an unprivileged run of the same scan; the helper's version of
   that script compares a helper-brokered run against a `sudo` run and shows the same
   ARP frames leaving the machine either way. Nothing here ships on the strength of
   an artifact saying it worked.

Until item 1 exists, `sudo zhen` is the supported way to reach the privileged
path, and the manual says so plainly.
