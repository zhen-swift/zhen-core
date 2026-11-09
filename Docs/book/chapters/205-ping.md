# 5 · Ping without root

![One mailbox pings every host on the network, and no crown is needed.](figures/05-hero.svg)

::: short
The short version

- Darwin has a **ping socket any user may open**: `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`. No root, no password.
- **One** socket serves the whole sweep. ICMP has no ports, so the kernel stamps an id on each ping to send replies back to the right ticket.
- Each ping is **24 bytes**. Zhen writes the checksum itself, and identifies each probe by a 32-bit **token** in the payload.
- A full send buffer answers `EAGAIN`. Zhen **steps aside**, then **waits for the write bell**. It never sleeps.
- When the read bell rings, Zhen **reads until the socket is empty**, stamps the time at once, and throws away anything that isn't one of its echo replies.
:::

## The ping socket anyone may open

![SOCK_DGRAM + IPPROTO_ICMP opens for any user. SOCK_RAW needs root.](figures/05-dgram.svg)

- The classic way to ping is a **raw** socket (`SOCK_RAW`). Raw sockets need **root**.
- Darwin also offers an ICMP **datagram** socket. Any user may open it, and it's "the reason this tool needs no password" (`ICMPSocket.swift:77-79`).
- Zhen opens it once, and switches it to non-blocking straight away (chapter 4):

```swift
let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
guard descriptor >= 0 else { throw PlatformError.syscall("socket(SOCK_DGRAM, IPPROTO_ICMP)") }
guard setNonBlocking(descriptor) else {
    _ = Darwin.close(descriptor)
    throw PlatformError.syscall("fcntl(O_NONBLOCK)")
}
```

[`ICMPSocket.swift:81-86` @ 0.9.0]{.src}

Then it sets three options. They're all "best effort", so the code ignores their return value:

1. **`IP_RECVTTL`**: "also tell me each reply's TTL" (`ICMPSocket.swift:90-92`).
2. **`SO_RCVBUF` = 1 MiB**: a /24 can send 254 replies within a few milliseconds, and the default buffer would drop them, which "would read as packet loss from hosts that in fact replied" (`ICMPSocket.swift:93-98`).
3. **`SO_SNDBUF` = 1 MiB**: against the default, "roughly half" of 254 back-to-back pings are refused, "which reads as half the network being absent" (`ICMPSocket.swift:99-105`).

::: word
New word: ICMP echo

**ICMP** is the network's control-message protocol. An **echo request** (type 8) says "are you there?". A host that's up sends back an **echo reply** (type 0) with the same payload. That's all `ping` is.
:::

## One mailbox for the whole network

![ICMP has no ports. The kernel stamps an id on the way out, and uses it to route the reply back to ticket 3.](figures/05-onesocket.svg)

- TCP and UDP use **ports** to tell conversations apart. **ICMP has no ports** (`ICMPSocket.swift:3-7`).
- So the kernel **rewrites the identifier field** of each outgoing ping, and uses it to deliver replies to the right socket (`ICMPPacket.swift:3-6`).
- One ticket covers a whole /24. That's also why the ticket limit from chapter 2 never limits discovery; it only limits the TCP knock (`ICMPSocket.swift:6-7`).
- Since the **kernel owns the id**, Zhen can't use it to match replies. It uses its own **token** instead (next section).

The socket also gets **two private lanes**, so replies never queue behind the rest of the app:

- The socket's **actor** runs on its own serial queue, `com.jctec.zhen.icmp` (`ICMPSocket.swift:25-55`). That's where pings are sent from.
- Its **read bell** rings on the readiness queue from chapter 4 (`ICMPSocket.swift:140`).
- Why it matters: "a reply that waits behind a report encode is measured as network latency and inflates every RTT in the artifact" (`ICMPSocket.swift:9-13`).

## The 24-byte ping

![An 8-byte header, then 16 bytes of payload: the magic NSTY, a 32-bit token, and zeros.](figures/05-packet.svg)

1. **Type 8, code 0**: "echo request".
2. **Checksum**: Zhen computes it. "The kernel rewrites the identifier field on the way out … but it does not compute the checksum" (`ICMPPacket.swift:4-7`).
3. **Identifier**: left at zero, because the kernel overwrites it.
4. **Sequence**: set, because "middleboxes look at it", but not used for matching (`ICMPPacket.swift:41-42`).
5. **Magic `NSTY`**: so a reply to somebody else's ping is "visibly wrong rather than silently accepted" (`ICMPPacket.swift:25-27`).
6. **Token**: 32 bits, the probe's real name. An echo reply must return the payload unchanged, so the token comes back (`ICMPPacket.swift:33-39`).
7. **Eight bytes of zeros** make up the 16-byte payload (`ICMPPacket.swift:28-29`).

Why a token and not the sequence number? The sequence is **16 bits** and wraps at 65,536, "comfortably inside a single /16 sweep with retransmissions". A wrapped number makes a live host look absent (`ICMPPacket.swift:33-37`).

The checksum is the classic **internet checksum** (RFC 1071), in ZhenCore:

```swift
while index + 1 < bytes.count {
    sum &+= UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
    index += 2
}
while sum >> 16 != 0 {
    sum = (sum & 0xFFFF) &+ (sum >> 16)
}
return ~UInt16(truncatingIfNeeded: sum)
```

[`InternetChecksum.swift:57-70` @ 0.9.0 (trimmed)]{.src}

Why not let the kernel do it with a raw socket? That needs root. As the code puts it: "Computing sixteen-bit sums is cheaper than asking a user for a password" (`InternetChecksum.swift:8-10`).

::: word
New word: checksum

A **checksum** is a small number computed from a packet's bytes and sent with it. The receiver sums the bytes again; for the internet checksum, a correct packet **sums to zero** (`InternetChecksum.swift:78-85`). Anything else means the bytes were damaged.
:::

::: honest
🔍 Honest note: sequence or token?

The file's header says "the sequence number and the source address are what identify a reply" (`ICMPPacket.swift:9-11`). Twenty lines later the code says the opposite, in bold: "The token, not the sequence number, is what identifies a probe" (`ICMPPacket.swift:33`). The code matches on the **token**; the header is out of date.
:::

## Sending 254 pings at once

![When the send buffer is full: four quick yields, then wait for the write bell. Never sleep.](figures/05-send.svg)

- A sweep sends a whole round in **one actor hop**. 254 sends take "about ten milliseconds"; 254 separate hops "took several hundred" (`ICMPSocket.swift:207-214`).
- Each ping is one `sendto` (`ICMPSocket.swift:250`).
- If it fails with **`EAGAIN`** or **`ENOBUFS`**, the buffer is full. Zhen tries up to **8 times**:

```swift
if attempt < 4 {
    await Task.yield()
} else if await Readiness.writableBorrowed(fd, within: .milliseconds(50)) == .cancelled {
    return nil
}
```

[`ICMPSocket.swift:271-275` @ 0.9.0]{.src}

1. Tries 1–4: **`Task.yield()`**. A datagram buffer drains in microseconds, and a yield "costs nothing".
2. Tries 5–8: wait for the **write bell**, up to 50 ms. Not first, because a bell per refused ping "cost more wall clock than the sends themselves" (`ICMPSocket.swift:263-267`).
3. Never **`Task.sleep`**: it naps for about a millisecond, so "microsecond-scale retries across a sweep cost seconds" (`ICMPSocket.swift:269-270`).
4. Still refused? The ping is **not sent**, which is not the same as "no answer". It's left out of the results (`ICMPSocket.swift:216-218`).

## Reading the replies

![One ding: read until empty. Keep echo replies, skip everything else, stop when nothing is left.](figures/05-drain.svg)

When the read bell rings:

```swift
while true {
    switch ICMPSocket.receive(descriptor, at: .now) {
    case .datagram(let reply):
        if let reply { continuation.yield(reply) }
    case .drained:
        return
    }
}
```

[`ICMPSocket.swift:160-167` @ 0.9.0]{.src}

1. **Stamp the time first** (`at: .now`), inside the bell's handler. A stamp taken later "measures the scanner rather than the network" (`ICMPSocket.swift:157-159`).
2. **Read with `recvmsg`**, not `recvfrom`, because the TTL arrives as a separate **control message** and "there is no other way to see it" (`ICMPSocket.swift:282-283`).
3. **Find the TTL** by walking the control messages by hand. Swift can't import the C `CMSG_*` macros, so Zhen redoes their arithmetic: 32-bit alignment, and a `cmsg_len` check so a bad length can't push the cursor backwards or off the end (`ICMPSocket.swift:352-398`).
4. **Decode** the bytes (`ICMPPacket.swift:111-163`):
   - Does it start with an IPv4 header? Look at the version nibble and skip it if so (`:120-128`).
   - Not an echo reply? **Skip it**: "destination-unreachable and time-exceeded messages also land on this socket", and the host they name "is precisely the one that did not" answer (`:131-136`).
   - Checksum doesn't sum to zero, or no `NSTY`? Skip it (`:146`, `:153-155`).
5. **Keep reading until the socket is empty.** Don't stop at the first thing that isn't a reply (`ICMPSocket.swift:146-156`).

::: word
New word: TTL and control message

**TTL** (time to live) is a counter in every IP packet that each router lowers by one. Hosts start it at 64 (macOS, iOS, Linux), 128 (Windows) or 255 (network gear), so it's a free hint about the OS (`ICMPPacket.swift:88-93`). A **control message** (`cmsg`) is extra information the kernel attaches beside a packet's data, like that TTL.
:::

::: honest
🔍 Honest note: is the IP header there or not?

The decoder's comment says the IP header is stripped "on this machine" (`ICMPPacket.swift:100-101`). A few lines down, the checksum comment says the received datagram "still carries the IP header" (`ICMPPacket.swift:143-144`). The code doesn't take sides: it checks the version nibble and **handles both** (`ICMPPacket.swift:120-128`).
:::

::: iphone
📱 On iPhone & iPad

- ✅ The ping sweep is how the iPad finds hosts. It's part of the unprivileged set built for iPadOS (`DarwinScanner.swift:194-218`; `Docs/IPADOS.md:17`).
- ✅ The app's **Diagnostics** screen opens the same unprivileged ICMP socket on your device and reports what happened (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:35-46`).
- ✅ TTL, checksum, token, drain loop: the same code.
- ⚪️ The IPv6 all-nodes ping (`DarwinMulticastEcho`, `ICMPv6Socket.swift:221`) compiles for iOS, but only the Mac's command line switches it on (`zhen/Platform/ScannerFactory.swift:95`). The apps' adapter, ZhenScan, never asks for it.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Counting `EAGAIN` as silence.** The first version did, and reported "half the network as absent" (`ICMPSocket.swift:239-242`).
- **Stopping the drain early.** Each unreachable message ended the read loop, so the replies behind it got a later timestamp and an inflated round trip, which then slowed the adaptive timeout (`ICMPSocket.swift:149-155`).
- **Stamping late.** A LAN host answering in 0.4 ms was reported at 207 ms, and the error fed the timeout and slowed the whole sweep (`ICMPPacket.swift:81-86`).
- **Reading the wrong eight bytes.** If the decoder guesses the header wrong, "every host" looks unreachable "with no indication why" (`ICMPPacket.swift:102-105`).
- **Odd-length checksums.** Pad the last byte on the right, or the sum is wrong for every odd-length packet, a bug that "survives a test suite built only from realistic ICMP echo headers" (`InternetChecksum.swift:47-50`).
- **Two closers.** Only one of the read bell's cancel handler and `deinit` may close the ticket, chosen by `sourceOwnsDescriptor` (`ICMPSocket.swift:68-73`, `:115-126`).
:::

::: remember
🧠 Remember

- `SOCK_DGRAM` + `IPPROTO_ICMP` = **ping without root**, on the Mac and the iPhone.
- **One** socket, 24-byte pings, a **token** to match replies, a **checksum** Zhen computes itself.
- Full buffer: **yield, then the write bell, never sleep**. Read bell: **stamp, read until empty, skip what isn't ours**.
:::
