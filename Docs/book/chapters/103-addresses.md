# 3 · Mailboxes and addresses

![A socket is the mailbox. The address you write on the letter is a sockaddr.](figures/03-hero.svg)

::: short
The short version

- A socket is made from three choices: **family** (IPv4, IPv6…), **type** (stream, datagram, raw) and **protocol** (TCP, UDP, ICMP).
- An address is a small struct of bytes, a **`sockaddr`**. For IPv4 it's `sockaddr_in`: 16 bytes.
- Ports and addresses travel **big end first** ("network byte order"). Apple's chips store numbers the other way round, so Zhen flips them.
- When you don't know the family yet, use the big crate, **`sockaddr_storage`**, and read the family first.
- Zhen reads kernel structs **byte by byte at known offsets** instead of casting, because kernel buffers aren't always lined up.
:::

## A socket is a recipe

![socket(family, type, protocol). Zhen's ping is AF_INET + SOCK_DGRAM + IPPROTO_ICMP.](figures/03-recipe.svg)

Every `socket()` call picks one item from each column:

- **Family**: which kind of address.
  - `AF_INET` for IPv4, `AF_INET6` for IPv6.
  - `AF_LINK` is hardware (MAC) addresses. Zhen never opens an `AF_LINK` socket; it only *reads* `AF_LINK` addresses that the kernel hands back about interfaces (`Interfaces.swift:49`).
- **Type**: how the conversation goes.
  - `SOCK_STREAM`: a phone call. Connect first, then a steady stream (TCP).
  - `SOCK_DGRAM`: postcards. Each message stands alone (UDP, and Darwin's ping socket).
  - `SOCK_RAW`: build the whole packet yourself. Needs root, and Zhen opens none. On the Mac it uses BPF instead (chapter 11).
- **Protocol**: the exact protocol inside that type.

Zhen's sockets, all from the same three columns:

| What | Recipe | Where |
|---|---|---|
| Ping (chapter 5) | `AF_INET, SOCK_DGRAM, IPPROTO_ICMP` | `ICMPSocket.swift:81` |
| IPv6 ping | `AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6` | `ICMPv6Socket.swift:46` |
| TCP knock (chapter 6) | v4 or v6, `SOCK_STREAM, IPPROTO_TCP` | `TCPConnectScan.swift:176` |
| UDP probe (chapter 7) | v4 or v6, `SOCK_DGRAM, IPPROTO_UDP` | `UDPProbe.swift:125` |

::: word
New word: address family

An **address family** is a number that says what kind of address follows: `AF_INET` (2) is IPv4, `AF_INET6` (30 on Darwin) is IPv6, `AF_LINK` (18) is a hardware address. It's the first thing to check in any address the kernel gives you.
:::

## The address label: `sockaddr_in`

![sockaddr_in is 16 bytes: length, family, port, address, then padding.](figures/03-sockaddr.svg)

1. **`sin_len`**: the struct's own length, 16. This byte exists **only on BSD** systems like Darwin. Linux doesn't have it.
2. **`sin_family`**: `AF_INET`.
3. **`sin_port`**: two bytes, big end first.
4. **`sin_addr`**: four bytes, big end first.
5. **`sin_zero`**: eight bytes of padding.

Zhen fills one in like this:

```swift
func socketAddress(_ address: IPv4Address, port: UInt16 = 0) -> sockaddr_in {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: address.raw.bigEndian)
    return addr
}
```

[`DarwinPlatform.swift:146-153` @ 0.9.0]{.src}

## Big end first

![Port 80 is 0x0050. The chip stores 50 00; the wire wants 00 50.](figures/03-endian.svg)

- The network sends numbers **big end first**: the most significant byte goes out first. That's **network byte order**.
- Apple's chips (Intel and Apple silicon alike) are **little-endian**: they store the small end first.
- So every port and address is flipped on the way out (`.bigEndian`, above) and flipped back on the way in (`UInt32(bigEndian:)`, `DarwinPlatform.swift:219`).
- Forget the flip and port 80 (`0x0050`) goes out as `0x5000`, which is port **20480**.

::: word
New word: byte order

**Byte order** (or *endianness*) is which end of a multi-byte number is stored first. **Big-endian** puts the most significant byte first; **little-endian** puts it last. The network is big-endian; your Mac and iPhone are little-endian.
:::

## One crate for any address

![sockaddr_storage is big enough for any address. Read the family first, then decide.](figures/03-storage.svg)

When the kernel tells you who sent a packet, you don't know in advance whether it's IPv4 or IPv6. So:

1. Give the kernel a **`sockaddr_storage`**: 128 bytes, big enough and aligned for any address. The ping socket does exactly that before every read (`ICMPSocket.swift:300`).
2. Look at its **family** first.
3. Then read it as a `sockaddr_in` (16 bytes) or a `sockaddr_in6` (28 bytes), or skip it (`DarwinPlatform.swift:197-206`).

Going the other way, the kernel's doors take a plain **`sockaddr*`**, a pointer that only promises "length and family come first". Zhen hands over its `sockaddr_in` *viewed as* a `sockaddr`, just for the length of the call:

```swift
return unsafe withUnsafePointer(to: &storage) { pointer in
    unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        unsafe body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
}
```

[`DarwinPlatform.swift:179-183` @ 0.9.0]{.src}

## Read the bytes, don't cast

![Kernel records are packed end to end. Casting a struct onto a crooked spot can crash; reading bytes at an offset can't.](figures/03-align.svg)

- A struct is **aligned** when it starts at an address its fields expect: a 4-byte number at a multiple of 4.
- The kernel often packs records **end to end**, at whatever position the last one ended. So a struct inside its buffer can sit on a "crooked" address.
- **Casting** the buffer to that struct is undefined behaviour: it "works on every machine you own and crashes on someone else's" (`RouteMessages.swift:13-17`).
- So Zhen reads **bytes at known offsets**, with `loadUnaligned`, which is safe at any position:

```swift
func ipv4(from storage: sockaddr_storage) -> IPv4Address? {
    guard storage.ss_family == sa_family_t(AF_INET) else { return nil }
    let raw = unsafe withUnsafeBytes(of: storage) { bytes in
        unsafe bytes.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
    }
    return IPv4Address(raw: UInt32(bigEndian: raw))
}
```

[`DarwinPlatform.swift:209-220` @ 0.9.0 (comments trimmed)]{.src}

**Coming up: `sockaddr_dl` lies.** The hardware-address struct says it is 20 bytes, but the interface name and the MAC share a trailing array whose declared size "is a lie for anything with a name longer than six characters" (`RouteMessages.swift:7-11`). Chapters 8 and 12 deal with it.

::: word
New word: alignment

**Alignment** is the rule that a value of size N should start at an address that's a multiple of N. Reading a misaligned value through a typed pointer is undefined behaviour in Swift and C. `loadUnaligned` is the safe way.
:::

::: iphone
📱 On iPhone & iPad

- ✅ Socket families, types, `sockaddr_in`, `sockaddr_storage` and byte order: all identical. It's the same BSD layer.
- ✅ The iOS app reads `AF_LINK` addresses by byte offset too, in its Diagnostics check (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:104-111`).
- ❌ Your device's real MAC address: iOS reports `02:00:00:00:00:00` for every interface, so Zhen drops it (`Docs/IPADOS.md:25`). More in chapter 8.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **The forgotten flip.** Port 80 without `.bigEndian` goes out as port 20480.
- **IPv6 link-local needs a zone.** A `fe80::` address without `sin6_scope_id` "is unroutable on a machine with more than one link", and the connect fails or leaves by the wrong interface (`DarwinPlatform.swift:165-169`).
- **Casting packed kernel bytes.** Fine on your Mac, a crash on someone else's, or a crash a year later "when a struct grows by two bytes" (`RouteMessages.swift:13-17`).
:::

::: remember
🧠 Remember

- Socket = **family + type + protocol**. Zhen's ping is `AF_INET + SOCK_DGRAM + IPPROTO_ICMP`.
- `sockaddr_in` is 16 bytes, starts with BSD's **`sin_len`**, and stores port and address **big end first**.
- Read the **family** first, then read **bytes at offsets**. Don't cast kernel buffers.
:::
