# 12 · The castle's address book: routing socket and ARP table

![The kernel keeps an address book: IP on the left, MAC on the right. On a Mac, Pip can read it without root.](figures/12-hero.svg)

::: short
The short version

- The kernel keeps an **ARP table**, IP → MAC, for every neighbour it has recently talked to.
- On a Mac any app can read it with `sysctl`. **No root, no probe.**
- It arrives as a packed stream of **routing messages**. Zhen reads them **byte by byte**, never by casting to a struct.
- Not every line is a device. Zhen keeps the real ones, marks the "nobody home" ones and drops broadcast and multicast.
- During a sweep Zhen **peeks at the table every 25 ms**, to catch hosts the moment they answer ARP.
:::

## Asking with `sysctl`

![sysctl takes an address (a MIB). Call once to ask the size, once to fill. If the table grew, try again.](figures/12-sysctl.svg)

::: word
New word: `sysctl` and MIB

**`sysctl`** is a door for reading kernel tables and settings. You say what you want with a **MIB**, a short array of numbers that works like a path: "network → routing → IPv4 → ARP entries".
:::

Zhen reads three tables this way:

| Table | MIB | Where |
|---|---|---|
| ARP (IPv4 neighbours) | `[CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]` | `NeighborTable.swift:31-33` |
| NDP (IPv6 neighbours) | the same, with `AF_INET6` | `NeighborTable.swift:91-93` |
| Routes, to find the default route's interface | `[CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0]` | `Interfaces.swift:145` |

Each read is **two calls** (`RouteMessages.swift:223-256`):

1. Call with no buffer: "how big?"
2. Make a buffer that size **plus 4,096 bytes** of slack.
3. Call again to fill it, and trim to what was written.
4. **`ENOMEM`?** "The table can grow between them — a device joining the network is enough." Go back to step 1, **up to 4 times** (`RouteMessages.swift:226-228`, `:251-252`).
5. Still changing? Give up and say why (`RouteMessages.swift:254`).

```swift
let bytes = try RouteSysctl.fetch(
    [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
)
```

[`NeighborTable.swift:31-33` @ 0.9.0]{.src}

## What one message looks like

![A message is a 92-byte header, then the addresses its bitmask says are there, each rounded up to 4 bytes.](figures/12-message.svg)

- Each message is an **`rt_msghdr`** (92 bytes on this SDK), followed by a few `sockaddr`s (chapter 3) (`RouteMessages.swift:24-29`).
- Which `sockaddr`s follow is set by a **bitmask**, `rtm_addrs`: destination, gateway, netmask and so on, always in that order (`RouteMessages.swift:64-68`).
- Each address is padded to 4 bytes, and a length of **0 still moves 4**. Get that wrong and the whole rest of the buffer falls out of step (`RouteMessages.swift:70-78`).
- A message with an impossible length **stops the walk**. Everything parsed before it is kept (`RouteMessages.swift:80-99`).
- Two quirks the code handles:
  - The default route's destination arrives cut short (length 0 or 4) and means 0.0.0.0 (`RouteMessages.swift:123-126`).
  - A /24 netmask arrives as just 5 bytes, so the missing zeros are added back (`RouteMessages.swift:174-178`).

```swift
static func roundUp(_ length: Int) -> Int {
    length == 0 ? MemoryLayout<UInt32>.size
                : (1 + ((length - 1) | (MemoryLayout<UInt32>.size - 1)))
}
```

[`RouteMessages.swift:75-78` @ 0.9.0]{.src}

::: word
New word: routing socket (`PF_ROUTE`)

The **routing socket** is the kernel's channel for its routing table, and the ARP table lives inside it. Zhen reads it through `sysctl` with `PF_ROUTE` in the MIB.
:::

## Where the MAC hides

![After 8 fixed bytes come the interface name, then the MAC. The declared 12-byte field is too small for long names.](figures/12-sdl.svg)

- In an ARP entry, the "gateway" slot holds a **link-layer address**, a `sockaddr_dl`, and that's where the MAC lives (`RouteMessages.swift:52-54`).
- `sockaddr_dl` has 8 fixed bytes, then `sdl_data`: the **interface name**, then the **MAC** straight after it (`RouteMessages.swift:26-27`).
- So the MAC starts at **`sdl_data + sdl_nlen`** and is **`sdl_alen`** bytes long (`RouteMessages.swift:156-172`).
- `sdl_data` is declared as 12 bytes. That size "is a lie" for any name longer than six characters (`RouteMessages.swift:7-11`). `bridge100` plus a MAC is 15.
- **`sdl_alen == 0`** means the kernel asked and nobody answered: an **incomplete** entry (`RouteMessages.swift:159-161`).
- IPv6 has a quirk from the KAME code: the kernel tucks a link-local address's scope into bytes 2–3 (`fe80:e::…`). Zhen clears them, as `ndp` does (`RouteMessages.swift:131-137`).

## Don't cast. Read bytes.

![Casting packed kernel bytes to a Swift struct is undefined behaviour. Reading each field at its byte offset is safe.](figures/12-align.svg)

- The messages sit end to end at **4-byte steps**, laid out by the kernel, in varying lengths (`RouteMessages.swift:13-14`).
- Pretending a spot is a Swift struct (`bindMemory`, `assumingMemoryBound`) is **undefined behaviour**, "the kind that works on every machine you own and crashes on someone else's" (`RouteMessages.swift:14-17`).
- Instead: **explicit byte offsets** over a `RawSpan`, through four tiny helpers, `u8`, `u16`, `i32` and `u32be`. They're the only `unsafe` code in the file (`RouteMessages.swift:190-219`).
- `u32be` reads addresses in **wire order**; the other three read the kernel's own numbers (chapter 3).

```swift
static func u16(_ bytes: RawSpan, _ offset: Int) -> UInt16 {
    guard offset >= 0, offset + 2 <= bytes.byteCount else { return 0 }
    return unsafe bytes.unsafeLoadUnaligned(fromByteOffset: offset, as: UInt16.self)
}
```

[`RouteMessages.swift:204-207` @ 0.9.0]{.src}

**Tested with real kernel bytes.** This is the opposite of chapter 11's hand-built BPF buffers:

- `arp-cache.bin` (1,436 bytes) and `route-dump.bin` (21,400 bytes) are **real dumps**, committed in `Tests/ZhenDarwinTests/Fixtures/`.
- Why: "a fixture assembled in Swift would be laid out by Swift, not by the kernel." (`RouteMessageTests.swift:15-20`)
- The test checks for **exactly 10 messages** in `arp-cache.bin`. A rounding slip would miscount (`RouteMessageTests.swift:37-40`).

## Not every line is a device

![Three bins: a device (kept), nobody home (kept, marked incomplete), plumbing like broadcast and mDNS (dropped).](figures/12-decode.svg)

`DarwinNeighborCache.decode` sorts each entry (`NeighborTable.swift:45-81`):

- **Has a MAC**: a device, kept. A static entry is marked "permanent", which is weaker evidence that the host is here *now* (`NeighborTable.swift:74-77`).
- **No MAC**: incomplete. Kept and marked, because it's "evidence of *absence*": asked, nobody home (`NeighborTable.swift:20-24`, `:58-66`).
- **Broadcast or multicast** (`10.10.20.255`, or `224.0.0.251` for mDNS): dropped. Otherwise every network would grow two fake devices, and the captured fixture had exactly those two (`NeighborTable.swift:50-57`).

**A control for chapter 10.** The table stays readable even when the Local Network permission is denied. "Probes hear nothing, yet the table is full" is the signature of a denied permission (`NeighborTable.swift:3-7`).

## Watching the book fill up

![A routing socket stays silent when an entry fills in, so Zhen re-reads the table every 25 ms and spots new arrivals.](figures/12-watch.svg)

- When Zhen pings an address the kernel hasn't met, the kernel sends **ARP first**. The answer lands in the table, often **before** the ping reply, and for a host that ignores ping it's the **only** answer (`NeighborWatch.swift:5-12`).
- Can a `PF_ROUTE` socket say when an entry fills in? **No.** On macOS 26.6.2, eleven entries resolved and an unprivileged listener heard nothing (`NeighborWatch.swift:16-21`).
- So Zhen **polls**, re-reading the table every **25 ms** (`NeighborWatch.swift:38`).
- Above **1,024 targets** the gap grows in step, so the bytes copied per second stay about the same. A /16 polls every **1.6 s** (`NeighborWatch.swift:23-27`).
- An entry already complete when the sweep starts is **inherited**, not news (`NeighborWatch.swift:57-59`).
- The loop itself lives in the ping sweep (`ICMPSweep.swift:316-345`).

```swift
public static func interval(targets: Int) -> Duration {
    guard targets > scaleAbove else { return baseInterval }
    return baseInterval * (Double(targets) / Double(scaleAbove))
}
```

[`NeighborWatch.swift:47-50` @ 0.9.0]{.src}

::: iphone
📱 On iPhone & iPad

- ❌ **No ARP table for apps.** The iOS SDK has no `<net/route.h>`, and the sandbox doesn't give an app the table anyway (`RouteMessages.swift:30-31`).
- ❌ On iPadOS, `SystemNeighborCache` picks **`UnavailableNeighborCache`** (`SystemNeighborCache.swift:15-21`). Nothing reads it, and no engine claims the capability (`PlatformSeam.swift:133-138`).
- ❌ So an iPad gets **no MAC addresses**, no vendor prefixes from them, no hosts found only through the table, and **no neighbour watch** (`ICMPSweep.swift:192-194`).
- ⚪️ Whether the **route table** (`NET_RT_DUMP`) is readable on a real device hasn't been measured. The app's **Diagnostics** screen checks it, and checks that the ARP table really is empty (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:66-88`).
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Rounding zero to zero.** A zero-length address still takes 4 bytes. Miss that and every later message is read out of step.
- **Trusting `sizeof(sockaddr_dl)`.** It's 20; the real record is often longer.
- **Casting packed kernel bytes.** It works here and crashes somewhere else.
- **Reporting plumbing.** Broadcast and multicast entries would be two fake hosts on every network.
- **Counting incomplete entries as devices.** That invents hosts.
- **Waiting for a routing message.** It never comes; poll instead.
:::

::: remember
🧠 Remember

- On a Mac, the ARP table is free layer-2 truth: no root, no probe, and still readable when Local Network is denied.
- Read the kernel's packed records **by byte offset**, and test with **real kernel bytes**.
- Nobody tells you when an entry fills in, so Zhen peeks every 25 ms.
:::
