# 8 · Which network am I on?

![A Mac can have Wi-Fi, a VPN, a container bridge and a tethered phone all up at once. Only one of them is home.](figures/08-hero.svg)

::: short
The short version

- Before it scans, Zhen picks **one interface** and the network on it, for example `en0` with `192.168.1.20/24`.
- `getifaddrs` lists every address of every interface, as a chain of cards the kernel builds for you.
- "The first one that's up" is wrong on a Mac with a VPN or a bridge. The right answer is **where the default route points**.
- The Mac reads its routing table with `sysctl`. The iPad has no routing table to read, so it **ranks interfaces by name**.
- The MAC address comes from a `sockaddr_dl`, read **byte by byte**.
:::

::: word
New word: interface

An **interface** is one network connection the kernel knows about: `en0` (Wi-Fi on most Macs), `lo0` (the machine talking to itself), `utun3` (a VPN tunnel). Each one can have several addresses.
:::

## The kernel's chain of cards

![getifaddrs returns a linked list. Zhen keeps the IPv4 cards that are up, running and not loopback, puts the MAC aside, and frees the chain.](figures/08-list.svg)

1. **`getifaddrs(&head)`** builds a linked list: one card per interface and address family (`Interfaces.swift:25-31`).
2. Walk it card by card through **`ifa_next`**, until `nil`.
3. **`AF_LINK`** cards carry a hardware address. Put the MAC aside under the interface's name (`Interfaces.swift:49-54`).
4. **`AF_INET`** cards carry an IPv4 address and a netmask. Keep only those that are **up**, **running** and **not loopback** (`Interfaces.swift:55-60`).
5. **`freeifaddrs(head)`** gives the chain back. A `defer` runs it on every way out, "including a thrown error" (`Interfaces.swift:26-31`).

```swift
let flags = unsafe node.ifa_flags
guard flags & UInt32(IFF_UP) != 0,
      flags & UInt32(IFF_RUNNING) != 0,
      flags & UInt32(IFF_LOOPBACK) == 0
else { continue }
```

[`Interfaces.swift:56-60` @ 0.9.0]{.src}

- The address and netmask are read at **byte offset 4**, not through a cast, "since the pointer's alignment is the kernel's business" (`Interfaces.swift:62-72`).
- The netmask becomes a prefix by **counting its leading 1 bits**: `255.255.255.0` is `/24` (`Interfaces.swift:162-168`).
- **Point-to-point** interfaces (a VPN, a tethered phone) have no useful netmask, so they become a **`/32`**, one single address. To sweep one, name a range yourself (`Interfaces.swift:21-23`).
- No IPv4 interface up at all? That's a clear error: "No IPv4 interface is up on this machine." (`Interfaces.swift:84-86`).

::: word
New word: linked list

A **linked list** is a chain of cards where each card says where the next one is. The last card points to `nil`. You walk it from the head, one card at a time.
:::

## A MAC address, byte by byte

![A sockaddr_dl holds the interface's name and then its MAC. Where the MAC starts depends on the name's length.](figures/08-sockaddr.svg)

- An `AF_LINK` card's address isn't a `sockaddr_in`. It's a **`sockaddr_dl`** ("dl" for data link).
- Its size **varies**. The interface's name sits inside it, so the MAC starts at **byte 8 + the name's length** (`Interfaces.swift:179-187`).
- It may also be **unaligned**. So Zhen never casts the pointer to a struct. It reads single bytes at known offsets (`Interfaces.swift:171-178`).
- Only a 6-byte link address counts as a MAC (`Interfaces.swift:181`).

::: word
New words: MAC address, `sockaddr_dl`

A **MAC address** is a network card's hardware ID: six bytes, like `a4:83:e7:12:34:56`. It only travels on the local network. A **`sockaddr_dl`** is the address card for that layer. It holds an interface's index, name and MAC.
:::

## On the Mac: follow the default route

![On the Mac, Zhen dumps the routing table, finds the route to 0.0.0.0 via a gateway, and turns its interface index into a name.](figures/08-route.svg)

1. Ask the kernel for its IPv4 routing table: **`sysctl`** with `CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0` (`Interfaces.swift:144-147`). Chapter 12 opens that box properly.
2. Find the route that is **up**, goes **via a gateway**, and leads to **`0.0.0.0`**, which means "everywhere else" (`Interfaces.swift:148-157`).
3. That route names its interface by **index**. **`if_indextoname`** turns the index into a name like `en0` (`Interfaces.swift:99-108`).
4. Use the interface with that name.

- The table can grow between the call that asks "how big?" and the call that fills it. So the buffer gets 4 KB to spare, and a short read is retried (`RouteMessages.swift:229-253`).
- **No default route?** Then the first interface wins, because "an air-gapped LAN is a legitimate thing to scan" (`Interfaces.swift:90-98`).
- The opposite call, **`if_nametoindex`**, is used too: to keep Bonjour on the scanned interface (`MDNSBrowser.swift:104`, chapter 9) and to set an IPv6 address's scope (`ICMPv6Socket.swift:173`).

::: word
New word: default route

The **default route** is the kernel's rule for "everywhere else, go this way". The interface it points out of is the one that leads to your real network.
:::

## On the iPad: rank by name

![With no routing table, the iPad ranks en* first, then anything else, then cellular, VPN and hotspot interfaces. And iOS hides every MAC.](figures/08-ipad.svg)

- The iPadOS SDK has **no `<net/route.h>`**, so the routing table can't be read the Mac's way (`Interfaces.swift:120-121`).
- "The first one" isn't safe either: on a cellular iPad, `pdp_ip0` has an address too.
- So `preferredWithoutRoutes` ranks interfaces by **name** (`Interfaces.swift:130-140`):
  1. **`en*`**. Wi-Fi is `en0`; a USB Ethernet adapter is a later `en`.
  2. **Anything else.**
  3. **Last**: `pdp_ip*` (cellular), `utun*` and `ipsec*` (VPN), `bridge*` (Personal Hotspot).
  - On a tie, the kernel's own order wins.
- **Why not ask `NWPathMonitor`?** It answers through a callback, and "waiting for one inside this synchronous call is a blocked thread on the cooperative pool" (`Interfaces.swift:127-129`).

```swift
func rank(_ name: String) -> Int {
    if name.hasPrefix("en") { return 0 }
    for prefix in ["pdp_ip", "utun", "ipsec", "bridge"] where name.hasPrefix(prefix) {
        return 2
    }
    return 1
}
return candidates.min { rank($0.name) < rank($1.name) } ?? candidates[0]
```

[`Interfaces.swift:131-139` @ 0.9.0 (comment trimmed)]{.src}

- **iOS hides MACs.** Every interface reports `02:00:00:00:00:00`. That's "a placeholder, not a hardware address", so Zhen drops it. Otherwise every iPad would share one identity (`Interfaces.swift:189-192`).

::: iphone
📱 On iPhone & iPad

- ✅ `getifaddrs`, `freeifaddrs`, `if_nametoindex` and `if_indextoname` are all there and work the same.
- ❌ **The routing table.** There's no `<net/route.h>`, so the default route is guessed by name instead (`Interfaces.swift:113-115`).
- ❌ **A real MAC.** iOS reports `02:00:00:00:00:00` for every interface, and Zhen drops it.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **"The first interface that's up."** It's wrong on a machine with "a VPN, a container bridge, a Thunderbolt link and a phone tethered over USB" (`Interfaces.swift:4-8`).
- **Casting a `sockaddr_dl`.** It's variable-length and may be unaligned. Read bytes at offsets.
- **Forgetting `freeifaddrs`.** The chain belongs to your app. `defer` frees it on every exit.
- **Believing iOS's MAC.** It's the same placeholder on every device.
- **Refusing to run without internet.** No default route is a normal, scannable network.
:::

::: honest
🔍 Honest note: "sdl_len bounds the record"

The safety comment in `hardwareAddress` says the record's own length field (`sdl_len`) bounds the read (`Interfaces.swift:172-174`). The next lines read up to `max(sdl_len, MemoryLayout<sockaddr_dl>.size)` bytes instead (`Interfaces.swift:176-178`). So when `sdl_len` is smaller than the struct, the bound used is bigger than the record.
:::

::: remember
🧠 Remember

- `getifaddrs` gives a **chain of cards**. Keep the IPv4 cards that are up, running and not loopback, then free the chain.
- The right interface is where the **default route** points. Mac: read the routing table. iPad: rank by name.
- A MAC comes from a `sockaddr_dl`, **read byte by byte**. On iOS it's a placeholder.
:::
