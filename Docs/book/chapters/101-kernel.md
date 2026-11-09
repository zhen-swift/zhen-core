# 1 · The kernel in one picture

![The kernel is a castle. Each door is one kind of request: socket, read, close, sysctl, ioctl.](figures/01-hero.svg)

::: short
The short version

- The **kernel** owns the hardware. Your app lives outside its walls, in **user space**.
- The only way in is a **door**: a system call such as `socket`, `read`, `close`, `sysctl` or `ioctl`.
- Apple's kernel is **XNU**. It has three rooms: **Mach**, **BSD** and **IOKit**. Zhen lives almost entirely in **BSD**, the room with the sockets.
- Apple's frameworks (Dispatch, Network, `dns_sd`, Security) sit on top and knock on the same doors.
- The Mac and the iPhone run the **same XNU**. The iPhone's SDK and sandbox just hide some of the doors.
:::

## Two sides of a wall

![Your app can't reach the Wi-Fi chip directly. It asks the kernel through a door.](figures/01-spaces.svg)

- **User space** is where every app runs, Zhen included. The chip won't let code here touch hardware or another app's memory.
- **Kernel space** is where the kernel runs, with full power over the network card, the disk and memory.
- So an app **can't** send a packet by poking the Wi-Fi chip. It asks: "please send these bytes", through a door.
- The kernel checks each request first. That check is where "not allowed" (`EPERM`, `EACCES`) comes from (chapter 2).

Why the wall? If any app could drive the network card, any app could read everyone's traffic. The wall is what lets the kernel say no.

::: word
New word: user space and kernel space

**User space** is the walled-off area where apps run. **Kernel space** is inside the castle. A program crosses from one to the other only through a system call.
:::

## The doors Zhen knocks on

The castle picture at the top of this chapter has five doors. These are the ones Zhen uses most:

| Door | What it asks | Where in this book |
|---|---|---|
| `socket` | "Make me a mailbox." | chapters 3, 5, 6 |
| `read` / `recvmsg` | "Anything arrived?" | chapters 4, 5 |
| `close` | "I'm done with this ticket." | chapters 2, 4 |
| `sysctl` | "Tell me a fact about yourself." | chapters 2, 12 |
| `ioctl` | "Configure this device." | chapter 11 (Mac only) |

Each one is a plain C function. Swift calls it directly from the `Darwin` module.

## Darwin, XNU, and three rooms

![Apple's helpers sit on top. Inside XNU are three rooms; Zhen lives in BSD.](figures/01-xnu.svg)

- **Darwin** is the open-source core of macOS and iOS. Its kernel is called **XNU**.
- XNU is three things glued together:
  - **Mach**: threads, memory, and messages between programs.
  - **BSD**: files, tickets, sockets, `sysctl`. This is the classic Unix layer.
  - **IOKit**: device drivers.
- **Zhen uses BSD almost entirely.** Its sockets are ordinary POSIX sockets.
- Zhen never calls IOKit. It touches Mach only through XPC, to talk to the Mac's privileged helper (chapter 14).

On top of the kernel, Zhen also uses four Apple frameworks. Each one still goes through the same doors:

| Framework | What Zhen uses it for | Where |
|---|---|---|
| **Dispatch** | the "bell" that rings when a socket is ready (kqueue underneath) | `Readiness.swift`, chapter 4 |
| **Network** | TLS connections, to read a server's certificate | `BannerProbe.swift:43`, chapter 6 |
| **`dns_sd`** | Bonjour, through the system's mDNSResponder | `MDNSBrowser.swift:59`, chapter 9 |
| **Security** | reading that certificate | `BannerProbe.swift:45`, chapter 6 |

::: word
New word: POSIX sockets

**POSIX** is the shared standard for Unix-like systems. A **POSIX socket** is the classic `socket()`/`connect()`/`sendto()` interface. Code written against it looks almost the same on macOS, iOS and Linux.
:::

## Same castle, different fence

![The Mac and the iPhone run the same XNU. The iPhone's SDK and sandbox hide some doors.](figures/01-twins.svg)

- The Mac and the iPhone run the **same XNU kernel**, with the same BSD layer.
- On iOS, two things hide parts of it:
  1. **The SDK**, the headers your code compiles against. Some headers simply aren't there.
  2. **The sandbox**, the fence around every iOS app. It blocks some calls that would compile fine.
- What's missing for Zhen:
  - **`<net/bpf.h>`**: no BPF, so no raw packet capture (chapter 11).
  - **`<net/route.h>`**: no routing-socket types, and no ARP table to read anyway (chapter 12).
  - **Launch daemons**: no privileged helper (chapter 14).

Zhen fences those parts off at compile time:

```swift
// macOS only. The iOS SDK has no `<net/route.h>`, and the iOS sandbox does not hand an app
// the ARP table anyway, so on iPadOS the neighbour cache is `UnavailableNeighborCache`.
#if os(macOS)
```

[`RouteMessages.swift:30-32` @ 0.9.0]{.src}

::: iphone
📱 On iPhone & iPad

- ✅ The BSD doors Zhen needs for scanning are all there: `socket`, `read`, `recvmsg`, `close`, `fcntl`, `sysctl`.
- ✅ Dispatch, Network, `dns_sd` and Security are there too.
- ❌ BPF: the iOS SDK has no `<net/bpf.h>`, so every BPF file is `#if os(macOS)` (for example `BPFDevice.swift:41`).
- ❌ The routing socket's header, `<net/route.h>`, is missing. The iOS app even hand-copies one constant from it, `RTF_LLINFO = 0x400` (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:80`).
- ❌ Launch daemons and the privileged helper: the client is `#if os(macOS)` (`HelperClient.swift:21`).
- ⚪️ Whether a device lets an app read the routing table with `sysctl` hasn't been answered yet. Diagnostics checks it (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:66-76`).
:::

::: gotcha
⚠️ Gotchas the code remembers

- **The simulator isn't an iPhone.** It runs on the **Mac's** kernel, so it proves the build, not the sandbox. A multicast send that works on the simulator should fail on a device without the multicast entitlement (`Docs/IPADOS.md:63-65`).
- **A missing header isn't a missing feature.** The kernel underneath is the same; the SDK just doesn't name the door. Whether the door *opens* is a separate question, and only a device answers it.
:::

::: remember
🧠 Remember

- The kernel is a castle; apps stay in **user space** and knock on **doors** (system calls).
- XNU = **Mach + BSD + IOKit**. Zhen lives in **BSD**, plus Dispatch, Network, `dns_sd` and Security on top.
- Mac and iPhone share one kernel. The iPhone's **SDK and sandbox** hide BPF, the routing socket and launch daemons.
:::
