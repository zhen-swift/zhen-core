# 17 · What only a real device can answer

![A simulator runs on the Mac's kernel. Only a real iPhone has the iPhone's sandbox around it.](figures/17-hero.svg)

::: short
The short version

- The iOS **simulator** runs on the **Mac's kernel**. It proves the code builds and is put together right. It can't show what the iPhone's sandbox allows.
- So zhen-ios has a **Diagnostics** screen: six quick checks of the sandbox. None of them sends anything on the network.
- Each check says **as assumed** or **surprise**, and the whole report can be shared as plain text.
- Several questions are **still open** because nobody has run them on a device yet. One of them, a denied Local Network permission, has no good answer even then.
- You can help: run Diagnostics on your device and share the report.
:::

Why isn't the simulator enough?

- The simulator is an app on your Mac. Its "iPhone" makes system calls into **macOS's** kernel, with macOS's rules (`Docs/IPADOS.md:63-65`).
- Example: on the simulator the SSDP multicast send **succeeds**. On a device without the entitlement it shouldn't.
- CI says the same about itself: the `tool-ipados` job "proves the build and the composition, not the iPad sandbox" (`ci.yml:179-183`).

::: word
New word: sandbox

The **sandbox** is the fence the system puts around every iOS app. It decides which files, devices and kernel tables the app may touch. The fence is part of the device, which is why a simulator can't show it.
:::

## Six checks

![Diagnostics runs six checks. Each one makes the same call the engine (or a feature cut from it) would make.](figures/17-checks.svg)

Open it with the toolbar's **Diagnostics** button (a stethoscope). The checks run off the main actor as soon as the sheet appears (`zhen-ios/Zhen/Features/DiagnosticsView/DiagnosticsView.swift:55`).

1. **ICMP socket.** Opens `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` and closes it at once. Expect: opens. The whole sweep depends on it (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:35-46`).
2. **Open-file limit.** Reads `RLIMIT_NOFILE` with `getrlimit`. Expect: at least 256, or port scans run narrow (`:48-64`). The app has usually raised the limit already, at launch.
3. **Routing table.** Asks `sysctl` how big a `NET_RT_DUMP` would be. Readable or not, both count as "as assumed"; the answer is in the bytes or the errno (`:66-76`).
4. **ARP table.** Asks how big the ARP dump would be. Expect: **0 bytes**, or an error. Anything bigger is a surprise (`:78-88`).
5. **en0's MAC.** Walks `getifaddrs` for `en0`'s link address. Expect: the placeholder `02:00:00:00:00:00`, or none (`:90-120`).
6. **Bonjour types.** Compares the app's `NSBonjourServices` with every type the engine browses. Expect: all 17 declared. A missing one "browses to silence" (`:122-135`).

```swift
let rtfLLInfo: Int32 = 0x400  // RTF_LLINFO; <net/route.h> is not in the iOS SDK
let size = sysctlSize([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, rtfLLInfo])
return CapabilityCheck(
  id: "neighborTable", title: .checkNeighborTable,
  outcome: size.map { String(localized: .checkBytes($0)) } ?? describe(errno),
  verdict: (size ?? 0) == 0 ? .asAssumed : .surprise,
```

[`zhen-ios/Zhen/Platform/CapabilityProbe.swift:80-85` @ zhen-ios 793ebb0 (trimmed)]{.src}

- **Why `0x400` by hand?** `RTF_LLINFO` lives in `<net/route.h>`, which the iOS SDK leaves out. The value is copied in so the check can still ask.
- **Only sizes.** Checks 3 and 4 pass no buffer, so the kernel reports how many bytes it **would** return. No table is actually read.

## Telling "denied" from "empty"

![On a Mac, silence plus a full ARP table is a clue. On an iPhone there's no table, so silence could mean either.](figures/17-denied.svg)

- **On a Mac**, the denial check needs a control: probes all silent **and** the ARP table lists devices means "something is most likely blocking this tool" (`LocalNetworkDenial.swift:111-120`).
- **On an iPhone** there's no table, so the count is always 0 and the check can never fire.
- The naming check doesn't help either: naming only runs when the sweep found someone (`ScanRunner.swift:157`).
- So the **only** signal is the empty list: "Nothing answered", with **Scan Again** and **Open Settings** buttons (`zhen-ios/Zhen/Features/DevicesView/DevicesView+EmptyStateView.swift:33-45`). Its text says "usually the Local Network permission, which can't be checked directly".

## Still open

![Seven questions on the shelf. Nobody has opened these jars on a real device yet.](figures/17-open.svg)

From `Docs/IPADOS.md:61-79`, plus one this book adds:

- **Is `NET_RT_DUMP` readable?** If yes, the iPhone could pick its interface from the route, like a Mac. *Check 3 answers it.*
- **Is the ARP dump empty, or real?** If real, MACs and vendors could come back. *Check 4.*
- **How high does `RLIMIT_NOFILE` go?** The connect scan's width comes from it. *Check 2.*
- **What does a denied Local Network permission look like?** No check can tell; only a deliberate denial on a device will show what a better signal could be.
- **Does SSDP fail without the entitlement?** No check covers it, because no check sends anything.
- **The 464-second naming stage.** Once, on the first launch after a simulator's first boot, naming ran 464 s against a 4.5 s budget, with Bonjour silent. It hasn't happened since (`Docs/IPADOS.md:76-79`).
- **An iPhone at all.** `IPADOS.md` says "Nothing here was tried on an iPhone" (`:8`). zhen-ios is now universal: `TARGETED_DEVICE_FAMILY: "1,2"` (`zhen-ios/project.yml:56`).

## How you can help

![Each check is either "as assumed" or a surprise. Share the report as plain text: a surprise is the interesting one.](figures/17-verdict.svg)

On screen a check shows a green dot (as assumed) or a warning dot (surprise). The shared report has one line each, `ok` or `SURPRISE` (`zhen-ios/Zhen/Features/DiagnosticsView/DiagnosticsView.swift:60-67`).

1. Install zhen-ios on a **real** iPhone or iPad (simulators don't count).
2. Allow **Local Network** when asked, and run one scan.
3. Open **Diagnostics** (the stethoscope) and wait for the six checks.
4. Tap **Share** and send the text with a bug report or pull request.
5. For bonus points: turn Local Network **off** in Settings, scan again, and describe what you saw.

::: iphone
📱 On iPhone & iPad

- ✅ Diagnostics runs on both; its titles even say "iPhone" or "iPad" to match.
- ⚪️ Routing table, ARP dump, ticket limit: one Diagnostics run on a device answers each.
- ⚪️ Denied permission, SSDP without the entitlement, the slow first naming run: still unmeasured, and Diagnostics can't answer them.
- ⚪️ iPhone itself: the build targets it; nobody has reported a run yet.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **A browse for an undeclared Bonjour type returns nothing, silently.** It looks exactly like a device that isn't there. The test and check 6 exist for that (`zhen-ios/ZhenTests/AppEnvironmentTests.swift:32-38`).
- **`RLIM_INFINITY` isn't imported into Swift.** The check compares against `Int64.max` instead (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:59-60`).
- **The simulator says yes too easily.** A send that works there may be refused on a device.
:::

::: honest
🔍 Honest note: iPad-only words

`Docs/IPADOS.md` still talks about "an iPad-only host app (`TARGETED_DEVICE_FAMILY = 2`)" and "The iPad app" (`:8`, `:65`), but zhen-ios now targets iPhone and iPad (`zhen-ios/project.yml:54-56`). The engine code is identical either way; only the wording is behind.
:::

::: remember
🧠 Remember

- The simulator proves the **build**, not the **sandbox**.
- Diagnostics: six checks, no packets, **as assumed** or **surprise**, shareable as text.
- On iOS, "nothing answered" can't be told apart from "permission denied". The empty screen is the only hint.
:::
