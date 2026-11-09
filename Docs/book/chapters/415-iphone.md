# 15 · What your iPhone gets

![Same engine. The iPhone gets the half that needs no crown: sockets, yes; BPF and the helper, no.](figures/15-hero.svg)

::: short
The short version

- zhen-core builds for iOS and iPadOS. The phone gets the **unprivileged half**: ping, TCP and UDP ports, banners, TLS, Bonjour and NetBIOS names.
- It does **not** get BPF, the routing socket, the ARP table, real MAC addresses, the helper, SSDP or background scanning.
- The split happens in **one place**: an `#if os(macOS)` fork inside `DarwinScanner.make`.
- What's missing is **left out, not complained about**. The engine just doesn't claim it.
- The iOS build is real: a CI job builds it for a device and runs the engine's tests on an iPad simulator.
:::

## Mac vs iPhone, row by row

![What runs where. Green: works. Grey: built, but switched off. Red: not built for iOS at all.](figures/15-compare.svg)

- **Top half, same on both.** Everything above the dashed line uses plain BSD sockets, `dns_sd` and Network.framework, which iOS gives every app.
- **SSDP is the odd one.** The code is there. It's switched off, because its multicast send needs an entitlement Apple hands out on request (`com.apple.developer.networking.multicast`).
- **Bottom half, Mac only.** Each red row needs something the iOS SDK leaves out:
  - **ARP sweep, SYN scan, fingerprint**: BPF. The SDK has no `<net/bpf.h>`.
  - **MACs and vendors**: the ARP table. No `<net/route.h>`, and the sandbox hides the cache anyway.
  - **Default route**: also `<net/route.h>`. The iPhone ranks interfaces by name instead: `en*` first, then anything else, then cellular, VPN and hotspot (`Interfaces.swift:118-140`).
  - **Own MAC**: iOS reports `02:00:00:00:00:00` for every interface, so Zhen drops it rather than give every phone the same identity (`Interfaces.swift:189-192`).
  - **Helper**: a launch daemon behind a Mach service. iOS has neither.
  - **Background**: iOS suspends the app. So zhen-ios keeps the screen awake while a scan runs (`zhen-ios/Zhen/Platform/IdleTimer.swift:9-18`, switched on at `zhen-ios/Zhen/App/ScanHost.swift:16`).

::: word
New word: entitlement

An **entitlement** is a signed permission slip baked into an app. Some (like multicast networking) Apple must approve before you can ship them. Without the slip, the kernel or the system simply says no.
:::

## The fork in the road

![Every platform walks the same first three stones. Then the road splits on #if os(macOS).](figures/15-fork.svg)

`DarwinScanner.make` is where a scanner gets put together (`DarwinScanner.swift:72-231`).

1. **Same on every platform:**
   1. Raise the ticket limit: `raiseDescriptorLimit()` (`:83`, chapter 2).
   2. Turn the tickets into a budget: `ConcurrencyBudget.fromDescriptorLimit` (`:84`).
   3. Find the interface, and fail early if there isn't one (`:87-90`, chapter 8).
2. **`#if os(macOS)`** (`:96-192`):
   - **Try** to open a capture device, rather than asking "am I root?" (`:112-113`).
   - Opened: SYN replaces connect for ports, and discovery becomes ARP sweep **plus** ICMP, because "root must never find fewer" (`:177-178`).
   - Refused: the ICMP sweep alone.
3. **`#else`**, iPhone and iPad (`:193-218`): nothing to attempt. ICMP sweep, connect with banners, names without SSDP. Asking for SYN throws.

> "Which engines exist is decided by attempting, never by asking who we are" (`DarwinScanner.swift:97`).

```swift
if portScanType == .syn {
    throw PlatformError.unavailable(
        "--scan-type syn needs a packet-capture device, and iPadOS has none. "
        + "Use --scan-type connect, which is what runs here anyway."
    )
}
let discovery: any HostDiscovery = unprivileged
let naming = DarwinNameResolver(usesSSDP: false)
```

[`DarwinScanner.swift:207-217` @ 0.9.0 (trimmed)]{.src}

## Quiet about what's missing

![Don't nag on every scan. Claim only what really runs, and there's nothing to skip.](figures/15-quiet.svg)

On a phone, "no ARP table" isn't a problem. It's just how phones are. A warning on every scan teaches you to skip the warnings, including the one that matters. So Zhen reports **capabilities not claimed** (`IPADOS.md:32-45`):

- **`EngineCapabilities`** is a set of flags such as `icmpSweep`, `connectScan` and `neighborTable` (`Engines.swift:40-77`). An engine lists only what it does.
- **The ICMP sweep drops `.neighborTable`** when its cache says `isReadable == false` (`ICMPSweep.swift:86`), and then never reads or watches the table (`:194`).
- **`UnavailableNeighborCache`** is that cache: `isReadable` is `false`, and an accidental read throws instead of looking like an empty network (`PlatformSeam.swift:139-153`).
- **`SystemNeighborCache.current`** picks the right cache for the platform, in one place.
- **SSDP is switched off, not left to fail.** A source that never ran can't be blamed later as "went quiet".

```swift
public static var current: any NeighborCache {
    #if os(macOS)
    DarwinNeighborCache()
    #else
    UnavailableNeighborCache(
        reason: "iPadOS does not let an app read the system's neighbour table."
    )
    #endif
```

[`SystemNeighborCache.swift:14-21` @ 0.9.0]{.src}

On an iPhone the Diagnostics screen's engine line reads `icmp_sweep, connect_scan, banner_probe`. Nothing more, and no complaint.

::: word
New word: degradation

A **degradation** is Zhen's word for "something went wrong and the result is less than complete". It travels in the scan's report. Normal absences, like the iPhone's missing ARP table, are deliberately **not** degradations.
:::

## How the iPhone build exists at all

![Three things make it real: the manifest names iOS, the BPF shim is empty there, and CI builds and tests it.](figures/15-build.svg)

1. **The manifest** lists both platforms: `platforms: [.macOS("15.6"), .iOS(.v26)]` (`Package.swift:76`). SwiftPM has no separate iPadOS; `.iOS` covers both.
2. **The BPF shim is empty on iOS.** Its header is wrapped in `#if defined(__APPLE__) && TARGET_OS_OSX` (`CBPFShim.h:38`), because `__APPLE__` alone is also true on iOS, whose SDK has no `<net/bpf.h>`.
3. **CI job `tool-ipados`** builds `ZhenScan` for `generic/platform=iOS` and runs the core and engine tests on an iPad simulator (`.github/workflows/ci.yml:178-223`).

Every `#if os(macOS)` in `Sources/`, and what iOS loses at each:

| File | What iOS loses |
|---|---|
| `BPFDevice.swift:41`, `BPFBuffer.swift:41`, `BPFFilter.swift:26`, `CaptureSource.swift:26` | the capture device, its buffer walker and its filter |
| `BPFSweep.swift:49` | the layer-2 ARP sweep |
| `SYNScan.swift:40` | the half-open SYN port scan |
| `OSFingerprintProbe.swift:36`, `FingerprintingPortScan.swift:18` | OS fingerprinting |
| `BPFAcquisition.swift:31` | opening and configuring `/dev/bpf*` |
| `HelperClient.swift:21` | talking to the privileged helper |
| `zhen-helper/main.swift:44` | the helper itself (builds to a stub that exits 69) |
| `NeighborTable.swift:10`, `RouteMessages.swift:32` | the ARP table and the routing socket parser |
| `SystemNeighborCache.swift:15` | the real neighbour cache (gets `UnavailableNeighborCache`) |
| `Interfaces.swift:97`, `:142` | the default route (gets the name ranking) |
| `DarwinScanner.swift:96`, `:233` | the privileged composition and its notice |
| `PermissionAdvice.swift:20` | Mac wording (gets the iPad Settings path) |
| `ScanRunner.swift:436` | the `ZHEN_CAPTURE` switch (always `.directOnly`) |
| `zhen/Platform/ScannerFactory.swift:17`, `:78` | the command line's engine (no CLI on iOS) |

Plus one C gate: `CBPFShim.h:38` (`TARGET_OS_OSX`).

::: iphone
📱 On iPhone & iPad

- ✅ ICMP sweep, TCP connect with banners and TLS, UDP ports, Bonjour, NetBIOS, history.
- ✅ A SYN request fails loudly instead of quietly running connect (`DarwinScanner.swift:207-212`).
- ⚪️ SSDP: built, switched off until the app holds the multicast entitlement.
- ❌ ARP sweep, SYN, fingerprint, ARP table, MACs, vendors, default route, own MAC, helper, background scans.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **`__APPLE__` isn't "Mac".** It's true on iOS too. The shim tests `TARGET_OS_OSX` instead (`CBPFShim.h:32-33`).
- **`canImport(Darwin)` isn't "Mac" either.** The iOS SDK is Darwin. The CLI and helper gate on `os(macOS)` for exactly this reason (`ScannerFactory.swift:14-16`, `zhen-helper/main.swift:42-43`).
- **The first interface isn't safe on a cellular iPad.** `pdp_ip0` has an address too, hence the ranking by name (`Interfaces.swift:121-122`).
- **A claimed capability that never runs is a lie.** The study withdrew a finding over exactly that, which is why the sweep's descriptor depends on `isReadable` (`ICMPSweep.swift:79-81`).
:::

::: remember
🧠 Remember

- The iPhone gets the **unprivileged half**: sockets yes, BPF and the routing socket no.
- One fork, `#if os(macOS)` in `DarwinScanner.make`, decides the composition.
- Normal absences are **not claimed** rather than complained about.
:::
