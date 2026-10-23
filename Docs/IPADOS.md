# The engine on iPadOS

The engine builds for iPadOS and scans from an iPad, without the privileged half. This is
what that leaves, what was cut, and what only a device can still answer. The command line
and the helper are macOS-only and stay that way.

SwiftPM has no iPadOS platform of its own: it is the manifest's `.iOS(.v26)`, and an
iPad-only host app (`TARGETED_DEVICE_FAMILY = 2`). Nothing here was tried on an iPhone.

## What runs

`DarwinScanner.make` assembles the unprivileged composition. It is the same one macOS falls
back to when `/dev/bpf*` will not open, minus the neighbour table and SSDP:

| | iPadOS | Why |
|---|---|---|
| ICMP echo sweep (`ICMPSweepEngine`) | **runs** | An unprivileged `SOCK_DGRAM` ICMP socket opens without privilege |
| TCP connect scan, banners, TLS certificate | **runs** | BSD sockets and Network.framework |
| Bonjour naming (`dns_sd`) | **runs** | Needs `NSBonjourServices` with every type in `BonjourVocabulary.browsedTypes`, and the Local Network permission |
| NetBIOS naming | **runs** | One unicast datagram per host to UDP/137, no broadcast |
| History | **runs** | `HistoryLocation` resolves to the app container's Application Support. Not shared with a command line, because there isn't one |
| Layer-2 ARP sweep, SYN scan, OS fingerprint, `--scan-type syn` | **not built** | No BPF: the iOS SDK has no `<net/bpf.h>` |
| The privileged helper | **not built** | A launch daemon behind a Mach service; iOS has neither |
| Neighbour table and the neighbour watch | **absent** | The SDK has no `<net/route.h>`, and the sandbox does not give an app the ARP cache. So iPadOS has no MAC addresses, no vendor names, and no hosts found only by ARP |
| This device's own MAC | **absent** | iOS reports `02:00:00:00:00:00` for every interface. The engine drops it rather than giving every iPad the same identity |
| SSDP / UPnP naming | **off** | The M-SEARCH is a multicast send, which iOS gives only to an app holding the managed `com.apple.developer.networking.multicast` entitlement |
| Scanning in the background | **no** | iPadOS suspends a backgrounded app. A scan is a foreground act |

Expect fewer hosts than an unprivileged Mac scan of the same network. The neighbour watch
is what finds hosts that answer ARP and ignore echo, and it is gone.

## How the absences are reported

They aren't degradations, because on iPadOS they are the normal state, and a complaint on
every scan trains a reader to skip the list. They show up as **capabilities not claimed**:

- `ICMPSweepEngine.descriptor` drops `.neighborTable` when its cache says
  `isReadable == false`, and the sweep then neither reads nor watches it.
- `UnavailableNeighborCache` (in core, beside `NoIPv6MulticastEcho`) is that cache.
- `SystemNeighborCache.current` picks it on iPadOS and `DarwinNeighborCache` on macOS.
- SSDP is switched off rather than left to fail. A source that never ran is never named as
  one that went quiet, so it can't be blamed on a permission.

The Local Network remedy is worded for iPadOS (`ProbePermissionAdvice.appleLocalNetworkOnIPad`):
Settings › Privacy & Security › Local Network.

## Choosing the interface

macOS reads the default route. Without `<net/route.h>`, iPadOS ranks interfaces by kind
instead (`DarwinInterfaceProvider.preferredWithoutRoutes`):

1. `en*` first. Wi-Fi is `en0`; a USB Ethernet adapter is a later `en`.
2. Then anything unrecognised.
3. Last: cellular (`pdp_ip*`), VPN tunnels (`utun*`, `ipsec*`) and the Personal Hotspot
   bridge (`bridge*`).

`NWPathMonitor` would name the path's interface exactly, but it answers through a callback,
and `primaryInterface()` is synchronous. Waiting for the callback there would block a thread
of the cooperative pool.

## What only a device answers

The simulator runs on the Mac's kernel. It confirms the build and the composition, not the
iPad sandbox. On the simulator, for example, the SSDP send succeeds; on a device without
the entitlement it shouldn't. The iPad app,
[`zhen-ios`](https://github.com/zhen-swift/zhen-ios), has a Diagnostics screen built to
answer these on a device:

- Is `NET_RT_DUMP` readable? If so, the interface could come from the route, as on macOS.
- Is the ARP dump really empty, or does it carry real MACs?
- How far does `RLIMIT_NOFILE` raise? The connect scan's concurrency is derived from it.
- What does a **denied** Local Network permission look like? The macOS denial heuristic
  needs a populated neighbour table as its control (`LocalNetworkDenialHeuristic`). With no
  table it never fires, so iPadOS needs another control signal, and only a deliberate
  denial on a device shows what it could be.
- Does the naming stage hold its budget on a first launch? On the first launch after a
  simulator's first boot it ran 464 s against a 4.5 s budget, with Bonjour silent. Three
  later runs, including a fresh install and a cold boot, took about 3.5 s in all, and it
  has not reproduced.

## Building and testing

```bash
xcodebuild build -scheme ZhenScan -destination 'generic/platform=iOS'
xcodebuild test -scheme zhen-Package -destination 'platform=iOS Simulator,name=iPad Pro 13-inch (M5)' \
  -only-testing:ZhenCoreTests -only-testing:ZhenDarwinTests -skip-testing:…WallClockTests
```

The WallClock suites run afterwards, alone and serially, as on macOS. CI's `tool-ipados`
job is the authority on the exact list.

## The Mac app's distribution decision still holds

`SPEC.md` decides that the Mac app ships unsandboxed with Developer ID, because the
sandbox has no entitlement for BPF. That is unchanged. The iPadOS build doesn't overturn
it; it is what the engine is without that half.
