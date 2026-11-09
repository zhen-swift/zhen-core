# D · Honest notes

![What the docs say, and what the code does. Usually they agree. These are the places they don't.](figures/D-hero.svg)

zhen-core's comments are unusually careful, which is why the few places where they
disagree with the code are worth knowing. Each card says what's claimed, what's true, and
where to look. Every one was checked against tag 0.9.0 (zhen-ios at `793ebb0`).

::: honest
1 · `sudo zhen` never drops root

- **Claimed:** run under `sudo`, open BPF, then "irrevocably drop privileges" with `setgid` and `setuid`, so root lasts only "a handful of startup syscalls" (`SPEC.md:506-520`). The core protocol's comment says that mechanism "lives in the platform target" (`PlatformSeam.swift:462-466`).
- **True:** nothing in `Sources/` calls `setuid`, `setgid` or `seteuid`, and `PrivilegeBroker` (`PlatformSeam.swift:467-470`) has no implementations at all. A `sudo zhen` scan stays root from start to finish, history writes included.
- **Where:** `grep -rn "setuid\|setgid" Sources` is empty.
:::

::: honest
2 · `isPrivileged`, asked and not asked

- **Claimed:** `SPEC.md:545-551` designs a `PrivilegeBroker` with `var isPrivileged: Bool`.
- **True:** the code's stated rule is the opposite: "this type has no `isPrivileged` and takes no opinion. It opens, or it says … why it could not" (`BPFDevice.swift:13-15`; also `DarwinScanner.swift:97-103`). The protocol with `isPrivileged` is still in core (`PlatformSeam.swift:469`), unused.
- **Where:** chapter 11, chapter 15's fork.
:::

::: honest
3 · `OwnedDescriptor` is never made

- **Claimed:** the noncopyable `OwnedDescriptor` wraps every TCP probe's ticket, and "`consuming close()` makes a second close a compile error" (`DarwinPlatform.swift:30-38`; `TCPConnectScan.swift:170-174`).
- **True:** no code in `Sources/` or `Tests/` ever constructs one. The TCP probe holds a raw `Int32` (`TCPConnectScan.swift:176`) and closes it by hand on each path (`:183`, `:199`, `:208`).
- **Where:** `grep -rn "OwnedDescriptor(\|DarwinDescriptor(" Sources Tests` is empty.
:::

::: honest
4 · Is the IP header there or not?

- **Claimed:** on an ICMP `SOCK_DGRAM` socket the IP header "is stripped, and on this machine it is" (`ICMPPacket.swift:100-101`).
- **True:** thirty lines later the same function says the received datagram "still carries the IP header" (`ICMPPacket.swift:143-144`). The code handles both shapes by sniffing the version nibble (`:122-128`), so it works either way; only the comments disagree.
:::

::: honest
5 · `write` can't always report failure

- **Claimed:** `TCPStream.write` "writes a request in full, or reports that it could not" (`Readiness.swift:294-306`).
- **True:** the socket has no `SO_NOSIGPIPE`, and nothing in `Sources/` ignores `SIGPIPE` (the CLI watches only `SIGINT` and `SIGTERM`, `SignalHandler.swift:40`). Writing to a peer that has already reset can raise `SIGPIPE`, which by default ends the process instead of returning `false`. Separately, no socket path retries on `EINTR`; the only `EINTR` loop is the history file lock (`LogHistoryStore.swift:356-359`).
- **Where:** the banner request write, `BannerProbe.swift:117`.
:::

::: honest
6 · The mDNS comments describe an older `start()`

- **Claimed:** `start()` is "Synchronous … Returns false when the connection could not be created" (`MDNSBrowser.swift:514-518`). The browse callback's comment says its context was made "by passRetained in `browse(deadline:)`" (`:786`).
- **True:** `start()` returns nothing and does its work later on a queue (`:519-520`); a failure goes to `unreachable()` (`:526`). The `passRetained` is in `start()` (`:539`), as another comment correctly says (`:618`).
:::

::: honest
7 · `arpSweep`: "no engine sets this today"

- **Claimed:** "No engine sets this today. It is what `BPFDiscoveryEngine` will claim" (`Engines.swift:58`).
- **True:** it does already: `BPFDiscoveryEngine` advertises `[.arpSweep]` and reports it as used when replies arrive (`BPFSweep.swift:63`, `:263`).
:::

::: honest
8 · The Local Network check can't fire on iOS

- **Claimed:** a denied permission shows up as a degradation: silence while the neighbour table is populated (`LocalNetworkDenial.swift:105-125`), with iPad wording ready (`:74-78`).
- **True:** the check needs `neighborEntries > 0` (`:111`). On iOS the table is never read, so it's always 0. The naming check can't step in either, because naming is skipped when the sweep found nobody (`ScanRunner.swift:157`). The iPad remedy text is never shown by this path; the app's empty screen is the only hint (chapter 17).
:::

::: honest
9 · "iPad-only" in the iPad doc

- **Claimed:** "an iPad-only host app (`TARGETED_DEVICE_FAMILY = 2`). Nothing here was tried on an iPhone" (`IPADOS.md:8`), and "The iPad app, zhen-ios" (`:65-66`).
- **True:** zhen-ios is universal: `TARGETED_DEVICE_FAMILY: "1,2"` (`zhen-ios/project.yml:56`), with iPhone strings throughout. Whether anyone has run it on an iPhone is still unrecorded.
:::

::: honest
10 · `ScanRunner`: "constructed once and reused"

- **Claimed:** `ScanRunner` "is constructed once and reused, because building it raises the descriptor limit and reads the interface list" (`ScanRunner.swift:53-58`).
- **True:** zhen-ios builds a new one on every call, on purpose, so a moved iPad scans its current Wi-Fi (`zhen-ios/Zhen/Scanning/LiveScanRunner.swift:7-9`, `:48-50`). That's two builds at launch and two per scan (`zhen-ios/Zhen/Model/NetworkModel.swift:79-80`, `:133`, `:144`). The engine's comment and its main consumer disagree on the contract.
:::

::: honest
11 · `InfoPlistTests` doesn't exist

- **Claimed:** "`InfoPlistTests` pins it" (`zhen-ios/project.yml:62`); "`InfoPlistTests` reads the BUILT app's array" (`zhen-ios/Scripts/generate-bonjour-services.sh:10-12`).
- **True:** there's no such suite. The check is the `bonjourDeclared` test in `zhen-ios/ZhenTests/AppEnvironmentTests.swift:34-38`. It does what the comments promise; only the name is wrong.
:::

::: honest
12 · The helper's button sits behind a locked door

- **Claimed:** the app installs the privileged helper with a button, via `SMAppService` (`04-privileged-helper.md`).
- **True:** the app is "Developer ID signed and not notarized". On any other Mac it is blocked on first open, so "a person who cannot open the app cannot reach the button that installs the helper" (`04-privileged-helper.md:52-63`). The audit lists notarization as never run (`AUDIT.md:66`, finding M3); the release script it names now lives in zhen-app (`AUDIT.md:3-6`).
:::

::: honest
13 · Sequence number or token?

- **Claimed:** "The sequence number and the source address are what identify a reply" (`ICMPPacket.swift:9-11`).
- **True:** twenty lines later, in bold: "The token, not the sequence number, is what identifies a probe" (`ICMPPacket.swift:33-39`). The code matches on the 32-bit token; the file header is older than the fix.
- **Where:** chapter 5.
:::

::: honest
14 · "A `Mutex` over both fields"

- **Claimed:** `ResumeOnce` uses "a `Mutex` over both fields" (`Readiness.swift:363-365`).
- **True:** it's an `NSLock` (`Readiness.swift:367`). Same effect, different lock; only the comment is out of date.
:::

::: honest
15 · "A service is never inferred from a port number"… mostly

- **Claimed:** "**A service is never inferred from a port number.**" (`BannerProbe.swift:11`).
- **True:** two names do come from the port. A `220` greeting is called `ftp` on port 21 and `smtp` everywhere else (`BannerProbe.swift:149`), and a TLS service is `https` on 443 and 8443 but `tls` elsewhere (`:262`). The service is still confirmed by what it says; only its label leans on the port.
- **Where:** chapter 6.
:::

::: honest
16 · "`sdl_len` bounds the record"

- **Claimed:** reading a hardware address, "`sdl_len` bounds the record" (`Interfaces.swift:172-174`).
- **True:** the reader takes the **larger** of `sdl_len` and `sizeof(sockaddr_dl)` (`Interfaces.swift:176-178`), so for a short record it reads past the length the kernel declared.
- **Where:** chapter 8.
:::

::: honest
17 · A six-second ceiling that is four and a half

- **Claimed:** the early stop "is what makes a six-second ceiling affordable" (`NameResolver.swift:28-29`).
- **True:** the naming stage's ceiling is `NameBudget.ceiling = 4,500 ms` (`NameResolution.swift:83`), "set by measurement" (`:61`). The comment predates the measurement.
- **Where:** chapter 9.
:::

::: honest
18 · `helperThenDirect` goes direct first

- **Claimed:** by its name, the app's capture policy asks the helper, then opens directly.
- **True:** it does the opposite, on purpose: "Try a direct open first, then ask the helper" (`CapturePolicy.swift:19-26`), so a `sudo` run never depends on the daemon. The comment explains it; only the case name reads backwards.
- **Where:** chapter 14.
:::

::: honest
19 · The spec still rejects `SMAppService`

- **Claimed:** "**`SMAppService`/`SMJobBless`** … is the correct answer *later*, once the app exists", under "Rejected for now" (`SPEC.md:522-525`).
- **True:** "later" has arrived. The helper is built and registered with `SMAppService` (chapter 14; `04-privileged-helper.md`). The spec is amended in other places but not here.
:::

::: honest
20 · "One method, on purpose"

- **Claimed:** the helper's whole surface is "One method, on purpose" (`HelperProtocol.swift:3`).
- **True:** the protocol has two: `openCaptureDevice` and `helperVersion` (`HelperProtocol.swift:95-119`). The second only reports a version, so the spirit holds: there's still one thing the root process will *do*.
- **Where:** chapter 14.
:::

::: honest
21 · An SSDP search that says it's version 0.3

- **Claimed:** nothing, which is the point. The M-SEARCH introduces itself as `USER-AGENT: Darwin/26 UPnP/1.1 zhen/0.3` (`SSDPProbe.swift:567`).
- **True:** the engine is 0.9.0. Harmless, because devices don't act on it, but it's the one place the tool misstates its own version on the wire.
:::
