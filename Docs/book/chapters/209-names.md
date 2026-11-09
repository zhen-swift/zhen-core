# 9 · What's your name? Bonjour, NetBIOS and SSDP

![Three ways to ask a device its name: Bonjour and SSDP shout to everyone, NetBIOS asks one host at a time.](figures/09-hero.svg)

::: short
The short version

- An address like `192.168.1.31` means nothing to a person. "Living Room" does. This stage turns addresses into **names**.
- **Bonjour** (mDNS) and **SSDP** (UPnP) **shout** a question at the whole network, at the same time. **NetBIOS** then asks the still-unnamed hosts **one by one**.
- Bonjour goes through **`dns_sd`**, a C library that talks to a system helper, **mDNSResponder**. Its replies arrive as C callbacks.
- Every answer is checked: NetBIOS replies need our random ID, and an SSDP device may only describe **itself**.
- Apple asks permission first. Bonjour types must be listed in **`Info.plist`**, and the **Local Network** permission must be granted.
:::

## Who asks, and when

![Bonjour and SSDP run side by side on 70% of the stage each; NetBIOS gets the rest, for unnamed hosts only.](figures/09-budget.svg)

1. **Bonjour and SSDP together.** Both shout at the whole network, use different sockets and "contend for nothing", so they run **at the same time**, each on **70%** of the stage's time (`NameResolver.swift:9-13`).
2. **NetBIOS last.** It's "the weakest source on the list": uppercase, 15 characters, often made up by a manufacturer. So it only asks the hosts the first two **couldn't** name, in the remaining **30%** (`NameResolver.swift:15-19`).
3. **Stop when it goes quiet.** A browse never ends by itself, because nobody knows how many devices exist. So Bonjour stops once answers have started and then nothing new has come for **0.7 s** (`NameResolver.swift:21-31`, `NameResolution.swift:108`).

- The whole stage gets **40%** of the scan's remaining time, but never less than **1.5 s** or more than **4.5 s** (`NameResolution.swift:48-83`).
- This Mac's own Bonjour records point to `127.0.0.1`. Zhen moves them to the Mac's real address, or its own name would land on an address that's in no report (`NameResolver.swift:82-84`).
- **A denied permission returns nothing, not an error.** In the code's capitals: "DENIAL RETURNS ZERO RESULTS RATHER THAN AN ERROR" (`NameResolver.swift:154-157`). Chapter 10 shows how Zhen guesses that.

## Bonjour through `dns_sd`

![Zhen sends Browse, then Resolve, then GetAddrInfo to mDNSResponder over one shared connection. Each reply triggers the next question.](figures/09-dnssd.svg)

Bonjour lookups aren't done by Zhen's own sockets. **mDNSResponder**, a system helper, does the multicast talking for every app. `dns_sd` is the C library an app uses to ask it.

1. **One connection for everything.** `DNSServiceCreateConnection` once, then `DNSServiceSetDispatchQueue` so replies arrive on Zhen's serial queue (`MDNSBrowser.swift:524-533`). Seventeen service types share one socket "rather than seventeen sockets" (`MDNSBrowser.swift:21-23`).
2. **Browse** each type, like `_airplay._tcp`. A reply names a service: "Living Room" (`MDNSBrowser.swift:547-557`).
3. **Resolve** that name, from inside the browse reply. The answer is a host name and a TXT record (`MDNSBrowser.swift:660-676`).
4. **GetAddrInfo** for that host, IPv4 only. The answer is the address (`MDNSBrowser.swift:709-723`).

All three calls carry **`kDNSServiceFlagsShareConnection`**, which means "use the shared connection".

- **Why not Apple's newer `NWBrowser`?** "IT RETURNS NO IP ADDRESS". Getting one would mean a connection per service per device (`MDNSBrowser.swift:8-17`).
- **Replies are C callbacks.** A `@convention(c)` function can't capture anything and can't `await`. So the Swift object travels through the callback's `void *context`: `Unmanaged.passRetained` going in, `fromOpaque` coming back (`MDNSBrowser.swift:28-33`, `:539`, `:789`).
- **The serial queue is the lock.** Every field of the session is touched only on that one queue, "so the queue is the isolation domain" (`MDNSBrowser.swift:37-48`).
- **Copy C strings at once.** A string handed to a callback "is only guaranteed for the duration of the call" (`MDNSBrowser.swift:776-780`).

```swift
private let mdnsBrowseReply: DNSServiceBrowseReply = {
    _, flags, interfaceIndex, errorCode, serviceName, regtype, replyDomain, context in
    guard let context = unsafe context else { return }
    let session = unsafe Unmanaged<MDNSSession>.fromOpaque(context).takeUnretainedValue()
```

[`MDNSBrowser.swift:783-789` @ 0.9.0 (comments trimmed)]{.src}

`MDNSBrowser.swift` is where Swift meets C the most: **72** lines marked `unsafe`, more than any other file in the package (chapter 2 explains the marker).

::: word
New words: mDNS, Bonjour, daemon

**mDNS** (multicast DNS) lets devices answer "who's called that?" on the local network with no server. **Bonjour** is Apple's name for mDNS plus service discovery. A **daemon** is a program the system keeps running in the background; **mDNSResponder** is the one that speaks Bonjour for every app.
:::

::: word
New words: callback, `void *context`

A **callback** is a function you hand to a library so it can call you back later. A C callback gets one spare pointer, **`void *context`**, to say "this is about *that* object". `Unmanaged` is how Swift turns an object into that pointer and back.
:::

## NetBIOS: one question per host

![The question asks for "*", spelled CK and thirty A's. The answer lists names; the unique one is the machine, the group one is the workgroup.](figures/09-netbios.svg)

- **NBSTAT** is the whole protocol: one **50-byte** datagram to UDP port 137, one reply listing the names the machine has registered (`NetBIOSProbe.swift:3-4`).
- It names what the others miss: Windows PCs without Bonjour, Samba NAS boxes, old devices.
- **One socket** for every host, bound to an ephemeral port, not to 137, so it doesn't collide with Samba (`NetBIOSProbe.swift:17-19`, `:71-74`). It's chapter 7's **bound** shape.

Step by step:

1. Give each host its own **random transaction ID** (`NetBIOSProbe.swift:112-116`).
2. Send round 1 to every host. Wait 250 ms. Send round 2 to those that didn't answer (`NetBIOSProbe.swift:144-156`).
3. Listen for up to 500 ms more, and stop the moment everyone has answered (`NetBIOSProbe.swift:158-164`).
4. **Stop the socket first, then wait for the reader.** The other order threw away replies already sitting in the buffer (`NetBIOSProbe.swift:166-176`).

- **First-level encoding.** Each byte of the name becomes two letters: its high half plus "A", then its low half plus "A". So `*` becomes `CK`, and its 15 padding zeros become 30 `A`s (`NetBIOSProbe.swift:203-207`).
- **Machine or workgroup?** A name with the **group** flag is the workgroup. "Confusing them names every machine in an office `WORKGROUP`" (`NetBIOSProbe.swift:293-297`).
- **No forged names.** A reply must come from an address we asked **and** carry that address's ID. Without that, any host could "attach a name of its choosing to a real device" (`NetBIOSProbe.swift:98-111`).
- **Samba's MAC is all zeros.** That's treated as "no MAC", not as the address `00:00:00:00:00:00` (`NetBIOSProbe.swift:320-324`).

```swift
for byte in raw {
    encoded.append(0x41 + (byte >> 4))
    encoded.append(0x41 + (byte & 0x0F))
}
```

[`NetBIOSProbe.swift:235-238` @ 0.9.0]{.src}

## SSDP: shout, then fetch carefully

![The M-SEARCH must leave through the scanned interface, not the VPN. A LOCATION is fetched only if it is plain http, a numeric address, and the sender's own.](figures/09-ssdp.svg)

Televisions, printers, consoles and NAS boxes often speak **UPnP** and never Bonjour (`SSDPProbe.swift:3-6`). Two steps:

1. **Shout.** Send an **M-SEARCH** to the multicast group `239.255.255.250`, port 1900. Every UPnP device answers with a **`LOCATION:`** URL.
2. **Fetch.** Download that URL, an XML file, and read `<friendlyName>` and `<modelName>`.

About 60% of SSDP's time is for listening and 40% for fetching (`SSDPProbe.swift:25-33`).

**Shouting out of the right door.** The socket is chapter 7's bound shape, plus four options (`SSDPProbe.swift:518-547`):

- **`SO_REUSEADDR`**, to share the address with other listeners.
- **`IP_MULTICAST_IF`** = the interface's address. "Binding the address alone is NOT enough." Without it, a Mac with a VPN sends the search **down the tunnel**, and "the responses describe somebody else's printers" (`SSDPProbe.swift:14-23`, `:527-535`).
- **`IP_MULTICAST_TTL` = 2**, so the search stays on this network.
- **`IP_MULTICAST_LOOP` = 0**, so it doesn't hear its own echo.

The search is sent **three times, all early**, then the socket only listens. An earlier version resent every 250 ms, "a multicast storm this tool has no business creating" (`SSDPProbe.swift:127-140`).

```swift
var multicastInterface = in_addr(s_addr: interface.address.raw.bigEndian)
// SAFETY: setsockopt reads one in_addr from storage we own and sized.
guard unsafe setsockopt(descriptor, IPPROTO_IP, IP_MULTICAST_IF,
                        &multicastInterface, socklen_t(MemoryLayout<in_addr>.size)) == 0
else { return "setsockopt(IP_MULTICAST_IF)" }
```

[`SSDPProbe.swift:531-535` @ 0.9.0]{.src}

**Fetching carefully.** A `LOCATION` is a string any device on the network can send, even unasked. Fetched blindly, it could point at `http://127.0.0.1:…` or `file:///…/.ssh/id_rsa` (`SSDPProbe.swift:333-343`). So, before any fetch (`SSDPProbe.swift:350-387`):

1. **`http` only.** Not `file`, not `ftp`, not even `https`.
2. **A numeric IPv4 address**, never a name. Looking up a name would block, and "a name is also the easiest way to point rule 3 somewhere else".
3. **The address must be the sender's own.** "A device may describe ITSELF and nothing else."

- **No redirects.** `URLSession` follows them by default, so a delegate refuses each one (`SSDPProbe.swift:421-424`, `:494-508`).
- **256 KB at most**, counted *while* downloading, not after (`SSDPProbe.swift:314-321`, `:389-411`).
- A refused `LOCATION` shows up in the report, not just in a log (`SSDPProbe.swift:206-220`).

::: word
New words: multicast, UPnP, SSDP

**Multicast** sends one datagram to a group address, and every device that joined the group gets it. **UPnP** is a family of "plug and play" protocols for TVs, printers and routers; **SSDP** is its discovery part.
:::

::: word
New word: SSRF

**SSRF** (server-side request forgery) is tricking a program into fetching a URL *you* chose, with *its* access. `LOCATION` is an invitation to try, which is why the three rules exist.
:::

## Permission slips: `Info.plist`

![An app lists every Bonjour type in its Info.plist and asks for Local Network access. The command line has no bundle, so the linker sews an Info.plist into the binary.](figures/09-plist.svg)

- **Every Bonjour type must be declared.** An app lists them under `NSBonjourServices` in its `Info.plist`. A type that's browsed but not listed "returns nothing, silently" (`zhen-ios/Scripts/generate-bonjour-services.sh:5-8`).
- So nobody types the list by hand. It comes from **`BonjourVocabulary.browsedTypes`** in ZhenCore (`BonjourVocabulary.swift:91`), and zhen-ios generates its `Info.plist` from it with `Scripts/generate-bonjour-services.sh`.
- **The Local Network permission** is asked for the first time the app probes the network.
- **The command line has no bundle.** Without one, "the Local Network grant attaches to the terminal that launched the binary". So the linker sews an `Info.plist` straight into the `zhen` binary, with `-sectcreate __TEXT __info_plist` (the root `Package.swift:169-192`).

::: word
New words: `Info.plist`, bundle

An app is a folder, a **bundle**, and its **`Info.plist`** is the label on the folder: its name, ID and the permissions it asks for. A bare command-line binary is a single file with no folder, so it has no label unless one is sewn in.
:::

::: iphone
📱 On iPhone & iPad

- ✅ **Bonjour** works, through the same `dns_sd`. It needs every type in `NSBonjourServices` and the **Local Network** permission.
- ✅ **NetBIOS** works. It's one unicast datagram per host.
- ⚪️ **SSDP is switched off.** An M-SEARCH is a multicast send, and iOS allows that only to apps holding the managed `com.apple.developer.networking.multicast` entitlement. The iPad builds `DarwinNameResolver(usesSSDP: false)`, so SSDP is never listed as a source that went quiet (`DarwinScanner.swift:202-205`, `:217`).
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Blaming the permission for a restart.** Most `dns_sd` errors arrive later, through a callback. When mDNSResponder restarted (connecting a VPN does it), an earlier version swallowed the error, and the silence "was then handed to the denial heuristic". "We sent people to change a setting that was never the problem" (`MDNSBrowser.swift:229-239`).
- **Freeing twice.** Freeing the shared connection frees every operation on it, "so walking the table and deallocating each one would be a double free" (`MDNSBrowser.swift:598-601`).
- **Waiting on mDNSResponder from the pool.** Setup used to be a `queue.sync` on a cooperative-pool thread. A stuck responder then stuck the scan (`MDNSBrowser.swift:157-166`).
- **An actor for callbacks.** A C callback can't `await`, so reaching an actor meant an unstructured `Task`, and sightings that finished just before the deadline were dropped (`MDNSBrowser.swift:351-366`).
- **Cancelling the reader first.** It threw away replies already in the buffer. Stop the socket, then let the reader finish (`NetBIOSProbe.swift:166-176`).
- **Multicast down the tunnel.** Bind the address *and* set `IP_MULTICAST_IF`.
:::

::: honest
🔍 Honest note: `start()` is not synchronous

The comment says "Synchronous, because the caller needs to know whether Bonjour is reachable… Returns false when the connection could not be created" (`MDNSBrowser.swift:514-518`). But `start()` returns nothing, and does all its work later, inside `queue.async` (`MDNSBrowser.swift:519-520`). A failure is reported through the stream instead, as the call site says (`MDNSBrowser.swift:157-170`).
:::

::: remember
🧠 Remember

- Bonjour and SSDP **shout together**; NetBIOS **asks the leftovers**, one by one.
- Bonjour is `dns_sd` → **mDNSResponder**: Browse, Resolve, GetAddrInfo, over one shared connection, with C callbacks on one serial queue.
- **Check every answer**, send multicast out of the **right door**, and list your Bonjour types in **`Info.plist`**.
:::
