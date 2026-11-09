# 6 · Knocking on doors: the TCP connect scan, banners and TLS

![Knock on a port and you get one of three answers: open, closed or filtered.](figures/06-hero.svg)

::: short
The short version

- To find out whether a TCP port is open, Zhen just **tries to connect**, the way any app would. That needs no privilege.
- The connect is **non-blocking**: Zhen knocks, walks away, and lets the kernel ring back.
- The three answers stay three: **open** (it connected), **closed** (the host sent a RST, `ECONNREFUSED`) and **filtered** (silence).
- Zhen then asks the open ports **what** they are, in three ways: listen for a greeting, send an HTTP `HEAD`, or read the TLS certificate.
- A service is **never named from its port number**, only from what it said.
:::

## One knock, step by step

![Five steps: get a ticket, make it non-blocking, knock, wait for the callback, read the verdict.](figures/06-connect.svg)

1. **`socket(family, SOCK_STREAM, IPPROTO_TCP)`** gets one ticket for one port on one host (`TCPConnectScan.swift:176`).
2. Make it **non-blocking** (chapter 4) and set **`SO_LINGER`** (next section).
3. **`connect()`**. A non-blocking connect returns `-1` with `errno = EINPROGRESS` straight away. That means "I've knocked, and I'll tell you later".
4. **Wait until the socket is writable.** A `DispatchSource` (kqueue underneath) rings when the handshake ends, and a timer rings if it doesn't (`Readiness.swift:90-141`).
5. **`getsockopt(SO_ERROR)`** reads how it went. It's read on the readiness queue, *before* the ticket is closed (`Readiness.swift:107-116`).

Sometimes `connect` doesn't need step 4. It can succeed at once (loopback), or fail at once with some other `errno`. Both are decided on the spot (`TCPConnectScan.swift:197-214`).

| What came back | What it means | Zhen says |
|---|---|---|
| `SO_ERROR` is `0` | the handshake finished | **open** |
| `ECONNREFUSED` | the host answered with a RST | **closed** |
| the timer rang first | nothing came back in time | **filtered** |
| anything else, e.g. `EHOSTUNREACH` | trouble on the path, not at the port | **filtered** |

```swift
static func state(for code: Int32) -> PortState {
    switch code {
    case 0: .open
    case ECONNREFUSED: .closed
    default: .filtered
    }
}
```

[`TCPConnectScan.swift:252-258` @ 0.9.0]{.src}

**Closed is good news.** A RST proves the host is **there**. A scanner that prints "not open" for both closed and filtered "throws away the only signal separating a live host behind a firewall from an address with nothing on it" (`TCPConnectScan.swift:16-17`).

::: word
New word: handshake

TCP opens a connection with a **three-way handshake**: SYN ("hello?"), SYN-ACK ("hello!"), ACK ("great"). When it completes, the port is open. A full **connect** scan finishes it; a half-open **SYN** scan stops after step 2 (chapter 13).
:::

::: word
New word: RST

A **RST** (reset) is TCP's "go away". A host sends one when nothing is listening on the port. Your app sees it as `errno = ECONNREFUSED`.
:::

## Hang up rudely: `SO_LINGER`

![A polite close leaves the port parked in TIME_WAIT. Zhen's close sends a RST and frees it at once.](figures/06-linger.svg)

- A normal `close` says goodbye politely. Afterwards the kernel keeps the connection in **TIME_WAIT** for a while, and its local port stays taken.
- A deep scan opens **tens of thousands** of connections. Parked ones "would exhaust the ephemeral port range long before the scan finished" (`TCPConnectScan.swift:186-187`).
- So every scan socket gets `SO_LINGER` set to **on, 0 seconds**. Now `close` sends a RST and forgets the connection at once.

```swift
var linger = linger(l_onoff: 1, l_linger: 0)
_ = unsafe setsockopt(raw, SOL_SOCKET, SO_LINGER, &linger,
                      socklen_t(MemoryLayout<linger>.size))
```

[`TCPConnectScan.swift:188-190` @ 0.9.0]{.src}

::: word
New words: ephemeral port, TIME_WAIT

Every outgoing connection borrows a local **ephemeral port** (a temporary number, typically 49152 and up). **TIME_WAIT** is the cool-down a politely closed connection sits in before that port can be reused.
:::

## Everyone at once

![All host-and-port pairs go into one pool, so a host whose ports are all filtered costs one wait instead of one per port.](figures/06-pool.svg)

- Zhen doesn't loop "for each host, for each port". It builds **one flat list** of every (host, port) pair and hands it to **one worker pool** (`TCPConnectScan.swift:72-76`).
- The pool's width is chapter 2's number, **`min(512, tickets ÷ 4)`**. Each knock holds one ticket while it waits.
- The payoff: a host whose ports are all filtered "costs the same wall clock as one port on it, instead of costing its port count" (`TCPConnectScan.swift:74-75`).
- **Each host learns its own wait.** After a host's first real answer, open or refused, its next ports get a budget from that host's own round-trip times (`TCPConnectScan.swift:268-297`).
- **Only real answers teach.** "A timeout is not a round-trip sample — it is the absence of one" (`TCPConnectScan.swift:289-290`).
- **Ctrl-C invents nothing.** A cancelled knock reports *no* result, never "filtered" (`TCPConnectScan.swift:88-93`).
- **Out of tickets?** If `socket()` itself fails, the port is reported filtered, "rather than invented as closed: we learned nothing about the port" (`TCPConnectScan.swift:177-181`).

## Who's there? Banners and TLS

![Listen for a greeting, then ask with HTTP HEAD, then read the TLS certificate. Name only what the service said.](figures/06-banner.svg)

After the scan, only the **open** ports are asked what they are. Closed and filtered ones have already said all they will (`BannerProbingPortScan.swift:75-77`). Up to **16** conversations run at once, because each holds a ticket for up to a second (`BannerProbingPortScan.swift:35-40`).

Three ways a service identifies itself, cheapest first (`BannerProbe.swift:21-30`):

1. **Listen.** Connect and wait. SSH, SMTP, FTP, POP3, IMAP and VNC speak first, so "no bytes are sent at all" (`BannerProbe.swift:23-25`, `:127-160`).
2. **Ask.** Send `HEAD / HTTP/1.0` and read the `Server:` header (`BannerProbe.swift:113-119`).
3. **TLS.** Do the handshake and read the certificate's **subject**. A printer's self-signed certificate often names its model.

- On the usual TLS ports (443, 993, 8443 and friends) TLS goes **first**. Anywhere else it goes last, "because the handshake costs more than a read that returns nothing" (`BannerProbe.swift:72`, `:85-92`).
- **1.2 seconds** per port at most, and at most **2,048 bytes** kept, because "the far side chooses this number" (`BannerProbe.swift:54-62`).
- Something answered but it isn't recognised? It's reported as `unknown`, with the banner attached for a person to read (`BannerProbe.swift:161-165`).
- A port that says nothing gets **no name**, and that's a correct answer, not a gap to fill with a guess.
- Open ports on **IPv6 aren't asked**, and the report says so: "service identification speaks IPv4 only" (`BannerProbingPortScan.swift:78-94`).

::: word
New word: banner

A **banner** is the first thing a service says about itself, like `SSH-2.0-OpenSSH_9.6`. "OpenSSH" is the product and "9.6" the version.
:::

### TLS without writing TLS

- Listening and asking use plain sockets: `TCPStream`, with the same non-blocking machinery as the knock (`Readiness.swift:220-314`).
- TLS uses **Network.framework**: an `NWConnection` with `NWProtocolTLS.Options`. In the code's words, "a TLS handshake by hand is a protocol implementation and this is a scanner" (`BannerProbe.swift:211-212`).
- The **verify block** is where an app normally decides whether to trust a certificate. Zhen's reads the subject and then **always says yes** (`BannerProbe.swift:228-239`). The question is what the device calls itself, not whether its certificate chain is valid.
- The minimum is **TLS 1.0**, so old printers and cameras still talk (`BannerProbe.swift:240-245`).
- The `.waiting` state counts as a failure. A filtered port looks exactly like it (`BannerProbe.swift:297-300`).

```swift
{ _, trust, complete in
    let certificateTrust = unsafe sec_trust_copy_ref(trust).takeRetainedValue()
    if let leaf = unsafe SecTrustGetCertificateAtIndex(certificateTrust, 0),
       let summary = unsafe SecCertificateCopySubjectSummary(leaf) as String? {
        subject.record(summary)
    }
    complete(true)
```

[`BannerProbe.swift:230-236` @ 0.9.0]{.src}

::: word
New words: certificate subject, verify block

A TLS **certificate** is a server's ID card. Its **subject** is the name on the card. The **verify block** is a callback your app gives TLS to decide "do I trust this card?" Zhen only reads the name.
:::

::: iphone
📱 On iPhone & iPad

- ✅ All of it runs on iPadOS: `socket`, non-blocking `connect`, `SO_LINGER`, kqueue, and Network.framework for TLS. No privilege needed.
- ✅ It's the iPad's **only** TCP port scanner. The faster SYN scan needs BPF, which iPadOS doesn't have (chapter 13). Asking for it there fails with "Use --scan-type connect, which is what runs here anyway" (`DarwinScanner.swift:207-212`).
- ✅ Banners too. The iPad builds `BannerProbingPortScan(base: TCPConnectScanEngine(…))` (`DarwinScanner.swift:213-215`).
- ⚪️ Like every probe of the local network, it needs the **Local Network** permission (chapter 10).
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Lingering.** Without `SO_LINGER {1,0}`, TIME_WAIT eats the ephemeral ports partway through a deep scan.
- **Closing too early.** The ticket is closed only in the readiness source's cancel handler, and `SO_ERROR` is read before that (chapter 4). Close it early and the number can be reissued, and then a filtered port is "reported open, with a sub-millisecond round trip" (`Readiness.swift:50-55`).
- **A fixed wait for every port.** An earlier version took a per-host deadline "and never built an estimator at all" (`TCPConnectScan.swift:47-52`).
- **Counting a timeout as a round trip.** That would teach a host's estimator it is exactly as slow as the budget it was given.
- **Turning Ctrl-C into evidence.** A cancelled probe is silent, not filtered.
:::

::: honest
🔍 Honest note: the "owned descriptor" that isn't

The comment above `probe()` says "The descriptor is an `OwnedDescriptor`… `consuming close()` makes a second close a compile error" (`TCPConnectScan.swift:170-174`). The type exists (`PlatformSeam.swift:502`), but nothing in the package ever builds one. The code holds a raw `Int32` (`TCPConnectScan.swift:176`) and closes it by hand on each early path (`:183`, `:199`, `:208`).
:::

::: honest
🔍 Honest note: `SIGPIPE`

`TCPStream.write` uses plain `write()` (`Readiness.swift:295-306`). Nothing in `Sources` sets `SO_NOSIGPIPE` or ignores `SIGPIPE`; the command line's signal handler watches only `SIGINT` and `SIGTERM` (`SignalHandler.swift:40`). If a service resets the connection before Zhen sends its `HEAD`, `write` fails with `EPIPE` and the kernel also sends the process `SIGPIPE`, whose default action ends it. This was found by reading the code; it hasn't been seen in a run.
:::

::: honest
🔍 Honest note: two names that come from the port

The rule is "a service is never inferred from a port number" (`BannerProbe.swift:11`). Two lines bend it: a `220` greeting is named `ftp` on port 21 and `smtp` everywhere else (`BannerProbe.swift:149`), and a TLS service is named `https` on ports 443 and 8443 and `tls` elsewhere (`BannerProbe.swift:262`).
:::

::: remember
🧠 Remember

- A connect scan **knocks, walks away and lets the kernel ring back**, then reads `SO_ERROR`.
- **Open, closed, filtered**: a RST means someone's home. Never merge closed and filtered.
- Banners name a service only from **what it said**: listen, then ask, then TLS.
:::
