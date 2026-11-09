# B · Syscall cheat sheet

![Every door Zhen knocks on, in one wall.](figures/B-hero.svg)

Every call into the kernel that zhen-core makes, where it makes it, and whether it runs on
each platform. Line numbers are at tag 0.9.0. ✅ runs, ❌ not built, ⚪️ built but unmeasured
on a device.

## Sockets

| Call | What it does | Where in Zhen | Mac | iPhone |
|---|---|---|---|---|
| `socket` | makes a socket and returns its ticket | ICMP `ICMPSocket.swift:81`; TCP probe `TCPConnectScan.swift:176`; banner `Readiness.swift:232`; UDP `UDPProbe.swift:125`; ICMPv6 `ICMPv6Socket.swift:46` | ✅ | ✅ |
| `close` | gives a ticket back | `DarwinPlatform.swift:26`; `ICMPSocket.swift:84`; `TCPConnectScan.swift:183`, `:199`, `:208`; `Readiness.swift:312` | ✅ | ✅ |
| `connect` | TCP: starts the handshake. UDP: fixes the peer, so errors come back | `TCPConnectScan.swift:194`; `Readiness.swift:243`; `UDPProbe.swift:109` | ✅ | ✅ |
| `bind` | pins a socket to a local address | `UDPProbe.swift:91`; `ICMPv6Socket.swift:56` | ✅ | ✅ |
| `sendto` | sends one datagram to an address | `ICMPSocket.swift:250`; `UDPProbe.swift:147`; `ICMPv6Socket.swift:91` | ✅ | ✅ |
| `send` | sends on a connected socket | `UDPProbe.swift:164` | ✅ | ✅ |
| `recvfrom` | receives a datagram and who sent it | `UDPProbe.swift:225`; `ICMPv6Socket.swift:154` | ✅ | ✅ |
| `recvmsg` | receives a datagram plus control messages (the TTL) | `ICMPSocket.swift:324` | ✅ | ✅ |
| `read` | reads bytes from a ticket | banner `Readiness.swift:282`; BPF `BPFDevice.swift:329` | ✅ | ✅ banner, ❌ BPF |
| `write` | writes bytes to a ticket | banner request `Readiness.swift:300`; BPF frame `BPFDevice.swift:295` | ✅ | ✅ banner, ❌ BPF |
| `setsockopt` | sets an option, see the list below | `TCPConnectScan.swift:189`; `ICMPSocket.swift:91`, `:97`, `:104`; `SSDPProbe.swift:525-543` | ✅ | ✅, SSDP's ⚪️ |
| `getsockopt(SO_ERROR)` | "did my `connect` work?", asked once the socket is writable | `Readiness.swift:113`, `:258` | ✅ | ✅ |
| `fcntl` | sets `O_NONBLOCK` on every socket (and `O_APPEND` on the history file) | `DarwinPlatform.swift:140-142`; `BPFAcquisition.swift:277-279`; `LogHistoryStore.swift:652-653` | ✅ | ✅, BPF's ❌ |

The `setsockopt` options:

| Option | Why | Where |
|---|---|---|
| `SO_LINGER` = 0 | close with a reset, so tens of thousands of probes don't pile up in TIME_WAIT | `TCPConnectScan.swift:186-190` |
| `IP_RECVTTL` | deliver each reply's TTL as a control message | `ICMPSocket.swift:91` |
| `SO_RCVBUF`, `SO_SNDBUF` | 1 MiB buffers: a /24 answering at once overflows the default | `ICMPSocket.swift:97`, `:104` |
| `SO_REUSEADDR` | let the SSDP socket reuse its address | `SSDPProbe.swift:525` |
| `IP_MULTICAST_IF`, `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP` | send the M-SEARCH out of the right interface (not a VPN), two hops, without hearing ourselves | `SSDPProbe.swift:533`, `:539`, `:543` |

## Limits, interfaces and tables

| Call | What it does | Where in Zhen | Mac | iPhone |
|---|---|---|---|---|
| `getrlimit` / `setrlimit` | reads and raises the ticket limit | `DarwinPlatform.swift:86`, `:95`, `:98` | ✅ | ✅ |
| `sysctlbyname("kern.maxfilesperproc")` | the kernel's real ticket ceiling | `DarwinPlatform.swift:114` | ✅ | ⚪️ falls back to 1,048,576 if refused |
| `sysctl(PF_ROUTE …)` | dumps the routing table or the ARP table | `RouteMessages.swift:235`, `:245` | ✅ | ❌ (Diagnostics asks only the size) |
| `getifaddrs` | lists interfaces and their addresses | `Interfaces.swift:28`; `ICMPv6Socket.swift:202` | ✅ | ✅ |
| `if_nametoindex` | interface name → number | `MDNSBrowser.swift:104`; `ICMPv6Socket.swift:173` | ✅ | ✅ |
| `if_indextoname` | interface number → name | default route `Interfaces.swift:106`; `ICMPv6Socket.swift:194` | ✅ | ✅, route's ❌ |

## Waiting

| Call | What it does | Where in Zhen | Mac | iPhone |
|---|---|---|---|---|
| kqueue, via `DispatchSource` | calls back when a ticket is readable or writable | ICMP `ICMPSocket.swift:140`; connect `Readiness.swift:94-95`, `:154`, `:186`; UDP `UDPProbe.swift:176`; BPF `BPFDevice.swift:210` | ✅ | ✅, BPF's ❌ |
| `sched_yield` | gives up the CPU for a moment when a BPF write is refused | `BPFDevice.swift:302` | ✅ | ❌ |

## Mac only: BPF and the helper

| Call | What it does | Where in Zhen | Mac | iPhone |
|---|---|---|---|---|
| `open("/dev/bpfN")` | gets a capture device, trying `bpf0`, `bpf1`… | `BPFAcquisition.swift:144` | ✅ root or helper | ❌ |
| `ioctl(BIOCSBLEN)` | sets the buffer size (before binding!) | `BPFAcquisition.swift:182` | ✅ | ❌ |
| `ioctl(BIOCGBLEN)` | reads the size it really got | `BPFAcquisition.swift:187` | ✅ | ❌ |
| `ioctl(BIOCGDLT)` | checks the link type is Ethernet | `BPFAcquisition.swift:192` | ✅ | ❌ |
| `ioctl(BIOCIMMEDIATE)` | deliver packets now, not when the buffer fills | `BPFAcquisition.swift:200` | ✅ | ❌ |
| `ioctl(BIOCSHDRCMPLT)` | "I write my own Ethernet header" | `BPFAcquisition.swift:205` | ✅ | ❌ |
| `ioctl(BIOCSSEESENT)` | don't show us our own frames | `BPFAcquisition.swift:212` | ✅ | ❌ |
| `ioctl(BIOCFLUSH)` | drop whatever arrived during setup | `BPFAcquisition.swift:218` | ✅ | ❌ |
| `ioctl(BIOCSETIF)` | binds the device to an interface | `BPFAcquisition.swift:246` | ✅ | ❌ |
| `ioctl(BIOCSETF)` | installs the filter | `BPFAcquisition.swift:268` | ✅ | ❌ |
| `dup` | copies the ticket the helper passed over XPC, so the app owns its own | `HelperClient.swift:118` | ✅ | ❌ |

## Not syscalls, but doors all the same

| API | What it does | Where in Zhen | Mac | iPhone |
|---|---|---|---|---|
| `DNSServiceCreateConnection`, `…SetDispatchQueue` | one shared line to mDNSResponder, answered on a queue | `MDNSBrowser.swift:524`, `:529` | ✅ | ✅ |
| `DNSServiceBrowse` / `Resolve` / `GetAddrInfo` | find services, then their host, then its address | `MDNSBrowser.swift:549`, `:664`, `:711` | ✅ | ✅ needs `NSBonjourServices` |
| `DNSServiceRefDeallocate` | hangs up | `MDNSBrowser.swift:530`, `:566`, `:611`, `:699`, `:762` | ✅ | ✅ |
| `NWConnection` with TLS | handshake, then read the certificate | `BannerProbe.swift:247-249` | ✅ | ✅ |
| `NSXPCConnection` | the app talks to the helper | `HelperClient.swift:65`, `:150` | ✅ | ❌ |

::: gotcha
⚠️ Gotchas the code remembers

- **The order of the BPF `ioctl`s matters.** `BIOCSBLEN` after `BIOCSETIF` is refused with `EINVAL`, and the filter goes last so nothing arrives unfiltered (`BPFAcquisition.swift:18-28`).
- **`BIOCSETIF` is a macro Swift can't see.** That's the whole reason `CBPFShim` exists (`Package.swift:109-115`).
:::
