# E · Further reading

![A stack of man pages, RFCs and repo docs. Keep going!](figures/E-hero.svg)

Where to go next. Man pages are on every Mac: type `man 2 socket` in Terminal. Apple
documents are listed by name; search for them on Apple's developer site.

## In this repository

| Document | Read it for |
|---|---|
| `Docs/IPADOS.md` | what the engine is on iPhone and iPad, and what only a device can answer (Part IV) |
| `Docs/01-the-library.md` | the engine as a library: its types, its seams, how to drive it |
| `Docs/04-privileged-helper.md` | the helper: why it exists, how the ticket crosses over, what is still missing (chapter 14) |
| `Docs/SPEC.md` | the original design. Older than the code in places; Appendix D lists where |
| `Package.swift` | the comments on isolation and platforms are short essays (chapters 15, 16) |

## Man pages

| Page | Covers | Chapters |
|---|---|---|
| `socket(2)` | making a socket: domains and types | 2, 5 |
| `connect(2)` | starting a connection, `EINPROGRESS` | 6 |
| `recv(2)` | `recv`, `recvfrom`, `recvmsg`, control messages | 5, 7 |
| `setsockopt(2)` | socket options (`getsockopt` is on the same page) | 5, 6 |
| `fcntl(2)` | `O_NONBLOCK` and other flags | 4 |
| `kqueue(2)` | readiness events, the engine under `DispatchSource` | 4 |
| `getifaddrs(3)` | listing interfaces | 8 |
| `sysctl(3)` | reading kernel values, including the routing table | 2, 12 |
| `route(4)` | the routing socket and its messages | 12 |
| `bpf(4)` | the packet filter device and every `BIOC` ioctl | 11 |
| `icmp(4)` | ICMP sockets, including the non-root `SOCK_DGRAM` kind | 5 |
| `ip(4)` | IP-level options such as `IP_RECVTTL` and multicast | 5, 9 |
| `tcp(4)` | TCP sockets and their options | 6 |
| `udp(4)` | UDP sockets | 7 |
| `launchd.plist(5)` | how a launch daemon is described | 14 |

## Apple documentation, by name

- **Network.framework** (`NWConnection`, `NWParameters`): TLS for banners. Chapter 6.
- **DNS Service Discovery C API** (`dns_sd.h`): Bonjour browsing. Chapter 9.
- **SMAppService**: installing the helper as a launch daemon. Chapter 14.
- **NSXPCConnection**: the app talking to the helper. Chapter 14.
- **Local Network privacy** (Apple's technote "Understanding local network privacy", and the `NSLocalNetworkUsageDescription` key): why a denial looks like silence. Chapters 10, 17.
- **The multicast networking entitlement** (`com.apple.developer.networking.multicast`): what SSDP needs on iOS. Chapter 15.

## RFCs

| RFC | Title | Chapters |
|---|---|---|
| 792 | Internet Control Message Protocol | 5 |
| 1071 | Computing the Internet Checksum | 5 |
| 793, 9293 | Transmission Control Protocol (9293 replaces 793) | 6, 13 |
| 768 | User Datagram Protocol | 7 |
| 6762 | Multicast DNS | 9 |
| 6763 | DNS-Based Service Discovery | 9 |
| 1002 | NetBIOS on TCP/UDP: detailed specifications | 9 |
