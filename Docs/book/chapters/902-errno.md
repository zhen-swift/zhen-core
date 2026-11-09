# C · errno cheat sheet

![-1 means no. errno says why. Each sticky note is one reason.](figures/C-hero.svg)

When a door returns `-1`, `errno` holds the reason (chapter 2). These are the reasons
zhen-core looks at, and what it does about each.

| errno | Plain meaning | What Zhen does with it | Where |
|---|---|---|---|
| `EPERM`, `EACCES` | not allowed | turns it into `.denied`. Opening `/dev/bpf*`: `.notPrivileged`, and stops trying | `DarwinPlatform.swift:46`; `BPFAcquisition.swift:147-148` |
| `ENOENT` | no such file | `.notFound`. Opening `/dev/bpfN`: no more devices to try, stop | `DarwinPlatform.swift:48`; `BPFAcquisition.swift:152-153` |
| `ENXIO`, `ENODEV` | no such device | `.notFound` | `DarwinPlatform.swift:48` |
| `EBUSY` | someone else has it | `/dev/bpfN` is held (Wireshark, a VPN…): count it busy, try the next one | `BPFAcquisition.swift:149-151` |
| `EINVAL` | bad argument | never matched by name. The comments record where it bites: BPF `ioctl`s in the wrong order, a BPF read into a short buffer, asking `setrlimit` for too much (handled by halving and trying again) | `BPFAcquisition.swift:18-22`; `BPFDevice.swift:81`; `DarwinPlatform.swift:70`, `:92-97` |
| `EAGAIN` (= `EWOULDBLOCK`) | not now, try again | ICMP send: yield a few times, then wait for "writable" with kqueue. BPF write: `sched_yield`, up to 8 tries. UDP read: stop draining | `ICMPSocket.swift:256-272`; `BPFDevice.swift:291-302`; `UDPProbe.swift:235-238` |
| `EINPROGRESS` | connecting, check later | expected from a non-blocking `connect`: wait for writable, then ask `SO_ERROR` | `TCPConnectScan.swift:206`; `Readiness.swift:246` |
| `ECONNREFUSED` | the host said "nobody here" (a TCP reset, or ICMP port unreachable) | TCP port: `.closed`. UDP port: `.refused`, which means closed | `TCPConnectScan.swift:255`; `UDPProbe.swift:231`; `UDPPortScan.swift:160` |
| `EHOSTUNREACH`, `ENETUNREACH`, `EHOSTDOWN`, `ENETDOWN` | the path, not the port, is the problem | UDP: `.unreachable(errno)`. TCP: falls through to `.filtered`, because it says nothing about the port | `UDPProbe.swift:234`; `TCPConnectScan.swift:246-257` |
| `ENOBUFS` | the kernel's send queue is full | treated exactly like `EAGAIN` for ICMP sends and BPF writes | `ICMPSocket.swift:256`; `BPFDevice.swift:298` |
| `ENOMEM` | your buffer was too small (the table grew) | routing-table read: try again with a bigger buffer | `RouteMessages.swift:251-252` |
| `EMFILE` | out of tickets | never matched by name. A TCP probe whose `socket` fails is reported `.filtered` ("we learned nothing"). Avoided in the first place by sizing the scan from the real limit | `TCPConnectScan.swift:177-180`; `DarwinPlatform.swift:107-109` |
| `EINTR` | a signal interrupted the call | retried **only** around the history file's lock. No socket path checks for it | `LogHistoryStore.swift:356-359` |

Anything not in the table becomes `.systemError` when it goes through
`PlatformError.syscall` (`DarwinPlatform.swift:42-53`), or `.filtered` when it's the
answer to a TCP `connect` (`TCPConnectScan.swift:256`).

::: honest
🔍 Honest note: no `EINTR` on sockets

`grep -rn EINTR Sources` finds exactly one handler, for `flock` on the history file (`LogHistoryStore.swift:358`). The socket paths don't retry on `EINTR`. With non-blocking sockets and no signal handlers installed by the engine this is rarely hit, but a send or read interrupted by a signal would be taken as a failure, not retried.
:::
