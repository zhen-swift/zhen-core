# zhen — the manual

A fast native network scanner for macOS, written in Swift. This document is task-shaped:
what you want to know, and the command for it. `man zhen` is the reference; this is the
guide.

Written against 0.5.0. If something here disagrees with `zhen --help`, the tool is right
and this is a bug — please say so.

---

## Install

```sh
git clone https://github.com/zhen-swift/zhen-core.git && cd zhen-core
PREFIX=$HOME/.local ./Scripts/install.sh
```

Builds release, installs `zhen` and its man page under the prefix you name. It never calls
`sudo` and never asks for a password; if the destination is not writable it prints the
exact command to run and stops.

Put the prefix on your `PATH` if it is not already:

```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && exec zsh
```

System-wide instead: `sudo PREFIX=/usr/local ./Scripts/install.sh`. Uninstall: the same
command with `uninstall`.

**If a command behaves unlike this document, check you are running the copy you think you
are.** `type -a zhen` — an older install earlier on `PATH` shadows a newer one, and macOS
puts `/usr/local/bin` ahead of `~/.local/bin` by default.

## The two questions, and the two commands

Nearly everything divides in half.

| You want | Command |
|---|---|
| **What is on this network?** | `zhen scan` |
| **What is open on this host?** | `zhen ports <host>` |

`scan` sweeps a network and tells you which hosts answered. `ports` takes hosts you
already have and asks them about ports. `scan --deep` does both in one pass.

---

## Finding hosts

```sh
zhen scan                              # the network on your default route
zhen scan --cidr 10.10.20.0/24         # a network you name
zhen scan --iface en1                  # from a particular interface
zhen scan --deadline 5s                # spend at most five seconds
```

Output is a table of what answered: address, name, model, hardware address, round trip,
and TTL. A row with `—` for round trip came from the kernel's neighbour cache rather than
from a reply — the host is known to be there without having answered this scan.

**Names come from the network, never from a guess.** mDNS, UPnP and NetBIOS are asked;
nothing is inferred from a port number or an address. A device with no name shows `—`, and
that is a result rather than a gap.

### Also probe ports while you are there

```sh
zhen scan --deep                       # a small common set
zhen scan --deep --ports 22,80,443
```

With 8 ports or fewer the table becomes a matrix — one column per port, one row per host —
and drops the model and hardware columns to make room. Above 8 it prints a list of open
ports underneath instead. `--ports-view matrix|long|auto` overrides the choice.

```
ADDRESS       NAME                      22   80  443
10.10.20.1    —                          ·    ●    ●
10.10.20.5    Sala de estar principal    ○    ○    ·

● open   ○ closed   · filtered   ◐ open or filtered   – not probed
```

Four glyphs, not three, and the difference matters — see **Reading a port result** below.

---

## Asking about ports

```sh
zhen ports 10.10.20.11 22              # is ssh open
zhen ports 10.10.20.11 22,80,443
zhen ports 10.10.20.11                 # the common set
zhen ports 10.10.20.0/24 22            # is ssh open anywhere on this network
zhen ports 10.10.20.11 ssh,http,https  # by service name
zhen ports fe80::1%en0 22              # IPv6, zone and all
zhen ports - 22 < hosts.txt            # read targets from stdin
```

A service name selects a port; it never names a result. `ssh` means "try 22". What comes
back is still whatever the banner actually said, or nothing.

### Port specs

| Spec | Means |
|---|---|
| `22` | one port |
| `22,80,443` | a list |
| `1-1024` | a range |
| `common` | the default small set |
| `iana` | the 682 well-known ports with a real IANA assignment |
| `1-1024,!135-139` | with an exclusion |
| `T:80,U:53` | protocol-qualified |

### UDP

```sh
zhen ports 10.10.20.1 53 --udp         # everything listed is UDP
zhen ports 10.10.20.1 T:80,U:53        # mixed
```

UDP is slow for a reason no amount of concurrency fixes: a closed port answers with an ICMP
unreachable, and hosts rate-limit those to roughly one a second. A large UDP range takes
as long as that implies.

### In a script

```sh
zhen ports "$GATEWAY" 22 --check && ssh "$GATEWAY"
```

`--check` prints nothing and puts the answer in the exit code: **0** if any requested port
is open, **1** if none is. A scan that could not run exits neither — so a failure never
reads as "closed".

### Keeping the answer

```sh
zhen ports 10.10.20.11 22,80,443 --record
```

`zhen ports` writes nothing unless asked. `--record` keeps what it found in history: the
ports of each device history already holds, and an event when a port opens or stops being
open. It is **not recorded as a scan** — `zhen ports` never sweeps, so it says nothing about
the rest of the network, and nothing goes offline because it was not asked about. A host
history has never seen is skipped rather than added: a port answer is not a discovery, and
`zhen scan` is how a host joins.

### Choosing the mechanism

```sh
zhen ports host 22 --scan-type connect   # full handshake, no privilege
zhen ports host 22 --scan-type syn       # half-open, needs the helper, IPv4 only
zhen ports host 22 --scan-type auto      # the default: best available per target
```

`connect` is not merely the fallback — it is the permitted option on a network where you
may open sockets but not forge frames, and it completes the handshake so a banner comes
for free. `syn` against an IPv6 target is **refused by name**, not silently substituted.

---

## Reading a port result

The four states are not three, and collapsing them throws away the only signal that
separates a firewalled host from a dead address.

| | Means |
|---|---|
| `open` | something accepted, or answered |
| `closed` | actively refused — a TCP reset, or an ICMP port-unreachable. **Positive information**: the host is there and told you so |
| `filtered` | nothing came back, or something said it was prohibited. Says nothing about whether the host exists |
| `open_filtered` | UDP only: silence, which on UDP genuinely cannot be resolved either way |

A host whose ports are all `closed` is definitely up. A host whose ports are all `filtered`
may not exist at all.

**A service is named only when something on the wire said what it was** — a banner, a TLS
certificate, or a protocol handshake. An absent service means *not observed*, never "we
assumed from the port number".

---

## History

Every scan is recorded, so you can ask what changed.

```sh
zhen hosts                             # every device history has seen, present or absent
zhen events                            # what changed between scans, newest first: arrivals,
                                       #   departures, moves, renames, ports opening and closing
zhen history 10.10.20.11               # one device: what is known, what has happened
zhen export                            # the whole history as one JSON document
```

The store lives under `~/Library/Application Support/zhen/`. Point somewhere else with
`ZHEN_HISTORY=/path/to/history.ndjson`, which is how you keep a scan out of your real
history.

## Machine-readable output

```sh
zhen scan --json                       # one report on stdout
zhen scan --ndjson                     # one event per line, as they happen
zhen scan --json --quiet               # no progress on stderr
```

JSON goes to stdout and progress to stderr, so redirecting output still leaves a visible
scan. The artifact carries a `schema` field; readers should check it.

```sh
zhen scan --deep --json | jq '.devices[] | {ip: .addresses, ports}'
```

**A partial result exits 0.** An expired deadline is the system working as designed, and
whether a run was complete is a field in the artifact rather than the exit status.

## What it tells you it could not do

Degradations are the point rather than noise. A line beginning `!` on stderr is the tool
saying what it could not work out and why — no privilege for the layer-2 sweep, replies
arriving after their timeout, a service it could not ask about. Read them; a scan that
found less than you expected usually explains itself there.

## What it deliberately does not do

- **Name a service from a port number.** A port table is a guess dressed as a fact.
- **Report `top-100` ports.** That needs frequency data this project cannot license, and
  shipping a list as a frequency claim its source cannot support is the same error.
- **Identify services over IPv6.** Port states are complete on both families; banner and
  certificate identification speak IPv4 today, and the tool says so when it applies.
- **OS fingerprint or SYN scan over IPv6.** Both need a capture device and an IPv4-only
  filter.
- **Evade anything.** No idle scan, no fragmentation, no decoys. The audience is someone
  auditing a network they run.

## Privilege

The layer-2 ARP sweep and the half-open SYN scan need a raw capture device. Everything
else — ICMP discovery, connect scans, UDP, the neighbour caches, mDNS — is unprivileged.

Without the helper, `zhen` still works: it uses the unprivileged path, finds fewer hosts
on some networks, and says so. It never asks for your password.

**Read `SECURITY.md` before pointing this at a network you do not run.**
