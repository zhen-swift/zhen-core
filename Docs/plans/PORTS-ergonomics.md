# Asking about a port should be one short command

Written 2026-09-26. The capability landed; the ergonomics did not. Today the simplest
question this tool can be asked is spelled:

```
zhen ports 10.10.20.1 --ports 22
```

That is a flag and a value for a question with two nouns in it. This fixes that.

---

## 1. The four changes

### Port spec as the second positional

```
zhen ports 10.10.20.1 22
zhen ports 10.10.20.1 22,80,443
zhen ports 10.10.20.0/24 22          # is ssh open anywhere on this network
zhen ports 10.10.20.1                # the common set, as today
```

`--ports` stays as the explicit long form, because a script written against a flag should
not break. The positional is the one a person types.

Ambiguity is not a problem in practice: the first positional is targets, so `zhen ports 22`
resolves targets to "22", fails to parse as an address, and says so.

### Service names as selectors

```
zhen ports 10.10.20.1 ssh
zhen ports 10.10.20.1 ssh,http,https
```

**This does not violate the rule in `Ports.swift`, and the distinction is worth being
precise about.** That file refuses *port to service*: "something answered on 22, therefore
SSH". It is a claim about what is running, made from a number, with no evidence.

*Service to port* is the opposite direction and makes no claim at all. `ssh` is a way of
spelling 22 in the request. What comes back is still `open` with whatever the banner
actually said, or `open` with no service at all. Selecting a target asserts nothing about
what answers it.

The mapping comes from the IANA set already committed in `IANAPorts.swift`.

### Simple UDP

```
zhen ports 10.10.20.1 53 --udp
zhen ports 10.10.20.1 T:80,U:53      # mixed, as the parser already spells it
```

`--udp` means "everything I listed is UDP". `U:` stays for mixed specs. Nobody typing one
port should have to learn a prefix.

### `--check`, so the exit code is the answer

```
zhen ports 10.10.20.1 22 --check     # exit 0 if open, 1 if not. prints nothing
```

This is what makes the tool usable inside anything else:

```sh
if zhen ports "$GATEWAY" 22 --check; then
    ssh "$GATEWAY"
fi
```

It is a flag rather than implicit behaviour because "nothing was open" must stay a
**success** in the default mode — a scan that completed and found nothing is a working
scan, which is the same reasoning that makes a partial discovery exit 0 today. `--check`
opts into the other meaning explicitly.

Exit codes: 0 any requested port open, 1 none open, and the existing failure codes
unchanged so a broken scan is never mistaken for a closed port.

---

## 2. Simple UDP, made honest rather than narrow

The payload table — DNS 53, NTP 123, NetBIOS 137, SNMP 161, mDNS 5353, SSDP 1900 — covers
the ports that answer on a LAN. It does not cover port 12345, and a person asking about
port 12345 should get an answer rather than a refusal.

So generic UDP is three outcomes, all honest:

| What came back | State |
|---|---|
| A parsed protocol answer | `open` |
| ICMP port-unreachable | `closed` |
| Nothing, within the budget | `open_filtered` |

An empty datagram to a port with no payload in the table still gets ICMP unreachable from
a closed port on most hosts, so `closed` is reachable everywhere and `open` is reachable
wherever we can speak the protocol. Nothing is guessed, and every arbitrary UDP port is
answerable.

**One caveat to surface in the output, not hide:** ICMP unreachable is rate-limited by the
target — roughly one per second on Linux. A large UDP range is slow for a reason no
concurrency fixes, and the run should say so rather than appear to hang.

## 3. What this is not

Not a service-probe database, and not `top-N`. The question being answered is "is this port
open, and did anything identify itself" — which is what network analysis needs. Everything
past that is signature matching.

## 4. Stages

| | Work | Done when |
|---|---|---|
| **1** | Port spec as second positional; `--ports` kept | `zhen ports HOST 22` works; the existing flag form is unchanged and tested |
| **2** | Service-name selectors from the IANA set | `ssh` resolves to 22; the output still names a service only from wire evidence |
| **3** | `--check` and its exit codes | `zhen ports HOST 22 --check` exits 0 open, 1 closed, and a scan failure exits neither |
| **4** | `--udp`, and generic UDP with the three outcomes | port 12345 returns `closed` against a host that sends unreachable, `open_filtered` against one that does not; rate limiting is reported, not hidden |

Stages 1-3 are a day. Stage 4 rides with schema 3, as `Docs/plans/IPV6-plan.md` sets out.
