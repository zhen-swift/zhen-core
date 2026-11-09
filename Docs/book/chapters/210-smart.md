# 10 · Being smart on top

![The doors stay the same: sendto, recvfrom, connect, sysctl. What changes is when to ask again, how long to wait, and what silence means.](figures/10-hero.svg)

::: short
The short version

- This chapter has **no new system calls**. It's about the decisions made on top of the ones you've met.
- The ping sweep keeps **two clocks**: a short one for "ask again?" and a long one, paid **once**, for "nobody's home".
- **Every host gets its own clock**, so one slow Wi-Fi phone isn't judged by the fast majority.
- Retries are **spread out**, so a phone that dozes between Wi-Fi beacons still gets caught awake.
- The **Local Network** permission can't be checked. Zhen **infers** a denial from silence, with the ARP table as its witness.
:::

## Two clocks, two questions

![Retransmits are short and paid on every try; the tail is one long wait, shared by every host and paid once.](figures/10-budgets.svg)

The sweep sends to everyone, listens, re-sends to the silent ones, and stops. Each address gets **three** tries in all (`ICMPSweep.swift:90-95`). Two different waits decide the pace (`ICMPSweep.swift:13-27`):

1. **Retransmit: "when do I ask again?"** Being wrong here costs one packet, so this wait is **short**. It comes from a **low quantile** of the round trips seen so far. It's paid on every try: "244 dead addresses × 2 retransmissions, so every millisecond of it costs 488 milliseconds of nothing".
2. **Tail: "when do I say nobody's home?"** This one must cover the slowest live host. But it's asked **once**, at the end, for every address at the same time.

- The old way used one number for both. With one 600 ms host on the network, every dead address waited about "3 × 600 ms" (`ICMPSweep.swift:29-33`).
- **No backoff.** Waiting longer after silence makes sense if silence means "slow". Here "silence is evidence of ABSENCE": a retry is there to recover a lost frame, which is done "by asking again rather than by waiting longer" (`ICMPSweep.swift:1041-1045`).
- The tail has a **250 ms floor**: it's `srtt + 4·rttvar`, but never less (`SweepSpacing.swift:37-39`).

::: word
New words: round trip, quantile

A **round trip** (RTT) is the time from sending a probe to hearing its reply. A **low quantile** is a number most replies beat easily, like "the time the fastest quarter of replies took". Zhen asks again after that, not after the slowest.
:::

::: word
New word: backoff

**Backoff** means waiting longer after each failure: 1 s, then 2 s, then 4 s. It's right when silence means "busy". It's wrong when silence means "nobody there".
:::

## Every host gets its own clock

![With one wait for everyone, the 180 ms phone's reply arrives after the give-up line. With a wait per host, it's caught.](figures/10-perhost.svg)

- An earlier version used **one** wait for the whole network. So "a 180 ms Wi-Fi device on a network whose other hosts answer in 0.4 ms was missed on every single run, deterministically" (`ICMPSweep.swift:47-53`).
- Now each host has **its own estimator** and its own deadline, and it's re-asked when *its* time is up.
- A host that has never answered has no history. Its **first** wait comes from a **network-wide** estimator instead (`ICMPSweep.swift:55-62`).
- **Karn's rule, the easy way.** Every try carries its **own token** and its own send time. A late reply to try 1 that arrives after try 2 went out is still "a clean sample of the first, and is used" (`ICMPSweep.swift:64-69`).
- Once a host has answered, its estimate follows it into the port scan (chapter 6).

::: word
New word: Karn's rule

**Karn's rule** says: don't time a reply when you can't tell which try it answers. Zhen can always tell, because each try carries its own token.
:::

## Sleepy phones

![Three quick tries can all land while a Wi-Fi phone sleeps. Pushing the last try later lets it land when the phone wakes.](figures/10-powersave.svg)

- Phones on Wi-Fi **doze** to save battery. They wake for the access point's beacon and sleep in between, "unreachable for stretches of a hundred milliseconds and up" (`SweepSpacing.swift:11-16`).
- Three tries spaced by a short retransmit wait span about 50 ms. One nap swallows **all three**, and the phone is reported absent.
- In the study's simulation, with naps averaging 100 ms, three quick tries found **91.0%** of hosts and spread tries found **97.6%** (`SweepSpacing.swift:21-23`). It was "recall being lost for nothing".

So the **last** try is pushed later, into the tail (`SweepSpacing.swift:36-49`):

1. The sweep was going to sit in the tail anyway, waiting for stragglers.
2. The last try is sent **inside** that idle time, late enough to land after a nap.
3. The sweep still ends when it always did. The spread is capped at **400 ms** (`SweepSpacing.swift:105-107`).

**Scattered, but not random.** Each host's gaps are stretched or shrunk by up to **±25%**, so retries don't fall into step with a sleep cycle (`SweepSpacing.swift:58-65`). The amount comes from a hash of the host's **address**, so two scans of the same network space each host the same way (`SweepSpacing.swift:67-70`).

```swift
guard jitter > 0 else { return 1 }
var x = UInt64(address.raw) &+ 0x9E37_79B9_7F4A_7C15
x = (x ^ (x >> 30)) &* 0xBF58_476D_1CE4_E5B9
x = (x ^ (x >> 27)) &* 0x94D0_49BB_1331_11EB
x ^= x >> 31
let unit = Double(x >> 11) * (1.0 / Double(1 << 53))   // [0, 1)
return 1.0 - jitter + 2.0 * jitter * unit
```

[`SweepSpacing.swift:121-127` @ 0.9.0]{.src}

A cheap hash, like the address's last byte, "would put adjacent addresses at adjacent phases", and the sleepy devices are "often a contiguous DHCP range" (`SweepSpacing.swift:116-119`).

::: word
New word: Wi-Fi power save

In **power save**, a phone tells the access point "hold my mail" and sleeps. It wakes for regular **beacons** (the DTIM ones), collects what's waiting, and sleeps again. Packets sent during a nap wait, or get lost.
:::

## Matching the right reply

![A late reply from the previous scan carries a token nobody expects, so it's a stray. A reply that beats its own paperwork waits in a stash until the send is recorded.](figures/10-tokens.svg)

- **Ghosts from the last scan.** Tokens used to start at 1 every scan, so a slow host's reply to the *previous* scan matched *this* one and was "recorded as a first contact of 46 ms". Now each sweep starts at a **random** number, so "another sweep's token names nothing here and its reply is a stray" (`ICMPSweep.swift:711-719`, `:730`).
- **Answers before the paperwork.** A whole /24 takes about 10 ms to hand to the socket, and a nearby host answers in 0.4 ms. So a reply can arrive before Zhen has written down that it sent the probe. It waits in a stash (`unmatched`) until the send is recorded, then counts with its real arrival time. Dropping those made "the fastest hosts on the network the ones most likely to be reported absent" (`ICMPSweep.swift:661-674`, `:1148-1152`).
- **Late but honest.** A reply that arrives after its probe expired is still matched by its token, and the report says the timeouts are "running tight for this network" (`ICMPSweep.swift:477-486`).

## The permission nobody can ask about

![On the Mac, silence plus a full ARP table points at the permission. On the iPad there's no ARP table, so the app can only say "Nothing answered" and offer Settings.](figures/10-permission.svg)

On Apple platforms, probing the local network needs the **Local Network** permission. Two things make it hard (`LocalNetworkDenial.swift:3-12`):

- There's **no API to ask** whether it was granted.
- A denial returns **zero results, not an error**. Every socket opens, every probe goes out, nothing comes back.

So Zhen **infers** it. The witness is the kernel's **ARP table**, which can be read *without* the permission (`LocalNetworkDenial.swift:9-12`):

1. Probes were sent (more than zero).
2. Not one reply came back.
3. The ARP table lists devices on this network, so the Mac has been talking to them.

All three true? Then something is blocking the probes, most likely the permission. The message says it's "a likely cause rather than a confirmed one" (`LocalNetworkDenial.swift:105-126`).

```swift
public static func evaluate(
    repliesSeen: Int,
    probesSent: Int,
    neighborEntries: Int,
    advice: ProbePermissionAdvice = .unspecified
) -> Degradation? {
    guard probesSent > 0, repliesSeen == 0, neighborEntries > 0 else { return nil }
```

[`LocalNetworkDenial.swift:105-111` @ 0.9.0]{.src}

- **The remedy depends on who's asking** (`PermissionAdvice.swift:12-24`):
  - the `zhen` command line: "the grant may be listed under the terminal application";
  - a Mac `.app`: listed "under its own name";
  - an iPad: Settings › Privacy & Security › Local Network.
- The naming stage has a twin check for Bonjour, SSDP and NetBIOS. It only speaks about sources that **actually ran** and **didn't fail** on their own (`LocalNetworkDenial.swift:151-216`, chapter 9).

::: word
New words: ARP table, neighbour table

The **ARP table** (or **neighbour table**) is the kernel's address book for the local network: "192.168.1.31 is the card with MAC 3c:22:…". It fills up whenever the machine talks to a neighbour. Chapter 12 reads it properly.
:::

**Sizing, once more.** How many probes fly at once is still chapter 2's `min(512, tickets ÷ 4)` (`FanOut.swift:105-107`). It's derived from what the kernel granted, never chosen.

::: iphone
📱 On iPhone & iPad

- ✅ All the timing policy is plain Swift: two clocks, a clock per host, spread retries, random tokens. It runs the same on iPadOS.
- ❌ **No ARP table.** iPadOS "does not let an app read the system's neighbour table", so discovery neither reads nor claims one (`SystemNeighborCache.swift:13-20`, `ICMPSweep.swift:79-88`).
- ⚪️ So the denial check **can never fire** on the iPad: it needs `neighborEntries > 0`. The iPad's wording exists (`LocalNetworkDenial.swift:74-79`), but this check never gets to print it.
- ⚪️ The only signal is the app's empty state: **"Nothing answered"**, a line saying "On an iPad that is usually the Local Network permission, which can't be checked directly", and an **Open Settings** button (`zhen-ios/Zhen/Features/DevicesView/DevicesView+EmptyStateView.swift:33-45`).
:::

::: gotcha
⚠️ Gotchas the code remembers

- **One timeout for two questions.** It was either too slow for the dead or too quick for the slow.
- **One clock for every host.** The 180 ms phone was missed every time.
- **Backoff after silence.** Silence means absent, so waiting longer buys nothing.
- **Three quick tries.** One Wi-Fi nap eats all of them.
- **Tokens starting at 1.** The last scan's late replies matched this scan's probes.
- **Pinging yourself.** A probe to your own address is answered inside the kernel and "never reaches the interface". A packet capture shows nothing, so the host is marked as this machine (`ICMPSweep.swift:511-520`).
- **A refused `sendto`.** If the kernel refuses every send, there's no route. That's reported as "the scan did not happen", not as an empty network (`ICMPSweep.swift:525-536`). A refused try is spent, not queued again forever (`ICMPSweep.swift:1154-1157`).
- **The ARP table moves.** Pinging a host makes the kernel look up its MAC, so the table **grows during the scan**. Zhen reads it again at the end (`ICMPSweep.swift:437-447`).
:::

::: remember
🧠 Remember

- **Two clocks**: a short one to ask again, a long one paid once. **No backoff**: silence means absent.
- **Every host gets its own clock**, and retries are **spread** so sleepy phones get caught awake.
- The Local Network permission can't be asked. Zhen **infers** a denial from silence plus the ARP table, and the iPad, with no ARP table, can only **suggest Settings**.
:::
