# zhen-core 0.8.0 — reach

**Base:** `main` (`cb786da`, the 0.7.0 tag) · **Branch:** `core-0.8.0-reach` · **Not tagged, not
pushed.** `ZhenVersion.current` is still `0.7.0`: the release commit and tag are JC's (questions Q10).

Study 1 found that a cold scan misses the slowest hosts one run in five, always `.12`/`.13`,
because the network-wide tail is learned from replies that already came back. It can't wait
for a host it has never heard from. This branch makes the wait a property of the address.
History says which addresses usually answer and how long they took when nothing was cached.
Those addresses wait longer and are asked more often. The rest keep the short learned wait.
A network never scanned waits long everywhere, once. Everything the study needs to measure
this from a frozen binary is a flag, and the artifact records it.

A review of the first run found four questions that would change what study 2 measures. The
second run (`core-0.8.0-fixes`) answers them, F1–F5, and corrects the record, F6. Its
review found one more defect in F1's rule (Q15), and the addendum run fixes it, F7. The
second addendum, F8, makes that reach the person running the scan: the IPv6 window had held
every scan at 2 s (Q18). Gate T then ran on the rebuilt testbed. Everything passed except G5:
on a network zhen knows, with a cold cache, it lost the 500 ms hosts in 5 of 10 scans and
never got them back. The third addendum fixes the three causes, F9–F11.

## The changes

| # | Change | Commit |
|---|---|---|
| 8 | `ExpiryQueue`: each tick costs what is due, not what was sent. G8: 15.04 comparisons per operation, against a bound of 40 | `126f856` |
| G0 | Spike: an unprivileged `PF_ROUTE` socket gets **no** message when an ARP entry resolves. So the watch polls | `e02e3c2` |
| 1 | **Neighbour watch.** An entry that resolves mid-sweep is `discovered_via: neighbor_resolved`, found at that moment. `neighbor_table` now means *inherited*. `run.neighbor_watch`. **Schema 4** | `9f952e7` |
| 2 | `SweepReach` (`learned`, `history(percentile:)`, `fixed`) and `ReachPlan`, a pure plan built before the sweep. Every constant is in `ReachSettings` | `adca7fd` |
| 3 | **First contact** per host (`first_contact_millis`, `first_contact_cold`). History keeps the newest 32 per device on a `"first_contact"` line of its own, which 0.7.0 carries through a compaction | `501a588` |
| G1, G2 | Fixtures written by 0.7.0's own store, by this branch on top of it, and by 0.7.0 compacting that | `c7c2c16` |
| 4 | **The sweep honours the plan.** Extended addresses get the plan's attempts, spread across their own wait, and a deadline. The sweep ends at the latest deadline, or as soon as every expected address has evidence. `.learned` runs the 0.7.0 schedule unchanged | `bfe3597` |
| 5 | **Look longer.** `ScanRunner.lookLonger(_:wait:)` and `HistoryStore.recordExtension(_:of:)`: a found device joins the *latest* run, and nothing else changes | `d0ccc68` |
| 6 | **Settling.** `ProbeEvent.settling(expectedMissing:)`; `run.reach` with `expected_missing` | `43a1cfc` |
| 7 | **CLI.** `--reach history\|learned\|<duration>`, `--reach-percentile`, `--no-neighbor-watch`, `zhen scan --look-longer` | `97a79d1` |
| 9 | **The study contract.** A flag for every constant, each echoed in `run.reach`; `found_after_millis`; per-stage `attempts`/`concurrency`; `run.tool`; `zhen --version` with the commit | `ae9c4a8` |
| F1 | **Cold and warm, per address.** An address is judged by its own neighbour entry at sweep start: cold samples (or the 1.5 s first-scan wait) with no complete entry, warm samples (or the learned tail) with one. A warm address never waits the first-scan wait. `run.reach.paths`, `warm_wait_millis`, `warm_samples` | `e461ee8` |
| F2 | **An inherited entry satisfies the early exit.** An expected address already complete at sweep start is `inherited`: asked on the learned schedule, never waited for, still `neighbor_table` | `0e3441c` |
| F3 | **Expected means seen in the last 30 days**, not inside retention (history is kept for ever). `--expected-window`, `run.reach.expected_window_millis`. Durations accept `d` | `2c059a8` |
| F4 | **Each address says how it was found:** `address_sources`, one `{address, discovered_via}` per address. `discovered_via` stays the union | `d0c390e` |
| F5 | **Look longer asks on the latest scan's interface**, `run.interface` (on every run since 0.7.0). A disagreeing `--iface` exits 64 | `07925a2` |
| F6 | **Corrections:** the testbed isolates responders in network namespaces, which a reboot wipes along with the netem qdiscs. It doesn't use `arp_ignore`/`arp_announce`. The script's preflight now checks `.12`'s delay | `cf415ac` |
| F7 | **A known network's unexpected cold addresses take the learned tail.** The first-scan wait is for a network zhen doesn't know yet (fewer than 20 samples, cold and warm together) and for expected addresses. A machine that scans often no longer waits 1.5 s for the ~240 addresses where nothing lives. `--unexpected-cold learned` (default) or `first-scan` (F1's rule, for the study); `run.reach.unexpected_cold`, `run.reach.known_network` | `3255bfc` |
| F8 | **The IPv6 window ends when the IPv4 sweep ends,** floored at 500 ms and capped at 2 s, instead of a fixed 2 s that every scan waited for. `--ipv6-window sweep` (default), `<duration>` (`2s` is the old window), or `0` (no echo); `run.ipv6_window`. `check-manpage.sh` now reads option names with digits | `91f0d33` |
| F9 | **A reply to another scan's probe is a stray.** Probe tokens started at 1 every sweep, in the same address order, so a 500 ms host's late reply to the previous scan matched this scan's probe and became a 46 ms first contact. Each sweep draws a random 32-bit base. `timing.stages[].stray_replies`, `late_replies` | `9e0201b` |
| F10 | **A sighting with less than its record takes nothing away.** A MAC-less sighting, and the v6-only twin `Device.fusing` reports beside it, each replaced the host's record and removed its MAC, then its v4 address, so it left the expected set. Now such a sighting fills the record in; a MAC-less one joins the current holder of the address; samples carry `at_millis` and merge by time | `bca88f5` |
| F11 | **Each expected address waits for its own device:** the percentile of its device's cold samples, or their maximum below 5, floored by the learned tail, capped at 5 s. The network's value is the fallback for a device with none. `--reach-device-min-samples`, `run.reach.device_min_samples`, `paths.device` | `a79b034` |
| — | Testbed gates as one script (`Scripts/verify-reach-testbed.sh`), its fixes, and gate evidence | `588c6f4`, `562b90a`, `4a0e273`, `db58ed5`, `4a29208`, `11d4b02`, `b510ed8` |

## Breaking

- **Schema 4.** `discovered_via` has a new value and `neighbor_table` changed meaning. A
  schema-3 reader cannot decode a 4 document. `minimumReadableSchema` stays 1. Everything
  the fixes added (`paths`, `warm_*`, `expected_window_millis`, `address_sources`,
  `known_network`, `unexpected_cold`, `run.ipv6_window`, `paths.device`,
  `device_min_samples`, `stray_replies`, `late_replies`, a sample's `at_millis`) is additive
  inside 4.
- **Source-breaking:**
  - `DiscoverySource.neighborResolved`.
  - `ProbeEvent.settling`.
  - The `HistoryStore.recordExtension(_:of:)` requirement.
  - `ReachPlan.make` no longer takes `retention:`.
  - `Device` gains `addressSources` (defaulted in its initialiser).
  - `IPv6MulticastEcho` gains `solicitAllNodes(on:floor:cap:closing:)`, defaulted to the fixed
    window, so existing conformers compile unchanged.
  - `ReachPath` gains `.device`, so an exhaustive `switch` over it needs the case.

  The app must handle the first three when it adopts 0.8.0. `NeighborCache.snapshot()` is
  a new requirement with a default.
- **The default scan changes.** It reads history before the sweep. On a network with fewer
  than 20 cold samples, an address with no neighbour entry waits 1.5 s if history expects
  it, or if the network isn't known yet (fewer than 20 samples of both kinds together).
  `--reach learned --no-neighbor-watch` is 0.7.0's mechanism. The IPv6 all-nodes window
  closes with the IPv4 sweep (500 ms to 2 s) instead of lasting 2 s; `--ipv6-window 2s`
  restores it.
- The JSON fixture and the two `PipelineArtifactGate` baselines gain `run.tool` (change 9)
  and `address_sources` (F4), deliberately. Nothing else in them moved; each update was
  checked by removing the new key and comparing byte for byte.

## Verification

- `swift build`: 0 errors. The only warnings are the eight `main` already has. `swift test`:
  **679 → 744 → 773 → 782 → 796 → 812**, all passing on macOS 26.6.2 / Swift 6.3.3. Each of
  F9, F10 and F11's commits passes on its own (799, 805, 812).
- **Linux** (`swift:6.2` in the `swiftci` lima VM, Swift 6.2.4): the whole package builds,
  including `zhen` and its plugin. `swift test --filter ZhenCoreTests`: **416 pass**. That
  covers G1, G2, R1, R3, R6, R8's portable half, R11 and R12.
- **Passed:**
  - The first run's G0, G1, G2, G7 (fixture half), G8 and G9 (agent half).
  - The fixes run's R1–R5.
  - The addendum's R6, R7 and R4 again.
  - The second addendum's R8, R9 and R4 again.
  - The third addendum's R10 (fixture half), R11, R12 and R4 again.
  - The evidence for each is pasted in `Docs/process/0.8.0-progress.md`.
- **R10:** two sweeps over the testbed's ten responders; the first's reply for `.12` reaches the
  second 46 ms in, or before the second has recorded its sends. Before F9 it became a 46 ms
  cold first contact with no MAC, gate T's `g5-6` exactly. After, it is a stray. The capture
  half is `verify-reach-testbed.sh r10`, for gate T.
- **R11** replays gate T's G5 from its traces through history, with the cache keeping both slow
  hosts' link-locals. Before F10 it reproduces the gate's `expected` and `history_samples`
  columns to the sample (…, 10, 9, …, 77, 72, …). After, both hosts stay expected with their
  MAC'd record and every sample.
- **R12:** one slow device among 50 fast ones (20 of 1,020 samples) waits 1,006 ms for itself,
  where the network's P97 is under 20 ms. 3 samples wait their maximum; none falls back.
- **R2** is a fixture sweep: an expected, inherited, ARP-only address ends at the learned
  tail, before the 1.2 s F1 alone would have held it. With F2's line reverted, the same test
  fails.
- **R6** checks F7's rule in the plan: the shapes it changes, unknown networks under both flag
  values, and 6 × 6 × 4 × 254 cases where `--unexpected-cold first-scan` must equal F1's rule.
  The sweep half has Q15's shape: no plan kept, and the schedule identical to a plan-less
  sweep. R1 runs under `first-scan` now. With F7's condition forced false, the new tests fail.
- **R7, Q15's repro live on this Mac** (unprivileged, scratch history, a minute apart, at
  `3255bfc`). The first scan on a known network had `paths.first_scan` 0, equal to the expected
  cold count, and discovery took **364 ms**, against 1,514–1,519 ms on the scans before it.
  The same history under `--unexpected-cold first-scan` took 1,518 ms. That first known scan
  is the **third**, not the second: one scan of a 15-host LAN leaves 14 samples (Q17). The
  committed `g5k` passed both halves on this LAN.
- **R8, F8 live on this Mac** (unprivileged, at `91f0d33`, known network, nothing expected
  missing). The default scan's wall clock was **504–517 ms**, 3–115 ms over its discovery
  stage. `--ipv6-window 2s` gave 2,023–2,048 ms, which is the old behaviour. The fixture half
  checks that the window closes after the sweep, the floor, the cap, `fixed`, `off` and the
  deadline. With the close signal removed, it fails.
- **R9:** at the 500 ms floor, the dual-stack hosts R5 found over IPv6 (`.1`, `.5`) answered
  the all-nodes echo in 5 of 5 consecutive scans, and so did the IPv6-only responder. All
  replies on this LAN arrive within 55 ms (`ping6`), so the floor stays at 500 ms.
- **R5, G9 live on this Mac, unprivileged, on 10.10.40.0/24** (not the study LAN and not a
  measurement). Every row's flag was accepted and its value is in the artifact, including
  F3's `--expected-window` (`1ms` forgets the scan before it; the default expects all 15
  hosts). `zhen --version` printed `0.7.0 (cf415ac…)`. JC's real history store had the same
  sha256 before and after.
- `Scripts/check-manpage.sh` (`scan: 30 options checked`) and `Scripts/check-docs.sh` pass.
- No `unsafe`, `@unchecked` or `nonisolated(unsafe)` was added to `ZhenCore`.
- **On the testbed** (first run, JC's sudo through a temporary sudoers entry, since removed):
  - **G4** 10 of 10, **G8** nothing moved, **G9** every row including root.
  - **G7**'s look-longer half passed.
  - **G3**'s mechanism matches 0.7.0 (medians 262 vs 267 ms).
  - The testbed had come back from a reboot **without its network namespaces or netem
    qdiscs**. So G3's absolute window, G5, G6 and G7's "comes back" half could not be
    judged, and nothing has yet run against a slow host. That is gate T, below.
- **Gate T** (2026-10-17, rebuilt testbed, 500 ms hosts back, at `b510ed8`): G3, G4 (10 of 10,
  mean wall 1,885 ms), G5w, G5k, G6, G7 and every G9 row, root included, passed. **G5
  failed**: 5 of 10 scans missed `.12`/`.13`. F9–F11 are the fixes; gate T has not run on them.
- `swiftlint` and GitHub CI weren't run, and nothing was pushed.

## For JC — gate T, again

The testbed is down (its VMs stopped at a reboot). The last gate T's kit is back in `/tmp`,
updated for R10's capture: `/tmp/zhen-gates.sudoers` (its four rules plus one for `tcpdump`,
`visudo -cf` clean) and `/tmp/zhen-gates-0.8.0/run-gates.sh`. Both texts are in the ledger's
latest closing entry, in case `/tmp` goes again. **Read Q19 first**: F11's wait has no margin,
and G5's 10 of 10 is at risk from it.

```bash
sudo install -m 0440 -o root -g wheel /tmp/zhen-gates.sudoers /etc/sudoers.d/zhen-gates

cd ~/Dev/InfinityCastle/zhen-study
python3 testbed/netbed.py up && python3 testbed/netbed.py configure && python3 harness/oracles.py
cp testbed/manifest.json /tmp/manifest-0.8.0-gates.json

cd ~/Dev/InfinityCastle/zhen-core && swift build -c release
zsh /tmp/zhen-gates-0.8.0/run-gates.sh check g3 g4 g5 g5w g6 r10 g7
cd ~/Dev/InfinityCastle/zhen-study && python3 testbed/netbed.py configure && python3 harness/oracles.py   # g7 restarts netbed3
zsh /tmp/zhen-gates-0.8.0/run-gates.sh g9 cleanup
git checkout -- testbed/manifest.json testbed/gate-0.4.json
git status --short                            # must show only paper/ and v2/PLAN.md
```

G5 is the one that matters: 10 of 10, mean wall below G4's. Each line prints `paths` (with
`device`) and `strays`. `r10` prints its own PASS or FAIL. Then bump to 0.8.0, tag, and write
`zhen-study/v2/frozen-binary-v2.json`.

## Known defects and open questions

Gate T's G5 failed for reasons in the code; F9–F11 fix them, and no agent gate fails.
`Docs/process/0.8.0-questions.md` holds Q1–Q19 and corrections to Q5, Q12 and Q14. **One is
waiting on a decision before gate T runs again:**

- **Q19:** F11 waits a device's maximum while it has fewer than 5 samples, with no margin. A
  500 ms host's cold first contacts scatter over ~25 ms (the neighbour watch's poll), so the
  next one often lands past the wait. That rule over the whole network is what missed `.13` in
  gate T's `g5-3`. Options: a margin, a miss that lengthens the next wait, or run gate T as is.

The rest:

- **Q18** is answered by F8.
- **Q17** was accepted as it stands: a small home network is known from its third scan, a
  one-time cost per network, and `--reach-min-samples` moves it.
- **The 500 ms floor shows on a very fast sweep.** Below 500 ms of discovery, the scan lasts
  500 ms. That is the floor's job, the sleeping phone, and `--ipv6-window` moves it.

Also open:
- **Flaky under load, predating this branch's last run:** three of F8's `IPv6WindowTests` assert
  wall-clock bounds and fail in a loaded parallel run (macOS once, Linux's whole package at
  `05ec5ef` too); alone they pass. `ConnectV6Tests`' link-local listener failed in two of seven
  full runs and passed every rerun.
- **The gate T artifacts are lost** to a reboot. What its transcript kept is in
  `~/Dev/_archive/gate-t-2026-10-17/`.
- **Q5:** XNU may send at most one ARP request per second per entry. A capture during G4
  would settle it.
- **Q7:** a 0.7.0 compaction of the shared history drops `run.reach`, `address_sources` and
  the stages' `stray_replies`/`late_replies`. Samples, `at_millis` included, are on a line
  0.7.0 keeps verbatim.
- **Q13:** a powered-off dual-stack host stays present through its NDP entry. Presence is
  unchanged by design; `address_sources` now lets the analysis filter it.

Answered: Q1 (F3), Q8 (F1 and F7), Q9 (F2), Q11 (F4), Q12 (F5), Q14 (corrected), Q15 (F7),
Q18 (F8). Accepted as they stand: Q17.
Accepted as resolved: Q16 (a cached, expected address waits for nothing; its warm percentile
is only reported).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01WBYqzzAHubrqLjum2CZLP1
