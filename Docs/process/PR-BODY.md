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
every scan at 2 s (Q18).

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
| — | Testbed gates as one script (`Scripts/verify-reach-testbed.sh`), its fixes, and gate evidence | `588c6f4`, `562b90a`, `4a0e273`, `db58ed5`, `4a29208`, `11d4b02` |

## Breaking

- **Schema 4.** `discovered_via` has a new value and `neighbor_table` changed meaning. A
  schema-3 reader cannot decode a 4 document. `minimumReadableSchema` stays 1. Everything
  the fixes added (`paths`, `warm_*`, `expected_window_millis`, `address_sources`,
  `known_network`, `unexpected_cold`, `run.ipv6_window`) is additive inside 4.
- **Source-breaking:**
  - `DiscoverySource.neighborResolved`.
  - `ProbeEvent.settling`.
  - The `HistoryStore.recordExtension(_:of:)` requirement.
  - `ReachPlan.make` no longer takes `retention:`.
  - `Device` gains `addressSources` (defaulted in its initialiser).
  - `IPv6MulticastEcho` gains `solicitAllNodes(on:floor:cap:closing:)`, defaulted to the fixed
    window, so existing conformers compile unchanged.

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
  **679 → 744 → 773 → 782 → 796**, all passing on macOS 26.6.2 / Swift 6.3.3.
- **Linux** (`swift:6.2` in the `swiftci` lima VM, Swift 6.2.4): the whole package builds,
  including `zhen` and its plugin. `swift test --filter ZhenCoreTests`: **403 pass**. That
  covers G1, G2, R1, R3, R6 and R8's portable half.
- **Passed:**
  - The first run's G0, G1, G2, G7 (fixture half), G8 and G9 (agent half).
  - The fixes run's R1–R5.
  - The addendum's R6, R7 and R4 again.
  - The second addendum's R8, R9 and R4 again.
  - The evidence for each is pasted in `Docs/process/0.8.0-progress.md`.
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
- `Scripts/check-manpage.sh` (`scan: 29 options checked`) and `Scripts/check-docs.sh` pass.
- No `unsafe`, `@unchecked` or `nonisolated(unsafe)` was added to `ZhenCore`.
- **On the testbed** (first run, JC's sudo through a temporary sudoers entry, since removed):
  - **G4** 10 of 10, **G8** nothing moved, **G9** every row including root.
  - **G7**'s look-longer half passed.
  - **G3**'s mechanism matches 0.7.0 (medians 262 vs 267 ms).
  - The testbed had come back from a reboot **without its network namespaces or netem
    qdiscs**. So G3's absolute window, G5, G6 and G7's "comes back" half could not be
    judged, and nothing has yet run against a slow host. That is gate T, below.
- `swiftlint` and GitHub CI weren't run, and nothing was pushed.

## For JC — gate T

Rebuild the testbed first, then run the gates on one `$OUT`, then put the study back. The
script asks for sudo where it needs it, and its preflight warns if `.11` answers echo or `.12`
answers in under 400 ms. The netbed VMs were stopped at the end of the fixes run. If
`netbed.py up` doesn't start them, run `for v in netbed{1..5}; do limactl start $v; done`.

```bash
cd ~/Dev/InfinityCastle/zhen-study
python3 testbed/netbed.py up && python3 testbed/netbed.py configure && python3 harness/oracles.py
cp testbed/manifest.json /tmp/manifest-0.8.0-gates.json

cd ~/Dev/InfinityCastle/zhen-core && swift build -c release
export OUT=$(mktemp -d /tmp/zhen-reach.XXXXXX)
Scripts/verify-reach-testbed.sh g3            # absolute window 330–404 ms; cold misses only .12/.13
Scripts/verify-reach-testbed.sh g4            # with the 500 ms hosts: 10 of 10
Scripts/verify-reach-testbed.sh g5            # primed: 10 of 10, first_scan false, wall below G4 (F8 removed the 2 s floor)
Scripts/verify-reach-testbed.sh g5w           # F1: warm cache never takes the first-scan wait; then F7 (g5k):
                                              #   the first known scan waits 1.5 s only for expected cold addresses
Scripts/verify-reach-testbed.sh g6            # .11 neighbor_resolved cold, neighbor_table warm
Scripts/verify-reach-testbed.sh g7 netbed3    # look-longer on the run's interface (F5)
Scripts/verify-reach-testbed.sh g9            # optional: the contract on the testbed, incl. rows 1w, 1u, 1i, root

cd ~/Dev/InfinityCastle/zhen-study
git checkout -- testbed/manifest.json testbed/gate-0.4.json
git status --short                            # must show only paper/
```

Then bump to 0.8.0, tag, and write `zhen-study/v2/frozen-binary-v2.json`.

## Known defects and open questions

No gate failed for a reason in the code. `Docs/process/0.8.0-questions.md` holds Q1–Q18 and
corrections to Q5, Q12 and Q14. Nothing in it is waiting on a decision before the freeze:

- **Q18** is answered by F8.
- **Q17** was accepted as it stands: a small home network is known from its third scan, a
  one-time cost per network, and `--reach-min-samples` moves it.
- **The 500 ms floor shows on a very fast sweep.** Below 500 ms of discovery, the scan lasts
  500 ms. That is the floor's job, the sleeping phone, and `--ipv6-window` moves it.

Also open:
- **Q5:** XNU may send at most one ARP request per second per entry. A capture during G4
  would settle it.
- **Q7:** a 0.7.0 compaction of the shared history drops `run.reach` and `address_sources`.
- **Q13:** a powered-off dual-stack host stays present through its NDP entry. Presence is
  unchanged by design; `address_sources` now lets the analysis filter it.

Answered: Q1 (F3), Q8 (F1 and F7), Q9 (F2), Q11 (F4), Q12 (F5), Q14 (corrected), Q15 (F7),
Q18 (F8). Accepted as they stand: Q17.
Accepted as resolved: Q16 (a cached, expected address waits for nothing; its warm percentile
is only reported).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01WBYqzzAHubrqLjum2CZLP1
