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
second run (`core-0.8.0-fixes`) answers them, F1–F5, and corrects the record, F6.

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
| — | Testbed gates as one script (`Scripts/verify-reach-testbed.sh`), its fixes, and gate evidence | `588c6f4`, `562b90a`, `4a0e273`, `db58ed5`, `4a29208` |

## Breaking

- **Schema 4.** `discovered_via` has a new value and `neighbor_table` changed meaning. A
  schema-3 reader cannot decode a 4 document. `minimumReadableSchema` stays 1. Everything
  the fixes added (`paths`, `warm_*`, `expected_window_millis`, `address_sources`) is
  additive inside 4.
- **Source-breaking:**
  - `DiscoverySource.neighborResolved`.
  - `ProbeEvent.settling`.
  - The `HistoryStore.recordExtension(_:of:)` requirement.
  - `ReachPlan.make` no longer takes `retention:`.
  - `Device` gains `addressSources` (defaulted in its initialiser).

  The app must handle the first three when it adopts 0.8.0. `NeighborCache.snapshot()` is
  a new requirement with a default.
- **The default scan changes.** It reads history before the sweep. An address with no
  neighbour entry, on a network with fewer than 20 cold samples, waits 1.5 s.
  `--reach learned --no-neighbor-watch` is 0.7.0's mechanism.
- The JSON fixture and the two `PipelineArtifactGate` baselines gain `run.tool` (change 9)
  and `address_sources` (F4), deliberately. Nothing else in them moved; each update was
  checked by removing the new key and comparing byte for byte.

## Verification

- `swift build`: 0 errors. The only warnings are the eight `main` already has. `swift test`:
  **679 → 744 → 773**, all passing on macOS 26.6.2 / Swift 6.3.3.
- **Linux** (`swift:6.2` in the `swiftci` lima VM, Swift 6.2.4): the whole package builds,
  including `zhen` and its plugin. `swift test --filter ZhenCoreTests`: **390 pass**. That
  covers G1, G2, R1 and R3.
- **Passed:**
  - The first run's G0, G1, G2, G7 (fixture half), G8 and G9 (agent half).
  - The fixes run's R1–R5.
  - The evidence for each is pasted in `Docs/process/0.8.0-progress.md`.
- **R2** is a fixture sweep: an expected, inherited, ARP-only address ends at the learned
  tail, before the 1.2 s F1 alone would have held it. With F2's line reverted, the same test
  fails.
- **R5, G9 live on this Mac, unprivileged, on 10.10.40.0/24** (not the study LAN and not a
  measurement). Every row's flag was accepted and its value is in the artifact, including
  F3's `--expected-window` (`1ms` forgets the scan before it; the default expects all 15
  hosts). `zhen --version` printed `0.7.0 (cf415ac…)`. JC's real history store had the same
  sha256 before and after.
- `Scripts/check-manpage.sh` (`scan: 27 options checked`) and `Scripts/check-docs.sh` pass.
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
Scripts/verify-reach-testbed.sh g5            # primed: 10 of 10, first_scan false, wall below G4
Scripts/verify-reach-testbed.sh g5w           # F1: warm cache never takes the first-scan wait
Scripts/verify-reach-testbed.sh g6            # .11 neighbor_resolved cold, neighbor_table warm
Scripts/verify-reach-testbed.sh g7 netbed3    # look-longer on the run's interface (F5)
Scripts/verify-reach-testbed.sh g9            # optional: the contract on the testbed, incl. root

cd ~/Dev/InfinityCastle/zhen-study
git checkout -- testbed/manifest.json testbed/gate-0.4.json
git status --short                            # must show only paper/
```

Then bump to 0.8.0, tag, and write `zhen-study/v2/frozen-binary-v2.json`.

## Known defects and open questions

No gate failed for a reason in the code. `Docs/process/0.8.0-questions.md` holds Q1–Q16 and
corrections to Q5, Q12 and Q14. **Decide these before the freeze.** They are rules, not
constants, so no flag can move them afterwards:

- **Q15:** F1 takes warm hosts off the first-scan wait, but a machine that only ever scans
  warm still has no cold history. Its ~240 empty addresses are cold, so they still wait
  1.5 s, and so does the scan. Seen live: 1,514–1,517 ms. One option is to give the
  first-scan wait only to expected cold addresses, or only while history holds too few
  samples of either kind.
- **Q16:** F1's warm percentile is computed and reported, but F2 takes every address it
  applies to, so no address waits it.

Also open:
- **Q5:** XNU may send at most one ARP request per second per entry. A capture during G4
  would settle it.
- **Q7:** a 0.7.0 compaction of the shared history drops `run.reach` and `address_sources`.
- **Q13:** a powered-off dual-stack host stays present through its NDP entry. Presence is
  unchanged by design; `address_sources` now lets the analysis filter it.

Answered: Q1 (F3), Q8 (F1, with Q15 left), Q9 (F2), Q11 (F4), Q12 (F5), Q14 (corrected).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01WBYqzzAHubrqLjum2CZLP1
