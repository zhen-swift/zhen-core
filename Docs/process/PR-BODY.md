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

## The changes

| # | Change | Commit |
|---|---|---|
| 8 | `ExpiryQueue`: each tick costs what is due, not what was sent. Written on Linux and never compiled until this run; it needed no fix. G8: 15.04 comparisons per operation, against a bound of 40 | `126f856` |
| G0 | Spike: an unprivileged `PF_ROUTE` socket gets **no** message when an ARP entry resolves. Eleven resolutions, socket proven live, zero messages. So the watch polls | `e02e3c2` |
| 1 | **Neighbour watch.** The sweep polls the table (25 ms, proportional above 1,024 targets). An entry that resolves mid-sweep is `discovered_via: neighbor_resolved`, found at that moment. `neighbor_table` now means *inherited*. `run.neighbor_watch`. **Schema 4** | `9f952e7` |
| 2 | `SweepReach` (`learned`, `history(percentile:)`, `fixed`) and `ReachPlan`, a pure plan built before the sweep. Every constant is in `ReachSettings` | `adca7fd` |
| 3 | **First contact** per host (`first_contact_millis`, `first_contact_cold`). History keeps the newest 32 per device on a `"first_contact"` line of its own, which 0.7.0 carries through a compaction | `501a588` |
| G1, G2 | Fixtures written by 0.7.0's own store, by this branch on top of it, and by 0.7.0 compacting that. Migration and plan-from-store tests, on macOS and Linux | `c7c2c16` |
| 4 | **The sweep honours the plan.** Extended addresses get the plan's attempts, spread across their own wait, and a deadline in an `ExpiryQueue`. The sweep ends at the latest deadline, or as soon as every expected address has answered. `.learned` runs the 0.7.0 schedule unchanged | `bfe3597` |
| 5 | **Look longer.** `ScanRunner.lookLonger(_:wait:)`, and the new `HistoryStore.recordExtension(_:of:)`: a found device joins the *latest* run with an `appeared`, and nothing else changes | `d0ccc68` |
| 6 | **Settling.** `ProbeEvent.settling(expectedMissing:)` fires when only expected addresses remain ("still listening for 2 you usually have"). `run.reach` records the plan and `expected_missing` | `43a1cfc` |
| 7 | **CLI.** `--reach history\|learned\|<duration>`, `--reach-percentile`, `--no-neighbor-watch`, `zhen scan --look-longer` (`run.extends_run`). Both pipelines build the plan from history | `97a79d1` |
| 9 | **The study contract.** `--first-scan-wait`, `--reach-cap`, `--reach-min-samples`, `--expected-attempts-step`, `--expected-attempts-cap` and `--no-history`, each echoed in `run.reach`. Also per-device `found_after_millis`, per-stage `attempts` and `concurrency`, `run.tool`, and `zhen --version` with the commit, stamped by a build-tool plugin | `ae9c4a8` |
| — | `Scripts/verify-reach-testbed.sh`: JC's gates in one script; questions Q8, Q9 | `588c6f4` |
| — | Script fixes found on the testbed (a failed flush stops the run; look-longer's interface; NDP flush; preflight) | `562b90a`, last |

## Breaking

- **Schema 4.** `discovered_via` has a new value, and `neighbor_table` changed meaning. A
  schema-3 reader cannot decode a 4 document. `minimumReadableSchema` stays 1.
- **Source-breaking:** `DiscoverySource.neighborResolved`, `ProbeEvent.settling`, and the new
  `HistoryStore.recordExtension(_:of:)` requirement. The app must handle all three when it
  adopts 0.8.0. `NeighborCache.snapshot()` is a new requirement, but it has a default.
- **The default scan changes.** It reads history before the sweep, and a network with fewer
  than 20 cold samples waits 1.5 s everywhere. `--reach learned --no-neighbor-watch` is
  0.7.0's mechanism.
- The two byte-for-byte artifact baselines in `PipelineArtifactGate` now include `run.tool`,
  deliberately. The `--version` test now checks the version part against the plist.

## Verification

- `swift build`: 0 errors. The only warnings are the eight that `main` already has.
  `swift test`: **679 → 744**, all passing on macOS 26.6.2 / Swift 6.3.3.
- **Linux** (`swift:6.2` in the `swiftci` lima VM, Swift 6.2.4): the whole package builds,
  including the `zhen` target and its plugin. `swift test --filter ZhenCoreTests`: 370 pass.
  That covers G1 and G2.
- **G0, G1, G2, G7 (fixture half), G8 and G9 (agent half) passed.** The evidence for each
  is pasted in `Docs/process/0.8.0-progress.md`.
- **G9 live, this Mac, unprivileged, on 10.10.40.0/24** (not the study LAN, and not a
  measurement). Every row's flag was accepted and its value is in the artifact.
  `--first-scan-wait 1200ms` ended discovery at 1,214 ms. `--reach learned
  --no-neighbor-watch` took 378 ms. `--no-history` left the store byte-identical.
  `zhen --version` printed `0.7.0 (ae9c4a8…)`. A cold run, once the cache had expired
  on its own, saw 11 resolutions. `.15`, which doesn't answer echo, was
  `neighbor_resolved` at 55 ms (warm, it was reported at 1,517 ms), and every IPv4 host but
  the gateway had `first_contact_cold: true`. JC's real history store has the same sha256
  before and after.
- `Scripts/check-manpage.sh` passes (`scan: 26 options checked`), and so does
  `Scripts/check-docs.sh`.
- No `unsafe`, `@unchecked` or `nonisolated(unsafe)` was added to `ZhenCore`.
- **On the testbed** (with JC's sudo, through a temporary sudoers entry with three exact
  rules, since removed): **G4** 10 of 10, **G8** nothing moved, **G9** every row including
  root (`composite`, `arp_sweep`), and **G7**'s look-longer half. **G3**'s mechanism matches
  0.7.0, run alternately on the same testbed: medians 262 vs 267 ms. But the testbed had come
  back from a reboot **without study 1's impairments**: no slow hosts, `.11` answering echo,
  and ARP flux between each VM's two NICs. So G3's absolute window, G5, G6 and G7's
  "comes back" half could not be judged. Evidence and reasons are in the ledger, and in
  questions Q13 and Q14.
- `swiftlint` and GitHub CI weren't run, and nothing was pushed.

## For JC

Restore the testbed's study configuration with the `zhen-study` tooling first. The script's
preflight warns if `.11` still answers echo. Then:

```bash
cd ~/Dev/InfinityCastle/zhen-core && swift build -c release
for v in netbed{1..5}; do limactl start $v; done
export OUT=$(mktemp -d /tmp/zhen-reach.XXXXXX)
Scripts/verify-reach-testbed.sh g3; Scripts/verify-reach-testbed.sh g4
Scripts/verify-reach-testbed.sh g5; Scripts/verify-reach-testbed.sh g6
Scripts/verify-reach-testbed.sh g7 netbed3   # now flushes NDP too
```

## Known defects and open questions

No gate failed for a reason in the code: every miss traces to the testbed's state. `Docs/process/0.8.0-questions.md`
holds fourteen questions. The ones that change behaviour are these:

- **Q8:** a machine that scans more often than every 20 minutes keeps its ARP cache warm. Its
  history then never gains cold samples, so it pays the 1.5 s first-scan wait every time.
  Seen live.
- **Q9:** an expected host that answers ARP but not ping, with its entry already cached
  (inherited), holds a warm scan to its full wait. Inherited is not evidence, by the brief's
  definition.
- **Q11:** on a dual-stack device, `discovered_via` can hold both `neighbor_resolved` (the v4
  address resolved this scan) and `neighbor_table` (its inherited IPv6 link-local). Seen
  live. The analysis should test membership.
- **Q13:** a powered-off dual-stack host stays present through its NDP entry, for up to a
  day, and never gets a `disappeared`. 0.7.0 does the same. Seen on the testbed.
- **Q14:** a Linux host with two NICs on one subnet (ARP flux) swaps MACs between its
  addresses. History is keyed by MAC, so its cold samples scatter.
- **Q12:** `--look-longer` reuses the latest run's network but not its interface.
- **Q1:** on the command line, history is kept for ever. So is the expected set.
- **Q5:** XNU may send at most one ARP request per second per entry. That would make the
  extra attempts about half as many ARP attempts as they look. A capture during G4 would
  settle it.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01WBYqzzAHubrqLjum2CZLP1
