# zhen-core 0.7.0 — ports in history

**Base:** `main` · **Tag:** `0.7.0` → `9a2310a` (annotated, local) · **Supersedes:** #5, the
contrast helper, which this branch contains unchanged (`17ce2cf`)

A port scan can be kept in history without being a run. A port opening or closing is an
event. A device's hardware addresses are kept, one row each. Those are the three things
zhen-app was working around. The helper is a product, its check at scanner build is bounded,
and the Local Network advice reads right inside an app.

> **Please merge with a merge commit and push the tag as it is.** zhen-app's companion PR
> pins 0.7.0 at `9a2310a`. A squash merge re-tagged on `main` works too, but then the app
> must be re-resolved before its PR merges.

## The changes

| # | Change | Commit |
|---|---|---|
| 8 | `Contrast` and `SRGBColor` (PR #5), unchanged | `17ce2cf` |
| 1 | `HistoryStore.recordPorts(_:targeted:at:)`, a new **requirement**: folds a `PortScanResult` into the records history holds. No presence change, no run line; an unknown host or an absent record's old address is skipped | `ef1d976` |
| 2 | `DerivedEvent.Kind.portOpened` / `.portClosed`, for transitions involving `open` only, and never from a port that was not asked about. Ports are merged by port, protocol and address rather than replaced | `ef1d976` |
| 3 | `zhen ports --record`, off by default; `MANUAL.md` and `zhen.1` name it | `6a102ac` |
| 9 | `Record.macHistory` / `StoredDevice.macHistory`: every MAC, its span, and how it joined (`original`, `rotation(by:)`, `merge(by:)`). On the record, not on `Device` | `9bfb877` |
| — | Migration gate on a store written by 0.6.0's own code; plus two defects it found | `b223e6d` |
| 4 | A `zhen-helper` executable product | `77e559e` |
| 5 | `PortStage` (`off`, `everyHost`, `newHosts`) on `ScanRunner.run`, and `ScanRunner.probePorts` | `429f141` |
| 6 | `HelperClient.probeTimeout`, 750 ms, for the scanner-build check (acquisitions keep 3 s) | `3198d6b` |
| 7 | `ProbePermissionAdvice.appleLocalNetworkInApp`, chosen from the running bundle | `e38e19b` |
| — | Release 0.7.0 | `9a2310a` |

## Fixed along the way

- **A merge was logged twice**, same id: `fold` re-logged what `reconcile` had already
  logged. The 0.6.0 fixture shows the pair.
- **A line half-understood was dropped.** An event or key kind this build does not know
  decoded, was skipped, and compaction then erased it. It is now kept verbatim. This is the
  mechanism by which a 0.6.0 build erases 0.7.0's port events (below).

## Breaking

- `HistoryStore` has a new requirement.
- `DerivedEvent.Kind` has two new cases.
- `ScanRunner.run(…deepScan:…)` is now `run(…ports:…)`.
- `ScanReport.schemaVersion` stays **3**, because no `Model/` type changed. The argument is in
  `Docs/process/0.7.0-progress.md` (DM.5).
- **Do not point a 0.6.0 build at a store 0.7.0 has written.** It drops port events and MAC
  history the next time it rewrites the file. The CHANGELOG says so; questions Q1 has the one
  mitigation, which the brief's frozen shape ruled out.

## Verification

- `swift test`: **632 → 673**, all green on macOS 26. Every new behaviour was shown failing
  first, either against a stub or by breaking the line a guard protects. Each is recorded in
  the ledger.
- **Old logs load:** `Tests/ZhenCoreTests/Fixtures/history-0.6.0.ndjson`, written by
  `Scripts/make-history-fixture` (pinned to `exact: "0.6.0"`), loads, folds and compacts with
  nothing lost. The gate was shown failing on a reader that drops undecodable lines, and on
  one that requires the new field.
- `Scripts/check-docs.sh` and `check-manpage.sh` pass. The man-page check was red on
  `ports --record` until the page named it.
- **Linux** (`swift:6.2` in a lima VM): `ZhenCore` builds. The suite aborts at the known
  AUDIT M2 `try!`, exactly as the baseline does. With the M2 suites skipped: 473 tests (439
  at baseline), with the same two container-only `CLITests` failures as the baseline.
- No `unsafe`, `@unchecked` or `nonisolated(unsafe)` in `ZhenCore`.
- Not run: `swiftlint` (not installed), GitHub CI (nothing pushed).

## Known defect

**K1:** this package still shows a `zhen-helper` scheme when opened on its own in Xcode, as
it did before. Hiding it could not be verified from the command line (questions Q3). The
app's scheme list, which is what the objection was about, is unaffected.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
