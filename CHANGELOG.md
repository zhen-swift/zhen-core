# Changelog

Notable changes, newest first. Dates are when the work landed, not when it was released —
nothing is released yet.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow the app's `CFBundleShortVersionString`.

## Unreleased

### Changed
- **`NOTICE` names the repository, not the organisation.** Its first lines are what a
  redistributor copies into their acknowledgements, so they now say what this is and where
  it lives: Zhen, its author, and `https://github.com/zhen-swift/zhen-core`. A
  `CITATION.cff` is new beside it, for anyone citing the tool in a paper or a report.

## [0.7.0] — 2026-10-12 — ports in history

Ports reach history. A port scan can be kept without being a run, a port opening or
closing is an event, and a device's hardware addresses are kept one row each — the three
things the app was working around. The privileged helper is a product the app can embed,
its check is bounded, and the Local Network advice reads right inside an app.

**Upgrading.** Source-breaking for anyone conforming to `HistoryStore` (one new
requirement), switching exhaustively over `DerivedEvent.Kind` (two new cases), or calling
`ScanRunner.run(…deepScan:…)` (now `ports: PortStage`). `ScanReport.schemaVersion` stays 3:
nothing in `Model/` changed. Once 0.7.0 has written a history store, do not point a 0.6.0
build at it — see the entry on hardware addresses below.

### Added
- **A port scan can be kept in history without being a run.**
  `HistoryStore.recordPorts(_:targeted:at:)` folds a `PortScanResult` into the devices
  history already holds — their ports, and the fingerprint the probe elicited — and
  touches presence not at all: no `appeared`, no `disappeared`, and the latest run stays
  the latest. A host no record holds is skipped, because a port answer is not a
  discovery; so is an absent device's old address, because whatever answers there now
  may be somebody else. Written as the device and event lines the file already has, and
  never as a run line.

  **For anyone conforming to `HistoryStore`**, this is a new requirement, not a defaulted
  method, for the reason `setRetention` is one.
- **Port events.** `DerivedEvent.Kind` gains `portOpened` and `portClosed`, derived when a
  port moves into or out of `open` — the other twelve transitions between the four states
  are not events, and neither is a port seen for the first time. A port the newest scan
  did not ask about is not closed: a device's ports are now merged by port, protocol and
  address rather than replaced, so a run without a port stage no longer forgets them.

  **Source-breaking** for an exhaustive `switch` over `DerivedEvent.Kind`.
- **A device's hardware addresses are kept, one row each.** The ledger has always
  followed a device across a MAC rotation and kept only the newest address. Each record
  now carries `macHistory`: every MAC it has presented, oldest first, with the span it was
  seen over and how it joined — `original`, `rotation(by:)` the identifier that did not
  rotate, or `merge(by:)` the identifier two records shared. On the ledger's `Record`
  and on `StoredDevice`, not on `Device`: like presence, it is history rather than
  observation. A record written before 0.7.0 is seeded from its one MAC, spanning the
  record's first-seen to its last-seen; a rotation before 0.7.0 was never written down.

  **Do not point a 0.6.0 build at a store 0.7.0 has written.** It reads the device lines
  and ignores `mac_history`, reads the port events and drops them, and the first time it
  rewrites the file both are gone. Nothing written by 0.7.0 can prevent that.
- **A port stage for new devices only.** `PortStage` — `off`, `everyHost`, `newHosts` —
  and `ScanRunner.run(network:budget:ports:progress:)` takes it. "New" is history's
  answer, through `firstSeen(for:in:)`, so a device that rotated its MAC is not new and is
  not re-probed for it. **Source-breaking:** `run(…deepScan:…)` is gone; `true` is
  `.everyHost` and `false` is `.off`.
- **`ScanRunner.probePorts(_:spec:budget:progress:)`.** Probes known addresses and keeps
  the result through `recordPorts`: no discovery, no naming, no run. What an app needs to
  scan one device's ports without taking the rest of the network offline.
- **The helper check at scanner build is bounded at 750 ms.** Building a scanner under
  `.helperThenDirect` asks whether a helper answers, and a registration launchd cannot
  start accepts the connection and never does. That check waited out the full 3 s
  acquisition timeout — 3.2 s on every engine build, measured in the app on a Mac with a
  stale registration. `HelperClient.probeTimeout` now bounds the question "is anybody
  there"; a scan's own acquisitions keep `acquisitionTimeout`. Once the check fails the
  privileged engines are not built, so nothing waits again until the next build.
- **The Local Network remedy is worded for an app when it is read in one.**
  `ProbePermissionAdvice.appleLocalNetworkInApp` gives the same grant without the sentence
  telling a command-line build its permission may be listed under the terminal — true for
  `zhen`, wrong in an app, and something the app was cutting out of core's text at runtime.
  The sweep and the naming stage pick it themselves, from whether the running bundle is an
  `.app` (`ProbePermissionAdvice.appleForThisProcess`); the command line's text is unchanged.
- **A `zhen-helper` product.** The privileged helper was an executable target with no
  product, so it never crossed the package boundary: the app could not embed it from the
  version it pins and built it by hand from a checkout. Declaring it changes no scheme
  list — measured: this package already showed a `zhen-helper` scheme when opened alone,
  and the app's project shows none for a remote package's products.
- **`zhen ports --record`.** Keeps what the scan found in history, through the call
  above: ports and port events for devices history already holds, never a run. Off unless
  asked for, because the command has written nothing since it was added. An interrupted
  scan keeps what it had probed, as an interrupted `zhen scan` does. Written where `zhen
  scan` writes, so `ZHEN_HISTORY` moves it too.
- **`Contrast`, for choosing a foreground that reads on a background at runtime.** WCAG 2
  ratios, the three floors that apply to this project (3:1 non-text, 4.5:1 AA, 7:1 AAA),
  and `Contrast.foreground(on:preferring:level:)`, which keeps the first candidate that
  meets the floor and otherwise returns the best one marked as falling short. Colours are
  `SRGBColor`, gamma-encoded components with no UI framework behind them, so the rule is
  the same on Linux and is tested there. The tests reproduce the 100 pairs the app's
  previous palette measured, against all three of the surfaces it drew text on. That
  palette was derived by hand against one of them and was wrong on the other two.

### Fixed
- **A merge is logged once.** A run that proved two records were one device logged the
  `merged` event twice, same id — once by the join and again by the fold. Found by the
  0.6.0 history fixture, which holds exactly that pair. Existing duplicates in a store are
  left as they are: removing them would be rewriting history to tidy it.
- **A line this build understands only in part is kept, not dropped.** An event whose kind
  it does not know, or a device whose key kind it does not know, decoded as a line and was
  then skipped — and erased at the next compaction. They are now kept verbatim, like a line
  that does not decode at all. This is the fault that lets a 0.6.0 build erase 0.7.0's port
  events; fixed here so 0.7.0 cannot do the same to whatever comes next.

## [0.6.0] — 2026-10-05 — the former name, retired

### Removed
- **The rename's compatibility layer.** It existed to carry history across the
  project's rename: a one-time copy of the store under the former name into `zhen/`,
  and the former name of the history override, still honoured. Nothing was ever
  released under the former name, and the one installation that had history under it
  migrated on 2026-09-22. `ZHEN_HISTORY` is now the only override; the former variable,
  if left in a shell, is ignored and the scan uses the default store.

  **For anyone importing `ZhenCore`**, four public members are gone:
  `HistoryLocation.legacyOverrideVariable`, `.legacyDirectoryName`, `.legacyStore(…)`
  and `.migrateLegacyStore(…)`.

  The measurement study keeps the former name throughout, because that is what it
  measured.

## [0.5.0] — 2026-09-22 — the privileged path

### Added
- **The app opens on a machine that is not the one that built it.** Signed with a
  Developer ID certificate, notarized by Apple and stapled, so a quarantined copy —
  which is what a download is — assesses as `accepted, source=Notarized Developer ID`
  rather than being blocked on first open. It matters here more than for most tools: a
  person who cannot open the app never reaches the button that installs the privileged
  helper, so every capability below was unreachable for anybody but its author.

  The ticket is stapled into the bundle, so this holds with no network at all. Verified
  with Wi-Fi off, which also corrected a belief worth writing down: `stapler validate`
  is **not** a local check and fails offline trying to reach Apple's ticket-delivery
  service. `spctl` is the one that answers the question, and it accepts.

  `Scripts/release.sh` is the path from a build to that bundle — sign, check the
  signing before uploading anything, package with `ditto`, submit by keychain profile
  name, staple, then assess a freshly quarantined copy rather than the local build. The
  credential is never handled by the repository.
- **A duplicate device record is joined rather than left standing.** Two records that
  turn out to be one device — a private Wi-Fi address that rotated between a
  discovery-only scan and a full one — are reconciled into the older of them, at the
  fold and when the history file is opened. The join is announced with a `merged` event,
  a kind the model and the design system had both declared and nothing could produce.
  Records sharing only a DHCP lease are still left alone, because two devices that held
  one address at different times are not one device.
- **The privileged path is real, and it is composition rather than replacement.**
  Under `sudo`, `zhen` opens a packet-capture device and adds a layer-2 ARP sweep,
  half-open SYN scanning and TCP stack fingerprinting, on top of everything the
  unprivileged run already does. Running as root never finds *fewer* hosts: the two
  discovery engines are unioned, because an either/or would lose every host that answers
  ICMP but not ARP. Selection is by attempting the open rather than by checking the
  effective user id, which is wrong in both directions — root with every `/dev/bpf*`
  node held by Wireshark has exactly the capability an ordinary user has.
- **Open ports say what they are.** A banner probe reads SSH, SMTP, FTP, POP3, IMAP and
  VNC greetings, an HTTP `Server` header, or a TLS certificate subject. `ServiceIdentity`
  is still never inferred from a port number: 22 is where SSH usually is, not evidence
  that SSH is there.
- **Stack fingerprinting, with the evidence attached.** One option-bearing SYN per host,
  matched against a deliberately small table of stack lineages. The observed features
  travel with the verdict whether or not anything matched, so a reader can disagree with
  the table and a future signature can be written against reports already collected.
  Distinct from `osHint`, which is one TTL band and always was.
- **Each host says how it was found.** `discovered_via` records `probe_reply`,
  `arp_reply`, `neighbor_table` or `local_interface`. A measurement study compared
  `hosts_found` against the echo replies in its packet captures, found them disagreeing
  in 431 of 485 runs, and could not settle from the artifact whether the scanner was
  inventing hosts. It was not: two testbed hosts answer ARP and ignore ICMP and were
  reported from the neighbour table, and one address was the scanner's own — a probe a
  host sends to itself is answered inside the kernel and never reaches the wire.
  Reconciling a scan against `tcpdump` now means comparing against the hosts that claim
  to have answered.
- **A manual page and an installer.** `zhen.1` documents every exit code by having
  produced it, and `Scripts/install.sh` builds release, reads the embedded `Info.plist`
  back out of the Mach-O before copying anything, and never runs `sudo` on your behalf.
- **Exit codes a script can branch on.** 0 for a scan that ran, including one an expired
  deadline cut short; 64 usage; 69 a capability that is not there; 75 transient; 130 the
  first interrupt, which commits what was gathered.
- **The app remembers, and remembers the same things the command line does.** History
  moved from an in-memory store to the file `zhen scan` already writes, so a scan
  run in a terminal is in the app when you open it and vice versa. `HistoryLocation`
  moved into core to make that literally one answer rather than two that agree until one
  changes. With nowhere to put a file the app keeps history for the session and the
  Settings screen says so, read from the store that was actually opened rather than
  claimed.
- **History is read at launch, not only after a scan.** The store was being written and
  never read back, so the app opened on "No scan yet" with a full history file beside it
  — indistinguishable from not persisting at all, at the one moment a person is looking
  to see whether it remembered. `hasScanned` stays false: a store with no devices means
  "nothing answered last time", which is a different empty state from "nothing answered
  just now".
- **Settings survive quitting.** The scan budget, the interval, deep-scan and retention
  were all forgotten on close — you could set a budget, quit, and be back to the default
  without being told. Stored in `UserDefaults`, not in the shared history file, because
  they describe how this copy of the app behaves rather than what is on the network. A
  stored value that is no longer an offered option falls back rather than leaving a
  picker showing something it cannot display.
- **Retention deletes something.** The picker offers 30 days, 90 days, a year or
  forever, and the choice now reaches the store and prunes on the next scan. It offered
  only "This session" before history outlived the session, which was honest and inert;
  for one commit it offered four real windows and was still inert, which was neither. The
  rule lives in `HistoryLedger` beside the fold rules, so a second conformance cannot
  carry a second copy of it, and it takes **events only** — a pruned device record is a
  device that comes back as newly discovered, which is a false alarm manufactured by a
  housekeeping setting. Identity is kept forever and Settings says so under the picker.
  The policy is a parameter defaulting to forever and the command line passes the
  default, so `zhen` behaves exactly as it did.
- **`zhen hosts`, `events`, `history <host>` and `export`.** The scanner could
  record nothing and therefore could not be asked anything about the past; `scan` now
  writes every run to a history file and these read it back. Absent is a state rather
  than a deletion — a device that stopped answering keeps its row and its last known
  address, because "seen two hours ago" is information and dropping it would silently
  shrink the network. Each takes `--json`, `--since` and `--store`.
- **The history file, and whose it is.** Under `sudo` every home-directory API answers
  `/var/root`, so a privileged scan would file its history where the person who typed the
  command cannot read it — and their next unprivileged scan would open an empty store and
  report the whole network as newly appeared. The path is rebuilt beneath the home of the
  user named in `SUDO_USER`. The spec listed this as a risk; this is the answer to it.
  `ZHEN_HISTORY` overrides it exactly, with nothing appended or assumed.
- **`LogHistoryStore`: the portable half of the persistence ruling.** An append-only
  file, one JSON object per line, in core so it reaches Linux. Append-only rather than
  rewrite-in-place because an interrupted scan then loses the last run and nothing else,
  where rewriting makes every scan a moment the whole history is one crash away from a
  truncated file. It compacts past a threshold — a log that only grows makes opening the
  store the slowest thing the CLI does — and the compaction is the one moment it rewrites
  rather than appends, so it is the one moment that gets an atomic write. The format is
  deliberately dull: greppable for a MAC, truncatable at a line boundary, readable with
  `head`.
- **`HistoryLedger` in core** — the rules for folding a run into history, as a value type
  with no I/O, no actor and no platform. Which candidate keys may join a new observation
  to an old one, which differences earn an event, and which earn one only from the second
  run onward. The seam was moved into core so a second conformance would be cheap; that
  only holds if the expensive part sits above both, and this is the expensive part.
  `InMemoryHistoryStore` is now fifty lines that hold one.
- The store suite runs against **both** conformances that ship — the log and the
  session-lifetime store. Two stores behind one protocol are only one idea if they behave
  identically, and identical is not something a protocol can require: it has no opinion
  about whether two devices swapping DHCP leases merge. What only a file can claim is
  tested where the file is, in core: a device kept across a reopen keeps its original
  first-seen and is not reported as newly appeared, the event log accumulates rather than
  restarting, and two writers racing on one file lose nothing.
- **`HistoryLedger` has a test suite of its own.** Its rules were reachable only through a
  store, so a defect in a rule would have been reported as a storage failure. Retention
  and the identity collision live there now, tested against a clock nobody has to wait
  for.
- **`zhen scan --retransmit-timeout <duration>` and `--shared-budget`.** Two ways
  to make the scan slower, on purpose. The first pins the interval before an unanswered
  probe is resent, which is otherwise measured from the network and re-derived as
  replies arrive; the second collapses that interval and the end-of-scan wait into one
  number, which is what the sweep did before they were separated. The split budget and
  its adaptive interval are the claims this scanner's speed rests on, and a claim like
  that is only falsifiable against the same scanner with the mechanism removed —
  measured against nmap's templates instead, every other difference between the two
  programs comes along for the ride and nothing is isolated. Measured against the
  study's shaped testbed, which is where a timing number means anything — same three
  hosts and same three replies every run: 0.37 s
  adaptive, 0.49 s with the interval pinned at 150 ms, 0.94 s with the budgets shared.
  Both ablations cost, and they cost differently, which is what makes them separable.
  Mutually exclusive, and refused together rather than one quietly
  winning. An imposed interval is deliberately *not* clamped into the adaptive path's
  25–150 ms range: those bounds keep a measurement sane and there is no measurement
  here, so 5 ms means 5 ms.
- `budget_policy` on each stage in the artifact — `split`, `shared` or
  `fixed-retransmit`. `retransmit_budget_millis` already said what interval was used;
  this says where it came from, and they are different facts. An imposed 150 ms and a
  measured 150 ms are identical in every other field and mean opposite things about the
  network: one says the operator asked for it, the other says half the hosts answered
  inside 75 ms.
- **`zhen scan --discovery-only`.** Report what is on the network without
  resolving what it is called: mDNS, SSDP and NetBIOS are skipped and the scan finishes
  as soon as discovery does. Naming is roughly 85% of a default scan's wall clock on a
  home network — 2.65 s of a 3.1 s run — and it is the flat part, taking its budgeted
  time almost regardless of what discovery found. Recall is unchanged; the mode changes
  what is reported *about* the hosts, not which hosts are found. Named positively rather
  than `--no-naming` so it says what you get and composes with `--deep` without a double
  negative.
- `run.mode` in the artifact, `"full"` or `"discovery_only"`. Under the new mode the
  naming stage is *absent* from `timing.stages` rather than present and zeroed, because
  a stage that ran and found nothing is a different fact from a stage that never ran —
  but absence has other causes too, so the mode is stated in a field rather than left to
  be inferred from which stages happen to be missing.
- `spacing_policy`, `spread_budget_millis` and `spacing_jitter` on each stage in the
  artifact, so a reader comparing two scans can tell whether they were probed on the
  same schedule before concluding anything from a difference in what they found.
- Open-source scaffolding: `LICENSE` (Apache 2.0), `NOTICE` with third-party
  attributions, `CITATION.cff` so the work can be cited from a paper,
  `CODE_OF_CONDUCT.md`, issue and pull-request templates, Dependabot, and
  `.editorconfig`.

### Fixed
- **`Scripts/verify-syn-scan.sh` counted the kernel's SYNs as ours.** It reported
  "SYNs carrying TCP options" as the fingerprint probes, "and only the privileged path
  emits them", while printing 27 of them for the unprivileged run, which emits none —
  it was measuring every `connect()` the machine made. It now discriminates on the
  option order, because the two SYNs are built by different code and Darwin never emits
  SACK-permitted directly after the MSS. A verification whose label and whose output
  disagree is worse than no check, because it reads like one.
- **A scan in a terminal and a scan in the app could delete each other.** They share one
  history file on purpose, and nothing made that safe: an actor orders the writers inside
  one process and knows nothing about the one in the other window. The append was
  `seekToEnd()` and then a write, so a run appended between those two calls was written
  over; and compaction rewrote the whole file from a ledger read before the other process
  existed, which turned "written over" into "deleted". Recording is now a read-fold-write
  under an exclusive `flock`, appends go out with O_APPEND so the kernel resolves the
  offset and the write together, and nothing is cached between calls — the file belongs
  to whoever else has it open as much as to this process. The lock is a sidecar beside the
  log rather than the log itself, because compaction replaces the log's inode and two
  processes locking either side of that rename exclude nobody.
- **The same history file could fold the same run two different ways.** `HistoryLedger`'s
  identity resolution fell back to scanning a Dictionary for a record carrying the
  candidate identifier, so when two records carried one — which two processes writing one
  file makes ordinary — the winner was decided by hash order. The fallback now takes the
  record that claimed the identifier as its primary key, and otherwise the oldest one:
  the record with the history behind it, and the only choice that does not change its
  answer every time a new device joins the network.
- **The anti-collapse guard's rationale argued against its own conclusion.** "Merging is
  recoverable and un-merging is not" — it is the missed merge that is recoverable, since
  a later observation carrying a shared key joins the two records. Corrected here and in
  the specification, which had the same sentence.
- **The retention picker did nothing at all.** It saved a choice to `UserDefaults` and
  no code anywhere read it — the same defect, in the same commit, as the Settings line
  that claimed persistence the app did not have. `HistoryStore` now requires a store to
  accept a policy, as a requirement rather than a defaulted extension method, because a
  default implementation is how a conformance inherits a setting it silently ignores.
- **`FileManager.createFile` is not create-if-absent.** Called on a file that exists it
  leaves a different inode behind, so two writers starting together each made "the" lock
  file and locked two different ones. Found by the race test rather than by reading: it
  cost one writer its first run, every time, and nothing else would have shown it.
- **Activity lost the window's top and bottom bars, and everything jumped up.** macOS
  draws those bars over a detail column that scrolls, so a screen that is a `ScrollView`
  when it has rows and a plain view when it is empty changes the window's chrome
  underneath it. Activity is empty by design after a first scan — events are differences
  between runs — so it was the room that showed it. `ScreenScroll` now decides the
  container from the screen rather than from its contents: an empty state still gets a
  scroll view, it just has nothing to scroll. Applied to all four non-scrolling branches,
  including "no scan yet", which is what a person meets on first launch.
- **The sidebar had a ragged left edge.** The section label sat 16pt from the edge, the
  room names at 8 + 12 = 20, and the scan footer at 16 again — so the rows were four
  points right of the title above them and the status below them. A3 states the selection
  pill's 8pt inset and says nothing about where text goes inside it, so the three call
  sites each decided. `sidebarTextInset` is now composed from the pill's inset and the
  text inset within it, and the label and footer use it, so sidebar text has one left
  edge by construction rather than by three agreements.
- **The screen title moved when you changed rooms.** Four screens each padded their own
  header, and two of them chose differently — 20 above and 12 below on Devices and
  Activity, 16 and 16 on Settings and Live Scan. Both total 32, so the block was the same
  height everywhere and only the title inside it shifted, by four points, at the one
  moment a person is looking at the sidebar rather than the words. A1 gives `contentInset`
  as horizontal only and never specified the vertical padding, so there was no answer to
  look up; `headerBlockHeight` was declared in `Metrics` and referenced by nothing.
  `ScreenHeader` now owns the title, the subtitle and every inset, and the screens supply
  only what goes on the trailing edge. Measured in a test rather than asserted. Found by
  running the app and switching rooms, which nobody had done before.
- **`ZhenCore`'s tests now RUN on Linux, and one of them failed there.** CI built
  the module on Linux and stopped, because `swift test` could not compile:
  `ZhenDarwin`'s sources are each wrapped in `#if canImport(Darwin)` and its tests
  were not — and one suite in `NameSourceTests` sat after the `#endif` entirely, which
  nothing on macOS could notice. With the guards consistent, 182 portable tests run on
  Linux, and they immediately caught a real defect: `LogHistoryStore`'s compaction used
  `FileManager.replaceItemAt`, which works on Darwin and does not leave the file at the
  original URL on swift-corelibs-foundation. It compiled everywhere and was broken on the
  one platform the type exists for. Now an atomic `Data.write`, which is both simpler and
  portable. CI runs the suite rather than only the build.
- **Correlated loss took all three transmissions to a host, not one.** The retransmit
  budget is driven from a low quantile of observed round trips, which is right when
  losses are independent — but it also decided how far apart the three transmissions to
  an address were, and those are not the same question. Three gaps of fifty milliseconds
  span less than one Wi-Fi power-save outage, so a sleeping phone missed all three and
  was reported absent. The final transmission is now scheduled *into* the tail window
  the sweep was going to spend idling anyway, and each host's gaps are scattered ±25%
  deterministically from its address so a fixed interval cannot resonate with a periodic
  outage. Simulated at 15% marginal loss, recall at a 100 ms mean outage goes from 0.910
  to 0.976, and the sweep ends when it always did — the declaration instant is anchored
  to the last *tight* transmission. Under independent loss nothing changes at all.
  (`Study/THEORY.md` correction C8.)
- CI ran on `macos-15` against a package declaring a macOS 26 floor. That runner has
  neither the SDK nor the Swift 6.2 toolchain `Span`, `InlineArray` and
  `.strictMemorySafety()` require, so the job could not have passed. Now `macos-26`.
- The CLI's embedded `Info.plist` reported version 0.2.0, two releases behind the
  changelog. **The other half of that fix, 2026-09-09:** `--version` was still printing
  0.2.0, so correcting the plist had left the binary disagreeing with itself. The two
  cannot be one constant — the plist is a static file the linker embeds via
  `-sectcreate` — so a test pins them together instead, the way the Bonjour list and the
  generated project are pinned.

### Changed
- **The version is declared once, in core.** It was in two places and they disagreed,
  the command line reporting two releases behind its own plist; a test then pinned that
  pair and left the shape untouched, with the app declaring its own copy and
  `CITATION.cff` a third. `ZhenVersion.current` is now the only declaration, and
  the derived files are checked against it rather than against each other.
- **SwiftData is not in the product, and the 2026-09-09 ruling is amended to say so.**
  The app was wired to the log file `zhen scan` writes, because one shared file is
  the only reason the app and the command line agree about the network — which left
  `SwiftDataHistoryStore` referenced by nothing but its own tests: 265 lines, a schema,
  and a chunk of `AppTests` maintained for a conformance that shipped nowhere. It was
  also holding the place in the store suite that the conformance the app actually opens
  did not have, and costing an Xcode-only macro plugin as a build prerequisite. History
  is the portable log on every platform; the seam keeps two conformances, both of which
  ship. The amendment is recorded in the specification, in document 03 and in the review,
  because a repository holding two answers to one question is worse than either answer.
  What it would take to bring SwiftData back is written down with it.
- **The SwiftData ruling came: portability wins, and the seam is how.** The spec's
  "SwiftData only, no alternative store, not even as a cache" was written before the
  portability requirement existed, and the two cannot both hold — SwiftData is
  Darwin-only. There are to be two `HistoryStore` conformances and no more: SwiftData on
  Darwin, an append-only log with an index everywhere else, both writing the same model
  types so an artifact from either is readable by both. Neither is a cache of the other,
  which is the part of the original rule worth keeping. Nothing is implemented yet; this
  records the decision the seam was moved into core in anticipation of, and amends the
  spec's requirement in place rather than leaving it contradicted.
- **Documents are cited by name, and the headings lost their numbers.** `A1 §7` became
  `A1's accessibility floor` throughout, and the rule is written down in
  `CONTRIBUTING.md`. A section symbol goes stale silently the moment a heading moves,
  and it tells a reader nothing about what they are about to look for. The numbers came
  off the headings in the same pass, because a number printed above a section is an
  invitation to cite it — leaving them would have left the rule arguing with the
  documents. External standards keep the convention: `RFC 1002 §4.2.18` is unchanged.
- The pinned-versus-scrolling rule is now recorded in `Corrections.md` as well, not only
  in A3's pinned-context rule. The rule and its implementation landed with the review;
  the entry that stops someone undoing them did not.
- **The palette honours Increase Contrast.** Every token moved from an
  `NSColor(name:dynamicProvider:)` to a custom `ShapeStyle`, which is handed the whole
  environment and can therefore read `\colorSchemeContrast` as well as `\colorScheme`.
  The old provider could not: macOS's accessibility appearances collapse into their base,
  so `bestMatch` never saw the setting and no test could construct one to check. Text
  tokens now clear 7:1 against all three surfaces in both themes when the setting is on,
  and separators and the offline ring reach WCAG 1.4.11's 3:1. AppKit is gone from the
  design module. Since `\colorSchemeContrast` is get-only and neither a preview nor a
  test can set it, a `paletteContrast(_:)` modifier overrides the tier for design review
  and for the contrast suite.
- `HistoryStore`, `DerivedEvent` and `StoredDevice` moved from `ZhenScan` to
  `ZhenCore`. The protocol was declared inside the app package, where the CLI
  cannot reach it — fine with one conformance, wrong the moment the SwiftData decision
  lands and produces a second one, because a Darwin store and a portable log have to
  satisfy the same protocol or they are two unrelated types sharing a name. The
  in-memory conformance stays in `ZhenScan`; only the seam moved. No behaviour
  changed. The ruling came the following day, and it is the two-conformance answer this
  move was made in anticipation of.
- Licence moved from CC BY-NC 4.0 to the Apache License 2.0. Creative Commons themselves
  advise against CC licences for software; NonCommercial is not an open-source licence
  by any accepted definition, is undefined enough that legal teams refuse it outright,
  and says nothing about patents. Apache 2.0 grants a patent licence, which MIT does
  not, and lets a reviewer reproduce the work without asking anyone's permission.

## [0.4.0] — 2026-09-04 — the app

### Added
- **A SwiftUI app that scans the real network.** Three rooms, the device list, device
  detail, the live scan screen and settings, all bound to live data. First device on
  screen 120 ms after launch, warm.
- **`Zhen.xcodeproj`**, generated by `Scripts/generate-xcodeproj.py` and owned by
  it. Two shared schemes; ⌘U runs all 38 tests through a target hosted by the app.
- `Scripts/build-app.sh`, which assembles a real bundle around the SPM binary. The
  `Info.plist` is generated by asking the binary, so `NSBonjourServices` cannot drift
  from the list the discovery layer actually browses.
- A `HistoryStore` protocol with an in-memory conformance. First-seen, last-seen,
  presence and the derived event log are correct within a session; the Darwin-versus-
  Linux persistence question stays open and this phase does not force it.

### Fixed
- **The sidebar was paying for the table.** Fixed-width columns gave the device list a
  hard intrinsic minimum, and `NavigationSplitView` in `.balanced` style took the
  difference from the sidebar — 228pt on Settings, 134pt on Devices at a narrow window.
  Columns are ranges now, the sidebar is pinned, and the window has a minimum that was
  measured rather than derived.
- Vertical-only scrolling over fixed-width content silently dropped the last column.
- The live scan's stage strip and Activity's histogram scrolled away exactly when there
  was enough content to scroll. Both are pinned; the rule is written down in A3's
  pinned-context rule.

## [0.3.0] — 2026-09-03 — the design system

### Added
- `ZhenDesign`: the token layer, every component, all five screens, and a DocC
  catalogue. Depends on nothing — not even the scanner — which is what lets every state
  be checked without a network.
- Fixtures taken from the real network, including a curly apostrophe and seven anonymous
  rows out of ten, because lorem ipsum hides exactly the problems this design solves.

### Fixed
- **Two rounds of contrast failures.** The artboard values were 3.00:1 and 2.24:1. The
  first correction was measured against one background when the design has three, and
  still failed at 4.18:1 and 3.89:1 on the raised surface. Every text pair now clears
  4.5:1 against every surface, and a test measures it through the same provider the
  views use.
- The asset-catalogue approach the appendix specified cannot work: `swift build` never
  runs `actool`, so every colour resolved to white. Replaced with dynamic providers.

## [0.2.0] — 2026-09-03 — naming

### Added
- mDNS over `dns_sd` with one shared connection, SSDP, and NetBIOS, arbitrated by the
  name cascade. Bonjour is a primary source, not a fallback.

### Fixed
- **NetBIOS never ran.** Its deadline was struck at stage start for 30% of the stage,
  and the concurrent phase ahead of it takes 70% — so the slice had always expired.
  Nothing failed; a source was simply never asked.
- Server-side request forgery in the UPnP description fetch, and no bound on the
  response size. See `SECURITY.md`.
- A Unicode crash: a range computed against `lowercased()` and used to slice the
  original trapped on any name containing `İ`, `K`, `Å` or `ẞ`.
- The denial heuristic blamed the Local Network permission for failures it had not
  checked for, and named sources that had not run.

## [0.1.0] — 2026-09-01 — the engine

### Added
- `ZhenCore`: the output model, deadlines, bounded concurrency and the engine
  protocols. Portable, and proven so by building it on Linux in CI.
- `ZhenDarwin`: unprivileged ICMP sweep, the neighbour table, TCP connect scanning.
- `zhen`, the command-line tool, with text, JSON and NDJSON output.
- **Retransmit early, declare late** — the two-budget timing split that makes a `/24`
  take about three seconds instead of thirty.
