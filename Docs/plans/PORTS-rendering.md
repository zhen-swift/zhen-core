# Rendering ports in the text output

Written 2026-09-24. Supersedes stage 5 of `Docs/plans/PORTS-plan.md`, which said only
"a port view is a new renderer". This is the design of that view.

## 1. The decision

**Both, chosen automatically from the size of the port set. Not a flag.**

| Port set | Rendering |
|---|---|
| 1-8 ports | **matrix** — one column per port, one row per host |
| 9+ ports | **long form** — one row per open port, under the device table |

A person scanning 3 ports across a /24 and a person scanning `top-100` across one host
are asking different questions, and no single table answers both. Making the user pick
with a flag pushes our design problem onto them.

## 2. Why not a single `PORTS` column

The obvious version — one column reading `22,443` — collapses three states into one.
`Ports.swift` spends its entire file header arguing that this specific collapse is the
defect:

> *A host whose ports are all `.closed` is definitely up. A host whose ports are all
> `.filtered` may not exist.*

A comma list of open ports shows a firewalled host and a dead host as the same empty
cell. The model went out of its way to keep those apart; the renderer must not put them
back together.

## 3. The matrix

```
ADDRESS        NAME                      22   80  443
10.10.20.1     —                          ·    ●    ●
10.10.20.103   Sala de entretenimiento    ○    ○    ·
10.10.20.106   65" Crystal UHD            ·    ●    ·
10.10.20.111   —                          –    –    –

● open   ○ closed   · filtered   – not probed
```

**Four glyphs, not three.** A host that was never port-scanned — discovery found it
after the port stage, or the run went partial — must not be indistinguishable from one
that returned silence. That is the same class of error as the open/filtered collapse,
one level up, and it is the one a matrix invites: every cell looks answered.

**Shape carries the meaning, colour only reinforces it.** Same rule as the paper's
figures and the same rule the app's accessibility work is applying to `StatusDot`. The
table must be readable under `--no-color`, which the study harness uses, and by a
colourblind reader.

**Columns dropped in matrix mode.** MODEL and HARDWARE go. Someone reading a port
matrix is not reading MAC addresses, and the six existing columns plus ports overflows
any terminal. ADDRESS and NAME stay.

**Width.** A port column is `max(5, digits)` wide plus a gutter: 8 ports is 56 columns,
plus 15 for the address, fits 80. Above 8 it does not, which is where the threshold
comes from — it is measured, not chosen.

## 4. The long form

*Example replaced 2026-09-24 when stage 3 landed. It previously drew a STATE column and
repeated the address on every row, and its footer was indented past the right edge of
its own table. What follows is what the code produces.*

For 9 or more ports. Device table unchanged, then:

```
OPEN PORTS
HOST          PORT      SERVICE                 RTT
10.10.20.1    53/tcp    —                       18.54ms
              80/tcp    http                    18.26ms
              443/tcp   https                   26.50ms
10.10.20.103  5000/tcp  http AirTunes 960.13.1  36.69ms
              7000/tcp  http AirTunes 960.13.1  36.93ms
                       5 open · 0 closed · 995 filtered
```

**No STATE column.** Only open ports get rows, so the column is the constant `open`
repeated once per line, costing eight columns of a table that has to hold a service
string. The heading and the footer's leading count carry it — which is why the heading
stays `OPEN PORTS` rather than shortening to `PORTS`, and why the footer keeps leading
with `N open`.

**The address is printed once per host and blanked on its repeats**, so the table reads
as one block per host. The cost is that a line no longer stands alone: `grep 10.10.20.1`
returns only that host's first port, and sorting the output separates a port from its
address. `--json` is the machine-readable path and is unaffected.

**The footer gains a fourth clause when it is needed.** Three counts of OBSERVATIONS,
which is what reconciles with the artifact, then — only when nonzero — a count of HOSTS
that were never probed at all, because that state is the absence of an observation and
has no representation in the artifact to count. It is placed last so the first three
integers can be taken positionally.

**When nothing was open**, the heading and the footer are printed and the column header
is omitted: a header over no rows reads as a table that failed to draw, whereas
`0 open · 900 closed · 0 filtered` is a complete answer.

Only open ports get rows — 100 ports across 9 hosts is 900 rows otherwise. Closed and
filtered are counted in the footer, which preserves the distinction without printing it
900 times.

The long form is also where **service identity** lives. The matrix has no room for it,
and service identity is the most valuable thing a port scan produces. That asymmetry is
fine and worth stating: the matrix answers *which hosts*, the long form answers *what is
running*.

## 5. Terminal width, which the CLI does not currently measure

`TextRenderer` has no width detection at all — the table simply grows and wraps. Adding
port columns makes that visible, so width detection comes first:

| Source | Order |
|---|---|
| `ioctl(TIOCGWINSZ)` on stdout | 1 |
| `COLUMNS` in the environment | 2 |
| 80 | fallback when stdout is not a terminal |

Not a TTY means a pipe or a file, and a fixed 80 is the reproducible choice there.
Anything else makes `zhen … > out.txt` produce different bytes depending on the window
it was launched from, which is the same class of problem the study harness hit with
`NETSANITY_HISTORY`.

## 6. Escape hatch

`--ports-view matrix|long|auto`, default `auto`. Present because the threshold is a
judgement and someone will want 12 ports as a matrix on a wide terminal. It is an
override, not the primary interface — if it turns out people set it routinely, the
automatic rule is wrong and gets fixed rather than documented around.

## 7. What does not change

- JSON and NDJSON. `PortObservation` already encodes everything here. This is a text
  rendering concern only, and the artifact stays the artifact.
- The device table when no ports were scanned. Today's six columns, unchanged.

## 8. Stages

| | Work | Done when |
|---|---|---|
| **1** | Terminal width detection with the three-source fallback | piping to a file gives 80 columns regardless of window size |
| **2** | Matrix renderer, four glyphs, colour as reinforcement only | `--no-color` output distinguishes all four states; a never-probed host is visibly not "filtered" |
| **3** | Long form with the counted footer | 100 ports across 9 hosts prints open rows only and the footer totals reconcile with the JSON |
| **4** | `auto` selection at the 8-port threshold, `--ports-view` override | the threshold is derived from measured column width in a test, not a literal someone chose |

Stage 2 is the one that closes the bug found on 2026-09-24: `scan --deep` scanned ports
and printed none of them.
