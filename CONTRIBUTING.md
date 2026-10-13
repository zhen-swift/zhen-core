# Contributing

Contributions are welcome. Read this first — it is short, and it explains the two or
three ways this codebase is opinionated in a way that is easy to trip over.

## Before you start

```bash
./Scripts/verify-environment.sh          # toolchain, signing, descriptor limits
swift test                               # the whole package
./Scripts/verify-linux.sh                # proves ZhenCore stays portable
```

All three must pass before and after your change. If `verify-linux.sh` says it cannot
check, that is not a pass — it needs Docker, Podman, or a matching Linux Swift SDK.

## The three rules that are not negotiable

**No subprocesses.** No `Process`, no `posix_spawn`, no shelling out, no bundled
binaries. Everything is done with system calls and frameworks. A test enforces it.

**`ZhenCore` stays portable.** It compiles on Linux. Darwin-only machinery —
`dns_sd`, kqueue, BPF, the route socket — is reachable only through protocols declared
in `Sources/ZhenCore/Platform/`. A `#if canImport(Darwin)` inside a public type in
core is a design failure; a protocol with two conformances is not.

**Actor isolation runs the opposite way in each half.** `ZhenCore`, `ZhenDarwin`
and `ZhenScan` build with `.defaultIsolation(nil)`. The app, which lives in
[`zhen-app`](https://github.com/zhen-swift/zhen-app), builds with
`.defaultIsolation(MainActor.self)`. If you find yourself adding `@MainActor`
to make something in the scanning half compile, stop — that is UI leaking into the
scanner, and the annotation would serialize every socket operation behind the window.

## Failures are values, not logs

A probe that gets no answer is a value. A budget that expires is a normal return
carrying partial results. A capability that is missing is a `Degradation` — a struct
with a plain-language consequence — that travels to the surface and gets rendered.

There is no logging framework here and adding one would be a step backwards. If
something goes wrong and a person should know, it becomes a `Degradation`. If nobody
should know, it does not need saying.

Write the consequence, not the error. "Bonjour names can't be read this scan" is useful;
"mDNS: EPERM" is not. And hedge what was inferred — the Local Network permission cannot
be queried, so the copy says "appears to be denied".

## The app and its design system

They live in [`zhen-app`](https://github.com/zhen-swift/zhen-app), which depends on this
package by version. Contributions to either go there. Nothing in this repository knows the
app exists, and a change here that needs the app to compile is in the wrong repository.

## Referring to the documents

Refer to a section by its name, never by a section symbol. `A1's accessibility floor`
and `document 03's note on the Local Network permission` survive a document being
reordered and tell a reader what they are about to look for; `A1 §7` and `03 §6.4` do
neither, and go stale silently the moment a heading moves.

The one exception is citing an external standard, where the symbol is the convention —
`RFC 1002 §4.2.18` stays as it is.

This is why the headings in `Docs/` carry no numbers. A number printed above a section
is an invitation to cite it, so the documents do not offer one: the name in the heading
is the whole of what a reference needs.

## Comments

Comments here explain *why*, not *what*. A comment restating the code is noise; a
comment recording the failure that made the code look like this is the most valuable
thing in the file. Several of them are the only reason a subtle bug has not come back —
the TXT key `md` means a model on `_googlecast` and a metadata list on `_raop`, and the
comment saying so is load-bearing.

## Commits

Explain the decision, not the diff. The diff is in the diff. What is not in the diff is
why the obvious approach was rejected, what was measured, and what is still unverified —
and that is the part a reader needs six months from now.

## Licence

By contributing you agree your contribution is licensed under the Apache License 2.0,
the same as the rest of the work, including the patent grant in section 3. No separate
contributor licence agreement is required.
