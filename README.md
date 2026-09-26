# zhen — the tool

One Swift package: the scanning engine, the command line, and the privileged helper.
The app in `../zhen-app` consumes this; nothing here knows the app exists.

| Target | What it is | Isolation |
|---|---|---|
| `ZhenCore` | Model, time, concurrency, protocols. No platform code. Builds and tests on Linux | non-isolated |
| `CBPFShim` | Header-only C for the `BIOCSETIF` family, which are macros ClangImporter will not evaluate | — |
| `ZhenPrivilege` | The one privileged resource. Small enough to read in a sitting, because a root process should not carry a TLS client around | non-isolated |
| `ZhenDarwin` | Sockets, BPF, `dns_sd`, the route table. Every file behind `#if canImport(Darwin)` | non-isolated |
| `ZhenScan` | The app's adapter over the engine — sibling to the CLI's `ScanPipeline` | non-isolated |
| `zhen` | The command line | **MainActor** |
| `zhen-helper` | The launch daemon the app bundle embeds | non-isolated |

## The isolation table is the important column

Swift 6.2's main-actor-by-default is right for a command line, where entry points and
terminal output are inherently serial, and actively harmful in a scanner, where it would
hop every socket helper onto the main actor and serialize the scan behind the display.

Getting it backwards does not fail. It compiles, it runs, and the scanner is quietly
serialized for the rest of the product's life. That is why the boundary is a target
boundary and not an annotation: there is no keyword to forget.

`ZhenScan` lives here rather than with the app for exactly this reason — it is the one
piece of the app's data layer that must stay off the main actor, and the app target is
main-actor by default.

## Build

```sh
swift build            # the library and the command line
swift test             # everything; on Linux, everything portable
swift build --product zhen-helper
```

`ZhenCore`'s portability is a claim CI checks on every change rather than one this file
asks you to believe. See `.github/workflows/ci.yml`.

Architecture and rationale: `../Docs/01-the-library.md` and `../Docs/02-the-cli.md`.
