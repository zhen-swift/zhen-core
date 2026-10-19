// swift-tools-version: 6.2
import PackageDescription

// ── One package, because there is one tool ──────────────────────────────────────
//
// This was two packages, `zhen-core` and `zhen-cli`, and the split bought nothing: no
// one ever depended on the engine without the tool, and the folder named "core" at the
// repository root read as a third product beside the CLI and the app when it is neither.
// The app now consumes THIS package and the app's own sources live in its Xcode project,
// which is the whole shape of the reorganisation.
//
// ── The isolation settings are not uniform, and that is the point ───────────────
//
// Library targets stay non-isolated on purpose. Swift 6.2's main-actor-by-default is
// right for a UI shell and actively harmful in a scanner: it would silently hop every
// socket helper onto the main actor and serialize the scan behind the UI.
//
// The executable is the inverse. Command entry points and terminal output are inherently
// serial, so main-actor-by-default keeps them that way without annotation.
//
// Getting these backwards is the single most expensive mistake available here, because
// it does not fail — it compiles, it runs, and the scanner is quietly serialized behind
// the terminal for the rest of the product's life.
//
// .strictMemorySafety() surfaces every unsafe construct as a diagnostic. Core is
// required to have none — see Wire/InternetChecksum.swift for the one place that
// pushed back, and the comment there for why Span<UInt8> is used over RawSpan.
let coreSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .defaultIsolation(nil),
    .strictMemorySafety(),
]

// The platform target keeps .strictMemorySafety() deliberately. Core has no unsafe
// constructs at all; this target necessarily does, because talking to the kernel means
// pointers. Leaving the check on means every one of them is a compiler diagnostic that
// has to be silenced with an explicit `unsafe` marker, so `grep unsafe` over this
// target returns a bounded, reviewable list rather than a shrug.
let darwinSettings: [SwiftSetting] = coreSettings

// Non-isolated, no memory-safety exemption needed: this target makes no syscalls of its
// own, it composes the ones below it.
let adapterSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .defaultIsolation(nil),
]

let toolSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .defaultIsolation(MainActor.self),
]

let package = Package(
    name: "zhen",
    // macOS 15.6, the oldest macOS that runs Xcode 26, so anyone who can build zhen can
    // run what they built. zhen is only ever built from source, so a lower floor would
    // describe Macs that have no way to get it.
    //
    // This was 26, on the grounds that no safe way to produce a `Span` from owned
    // storage existed below it. `Array.span` is 26+, and that much is true. But
    // `ArraySlice.span` is back-deployed to 10.14.4, so `bytes[bytes.indices].span` is the
    // same borrowed, bounds-checked view with no `unsafe` at any floor. Every span over
    // an array in this package is spelled that way. Not `bytes[...].span`: the
    // unbounded-range subscript yields a temporary, and the span escapes it.
    //
    // Going lower is measured and not done. 14 builds once `ProbeCounters` has a lock in
    // place of Synchronization's `Atomic`, which is 15+. But nothing on 14 can build
    // zhen, so it would need prebuilt binaries, and keeping those built and checked was
    // judged not worth it (PR #10).
    //
    // iOS is 26, and it is iPadOS that has been built: ZhenCore, ZhenDarwin and ZhenScan
    // compile for the device and the simulator, and the engine's tests run on an iPad
    // simulator in CI. What iPadOS gets is the unprivileged composition — no BPF, no
    // route socket, no helper, no SSDP — see Docs/IPADOS.md. The floor is not lowered
    // for the same reason as before: below 26 is support nobody has seen work.
    platforms: [.macOS("15.6"), .iOS(.v26)],
    products: [
        .library(name: "ZhenCore", targets: ["ZhenCore"]),
        .library(name: "ZhenDarwin", targets: ["ZhenDarwin"]),
        // A product, because the privileged helper is an executable in another place
        // and only products cross package boundaries.
        .library(name: "ZhenPrivilege", targets: ["ZhenPrivilege"]),
        // A product because the app's Xcode target links it. It is the app's adapter
        // over the engine and it lives here, not with the app, for one reason: it is
        // non-isolated and the app target is main-actor-by-default. A target boundary
        // is what keeps a socket off the main actor; an annotation is what somebody
        // eventually deletes.
        .library(name: "ZhenScan", targets: ["ZhenScan"]),
        .executable(name: "zhen", targets: ["zhen"]),
        // A product, so the app can embed the helper from the version it pins instead of
        // building it by hand from a checkout.
        //
        // It used to be withheld, on the grounds that declaring it would put a second
        // scheme in Xcode's menu for a daemon nobody launches by hand. Measured on
        // 2026-10-12, neither half of that holds: opened on its own, this package already
        // lists a `zhen-helper` scheme — SwiftPM synthesises an executable product for
        // every executable target of a ROOT package, and Xcode makes a scheme for it — and
        // the app's project lists only its own `Zhen` scheme, because Xcode makes none for
        // a remote package's products. What the synthesised product does not do is cross
        // the package boundary: a dependent asking for it got "product 'zhen-helper' not
        // found". Declaring it changes exactly that, and no scheme list.
        .executable(name: "zhen-helper", targets: ["zhen-helper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
    ],
    targets: [
        .target(name: "ZhenCore", swiftSettings: coreSettings),
        // Header-only C, and it exists for exactly one reason: `BIOCSETIF` and its
        // siblings are function-like macros over `sizeof(struct ifreq)`, which
        // ClangImporter will not evaluate — the symbols are simply invisible to Swift.
        // About a dozen `static inline` functions return the computed values, and the
        // file wraps no syscall: `ioctl`, `read` and `write` are called against the
        // Darwin overlay directly, because a second wrapper is a second thing that can
        // disagree with the platform.
        //
        // Its contents are behind `#if defined(__APPLE__)`, so a Linux build of this
        // package compiles it to an empty translation unit rather than failing to find
        // <net/bpf.h>. Nothing in ZhenCore depends on it.
        .target(name: "CBPFShim"),
        // The privileged resource, and nothing else.
        //
        // Two processes need this code: `ZhenDarwin` in the app and the CLI, and the
        // launch daemon that opens a device as root and passes the descriptor back. The
        // daemon linking `ZhenDarwin` would put a TLS client, a Bonjour browser and a
        // port scanner inside a root process to perform one `open`; a second copy of the
        // ioctl sequence would drift the first time one was corrected. So it is a target,
        // and it is deliberately small enough to read in a sitting.
        .target(
            name: "ZhenPrivilege",
            dependencies: ["CBPFShim"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .defaultIsolation(nil),
                // Not `.strictMemorySafety()`. This target exists to make syscalls, and
                // every `unsafe` in it is at a boundary the compiler cannot see past.
            ]
        ),
        // The engines.
        //
        // ZhenCore stays pure and must keep compiling on Linux; nothing here leaks back
        // into it. Every file in this target is wrapped in `#if canImport(Darwin)`, so a
        // Linux build produces an empty module rather than a failure, and a future
        // ZhenLinux slots in beside it.
        .target(
            name: "ZhenDarwin",
            dependencies: ["ZhenCore", "CBPFShim", "ZhenPrivilege"],
            swiftSettings: darwinSettings
        ),
        // The app's adapter over the engine — a scan runner and an in-memory store.
        // Sibling to the CLI's `ScanPipeline`, which is the same kind of thing for the
        // other front end.
        //
        // If something in this target ever needs `@MainActor` to compile, that is the
        // signal that UI has leaked into the scanner — not an invitation to add it.
        .target(
            name: "ZhenScan",
            dependencies: ["ZhenCore", "ZhenDarwin"],
            swiftSettings: adapterSettings
        ),
        .executableTarget(
            name: "zhen",
            dependencies: [
                "ZhenCore",
                // Conditional so a Linux build drops it and picks up a ZhenLinux instead.
                .target(name: "ZhenDarwin", condition: .when(platforms: [.macOS])),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            // Excluded, not a resource: it is consumed by the linker via -sectcreate
            // below and embedded in the binary itself. SPM refuses Info.plist as a
            // bundle resource anyway, and a bundle is exactly what this executable does
            // not have — which is the whole problem it solves.
            exclude: ["Info.plist"],
            swiftSettings: toolSettings,
            linkerSettings: [
                // Without this the Local Network grant attaches to the terminal that
                // launched the binary rather than to the binary, never appears under
                // this tool's name in System Settings, and a denial returns zero
                // results rather than an error. See Info.plist.
                //
                // ABSOLUTE, via Context.packageDirectory. A relative path here is
                // resolved against the linker's working directory, which is the package
                // root only when the build happens to be invoked from it — so
                // `swift build --package-path …` from anywhere else silently produced a
                // binary with no plist section at all. A silently unembedded plist is
                // the precise failure this flag exists to prevent.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT", "-Xlinker", "__info_plist",
                    "-Xlinker", "\(Context.packageDirectory)/Sources/zhen/Info.plist",
                ], .when(platforms: [.macOS]))
            ],
            // `zhen --version` and `run.tool.commit`. See the plugin for why the commit
            // is stamped at build time rather than read from the manifest.
            plugins: ["StampCommit"]
        ),
        .plugin(name: "StampCommit", capability: .buildTool()),
        .testTarget(
            name: "ZhenCoreTests",
            dependencies: ["ZhenCore"],
            // Real Bonjour strings, committed. The naming rules encode knowledge that
            // was expensive to acquire and is not rediscoverable from first principles —
            // that `md` on _raop is not a model, that a sleep proxy prefixes the name it
            // republishes — so they are tested against what the network actually says
            // rather than against what this code expects it to say. A fixture file also
            // records PROVENANCE per string, which an inline literal cannot.
            resources: [.copy("Fixtures")],
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "ZhenDarwinTests",
            // CBPFShim directly, so the BPF tests can pin the `bpf_hdr` offsets they
            // write headers at against what `offsetof` says on this SDK. The parser
            // reads the same offsets through the same shim; asserting them from the
            // test is what stops the two drifting into agreeing about a layout the
            // kernel does not use.
            dependencies: ["ZhenDarwin", "CBPFShim"],
            // Real bytes off a real routing socket, captured once and committed. The
            // parser they exercise has an alignment hazard that only shows up on
            // genuinely packed, genuinely variable-length input, so a hand-built buffer
            // would test the wrong thing.
            resources: [.copy("Fixtures")],
            swiftSettings: darwinSettings
        ),
        // ── The privileged helper ──────────────────────────────────────────────
        //
        // A launch daemon, so it is an executable of its own rather than anything the
        // app links. It depends on `ZhenPrivilege` and on nothing else: the whole point
        // of that target existing is that a root process performing one `open` should
        // not be carrying a TLS client and a port scanner around with it.
        //
        // It lives with the tool rather than with the app because it is neither a view
        // nor an Xcode target — it is a binary the app bundle embeds, built by
        // `swift build` like everything else here.
        .executableTarget(
            name: "zhen-helper",
            dependencies: ["ZhenPrivilege"],
            swiftSettings: adapterSettings
        ),
        .testTarget(name: "zhenTests", dependencies: ["zhen"], swiftSettings: toolSettings),
    ]
)
