// swift-tools-version: 6.2
import PackageDescription

// zhen-core 0.7.0's own `LogHistoryStore`, for the 0.8.0 migration gate (G2). Two modes:
//
//     # A history 0.7.0 wrote, every shape it can write.
//     swift run --package-path Scripts/make-history-fixture-0.7.0 make-history-fixture-0.7.0 \
//         write Tests/ZhenCoreTests/Fixtures/history-0.7.0.ndjson
//
//     # A history 0.8.0 wrote, opened by 0.7.0, one run folded in, and compacted by it —
//     # which is what the app pinned to 0.7.0 does to the file the command line shares.
//     swift run --package-path Scripts/make-history-fixture-0.7.0 make-history-fixture-0.7.0 \
//         rewrite Tests/ZhenCoreTests/Fixtures/history-0.8.0.ndjson \
//         Tests/ZhenCoreTests/Fixtures/history-0.8.0-rewritten-by-0.7.0.ndjson
//
// Pinned to the exact release, like the 0.6.0 generator beside it.
let package = Package(
    name: "make-history-fixture-0.7.0",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(url: "https://github.com/zhen-swift/zhen-core", exact: "0.7.0"),
    ],
    targets: [
        .executableTarget(
            name: "make-history-fixture-0.7.0",
            dependencies: [.product(name: "ZhenCore", package: "zhen-core")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
