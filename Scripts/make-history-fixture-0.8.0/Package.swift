// swift-tools-version: 6.2
import PackageDescription

// This build's own `LogHistoryStore`, for the 0.8.0 migration gate (G2):
//
//     swift run --package-path Scripts/make-history-fixture-0.8.0 make-history-fixture-0.8.0 \
//         Tests/ZhenCoreTests/Fixtures/history-0.7.0.ndjson \
//         Tests/ZhenCoreTests/Fixtures/history-0.8.0.ndjson
//
// Depends on the repository it lives in, by path, because the build it stands for is the
// one being written. Regenerate it only when the history format changes on purpose, and
// then regenerate `history-0.8.0-rewritten-by-0.7.0.ndjson` from it with the 0.7.0
// generator beside it.
let package = Package(
    name: "make-history-fixture-0.8.0",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(name: "zhen-core", path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "make-history-fixture-0.8.0",
            dependencies: [.product(name: "ZhenCore", package: "zhen-core")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
