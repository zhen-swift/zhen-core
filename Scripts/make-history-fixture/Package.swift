// swift-tools-version: 6.2
import PackageDescription

// Writes `Tests/ZhenCoreTests/Fixtures/history-0.6.0.ndjson` with zhen-core 0.6.0's own
// `LogHistoryStore`, so the migration gate loads a file an older build really wrote rather
// than one this build imagines it wrote. Pinned to the exact release; see main.swift.
//
//     swift run --package-path Scripts/make-history-fixture make-history-fixture \
//         Tests/ZhenCoreTests/Fixtures/history-0.6.0.ndjson
let package = Package(
    name: "make-history-fixture",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(url: "https://github.com/zhen-swift/zhen-core", exact: "0.6.0"),
    ],
    targets: [
        .executableTarget(
            name: "make-history-fixture",
            dependencies: [.product(name: "ZhenCore", package: "zhen-core")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
