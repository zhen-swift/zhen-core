// swift-tools-version: 6.2

// ── A harness, not a product ─────────────────────────────────────────────────────
//
// The smallest iPad app that runs the engine: one tab probes what the iPadOS sandbox
// allows, syscall by syscall, and one runs a scan through `ZhenScan` and shares the
// report. It exists so the iPadOS build can be checked on a device before anything in
// zhen-app commits to an iPad target. Nothing ships from here.
//
// An app package rather than an Xcode project, so the whole build is this file: iPad
// only, the Local Network purpose string and the Bonjour types declared below, and
// zhen-core by LOCAL PATH — the checkout it sits in, so a change to the engine is
// exercised here without a release. Open the `.swiftpm` folder in Xcode, or build it
// with `xcodebuild` (see README.md beside this file).

import AppleProductTypes
import PackageDescription

let package = Package(
    name: "ZhenPad",
    platforms: [.iOS("26.0")],
    products: [
        .iOSApplication(
            name: "ZhenPad",
            targets: ["ZhenPad"],
            bundleIdentifier: "com.jctec.zhen.pad-harness",
            displayVersion: "0.1",
            bundleVersion: "1",
            appIcon: .placeholder(icon: .magicWand),
            accentColor: .presetColor(.teal),
            supportedDeviceFamilies: [.pad],
            supportedInterfaceOrientations: [
                .portrait, .portraitUpsideDown, .landscapeLeft, .landscapeRight,
            ],
            capabilities: [
                // Must match `BonjourVocabulary.browsedTypes`. A browsed type missing
                // here returns nothing, silently; the probe tab compares the two at
                // runtime and says which are missing.
                .localNetwork(
                    purposeString: "ZhenPad probes devices on this network to find and name them.",
                    bonjourServiceTypes: [
                        "_googlecast._tcp", "_companion-link._tcp", "_homekit._tcp",
                        "_airplay._tcp", "_sonos._tcp", "_spotify-connect._tcp",
                        "_androidtvremote2._tcp", "_device-info._tcp", "_esphomelib._tcp",
                        "_hue._tcp", "_smb._tcp", "_ssh._tcp", "_workstation._tcp",
                        "_ipp._tcp", "_printer._tcp", "_raop._tcp", "_sleep-proxy._udp",
                    ]
                ),
            ]
        ),
    ],
    dependencies: [
        .package(name: "zhen", path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "ZhenPad",
            dependencies: [
                .product(name: "ZhenCore", package: "zhen"),
                .product(name: "ZhenScan", package: "zhen"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                // The app half's isolation, as in zhen-app. The engine stays off the main
                // actor because it lives in ZhenScan; the probes below say so explicitly.
                .defaultIsolation(MainActor.self),
            ]
        ),
    ]
)
