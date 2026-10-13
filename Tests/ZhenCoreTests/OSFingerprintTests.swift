// OSFingerprintTests.swift — the matcher, and the correction the network forced on it.
//
// The table is the part of fingerprinting that is a claim about the world rather than a
// claim about a packet, so it is the part that can be wrong while everything compiles.
// These run in core, with no network: a signature table is data and matching it is
// arithmetic.
//
// Every feature vector below was captured from a real host on 10.10.20.0/24.

import Foundation
import Testing
@testable import ZhenCore

@Suite("A stack fingerprint is a match against a table, and says so")
struct OSFingerprintMatchingTests {
    /// Exactly what a consumer router answered with.
    static let consumerRouter = TCPStackFeatures(
        observedTTL: 64, initialTTL: 64, dontFragment: true, window: 65160,
        maximumSegmentSize: 1460, windowScale: 6, sackPermitted: true, timestamps: true,
        optionOrder: "2-4-8-1-3"
    )
    /// A camera running a small Linux.
    static let camera = TCPStackFeatures(
        observedTTL: 64, initialTTL: 64, dontFragment: true, window: 28960,
        maximumSegmentSize: 1460, windowScale: 5, sackPermitted: true, timestamps: true,
        optionOrder: "2-4-8-1-3"
    )
    /// An Apple TV.
    static let appleDevice = TCPStackFeatures(
        observedTTL: 64, initialTTL: 64, dontFragment: true, window: 65535,
        maximumSegmentSize: 1460, windowScale: 5, sackPermitted: true, timestamps: true,
        optionOrder: "2-1-3-1-1-8-4"
    )

    @Test("The option order is what separates the lineages, not the window scale")
    func optionOrderDiscriminates() {
        // The correction this test exists for. Window scale was a hard gate in the
        // first version of the table, and every host on the development network came
        // back unmatched: a router at 6, a camera at 5, both emitting Linux's exact
        // option order, and an Apple device at 5 emitting Darwin's. The scale follows
        // the receive buffer, so it measures how much memory a device has rather than
        // what it runs.
        #expect(StackSignatures.match(Self.consumerRouter).family == "Linux")
        #expect(StackSignatures.match(Self.camera).family == "Linux")
        #expect(StackSignatures.match(Self.appleDevice).family == "macOS or iOS")
    }

    @Test("A size that disagrees downgrades the confidence rather than rejecting the match")
    func sizesDowngrade() {
        // All three differ from their signature's canonical scale, so all three are
        // probable rather than exact. That is the honest reading: the structure matched
        // and a size did not.
        #expect(StackSignatures.match(Self.consumerRouter).confidence == .probable)
        #expect(StackSignatures.match(Self.appleDevice).confidence == .probable)

        // And when everything agrees, it says so.
        var canonical = Self.consumerRouter
        canonical.windowScale = 7
        canonical.window = 64240
        #expect(StackSignatures.match(canonical).confidence == .exact)
    }

    @Test("A structural disagreement rejects the signature outright")
    func structureRejects() {
        // Timestamps are the field that separates Windows from Darwin at a glance, and
        // a Darwin option order without them is not Darwin.
        var noTimestamps = Self.appleDevice
        noTimestamps.timestamps = false
        #expect(StackSignatures.match(noTimestamps).family != "macOS or iOS")

        // A TTL from a different band is a different stack, whatever else matches.
        var windowsTTL = Self.consumerRouter
        windowsTTL.initialTTL = 128
        windowsTTL.observedTTL = 128
        #expect(StackSignatures.match(windowsTTL).family != "Linux")
    }

    @Test("A host nothing claims reports its features, unmatched, rather than nothing")
    func unmatchedCarriesEvidence() {
        // The property that makes the table extensible: the evidence is in the
        // artifact, so a signature can be written later against reports already
        // collected rather than needing the network back.
        let strange = TCPStackFeatures(
            observedTTL: 64, initialTTL: 64, dontFragment: false, window: 4096,
            maximumSegmentSize: 536, windowScale: nil, sackPermitted: true,
            timestamps: true, optionOrder: "8-4-2"
        )
        let fingerprint = StackSignatures.match(strange)
        #expect(fingerprint.family == nil)
        #expect(fingerprint.confidence == .unmatched)
        #expect(fingerprint.features.optionOrder == "8-4-2")
        #expect(fingerprint.features.window == 4096)
    }

    @Test("The initial TTL is inferred from the band, keeping the observed value beside it")
    func initialTTL() {
        #expect(TCPStackFeatures.inferInitialTTL(from: 64) == 64)
        // Four hops away and still plainly a 64 stack.
        #expect(TCPStackFeatures.inferInitialTTL(from: 60) == 64)
        #expect(TCPStackFeatures.inferInitialTTL(from: 128) == 128)
        #expect(TCPStackFeatures.inferInitialTTL(from: 120) == 128)
        #expect(TCPStackFeatures.inferInitialTTL(from: 255) == 255)
        #expect(TCPStackFeatures.inferInitialTTL(from: 250) == 255)
    }

    @Test("A fingerprint round-trips through JSON with its evidence intact")
    func roundTrip() throws {
        // The evidence is the reason this type exists, so losing it in transit would
        // leave the artifact carrying a bare verdict nobody can check.
        let original = StackSignatures.match(Self.appleDevice)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OSFingerprint.self, from: data)
        #expect(decoded == original)
        #expect(decoded.features.optionOrder == "2-1-3-1-1-8-4")

        // An unmatched fingerprint has no family, and the key is absent rather than
        // null — which the decoder has to accept on the way back.
        let unmatched = OSFingerprint(
            family: nil, confidence: .unmatched, features: Self.camera
        )
        let bytes = try JSONEncoder().encode(unmatched)
        #expect(try JSONDecoder().decode(OSFingerprint.self, from: bytes) == unmatched)
    }

    @Test("A fingerprint is not an OS hint, and the two are not interchangeable")
    func distinctFromOSHint() {
        // Both say "64" about the router and the camera; only one of them can then say
        // which is which. Conflating them is the mistake the two types exist to stop.
        #expect(OSHint(ttl: 64) == .unixLike)
        #expect(OSHint(ttl: Self.appleDevice.observedTTL) == .unixLike)
        #expect(OSHint(ttl: Self.camera.observedTTL) == .unixLike)
        #expect(StackSignatures.match(Self.appleDevice).family
                != StackSignatures.match(Self.camera).family)
    }
}
