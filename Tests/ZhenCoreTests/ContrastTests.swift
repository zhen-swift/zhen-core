import Foundation
import Testing
@testable import ZhenCore

// The contrast helper, held to the table the previous app measured.
//
// The cases are not invented. They are every pair the app's old `ContrastTests` asserted —
// seven text tokens on three surfaces, both themes, both contrast tiers, the two non-text
// tokens under Increase Contrast, and the button label on the accent — with the ratios
// that test printed. zhen-app's `Docs/process/DESIGN-FINDINGS.md` records where each
// value came from (the old `Palette.swift` at zhen-app `fdb7eaf`) and the script that
// recomputed them.
//
// The old palette was tuned to the edge: nineteen of these sit within 0.1 of their floor.
// That is why they make a good test of the arithmetic — a formula that is slightly wrong
// moves one of them across the line — and a poor answer to copy, which is why the app
// re-derives its colours instead.

/// One measured pair.
struct ContrastCase: Sendable, CustomTestStringConvertible {
    let name: String
    let foreground: SRGBColor
    let background: SRGBColor
    let level: Contrast.Level
    /// The ratio the old app's test printed, to two decimals.
    let ratio: Double

    var testDescription: String { name }
}

private func Case(
    _ name: String, _ foreground: UInt32, on background: UInt32,
    _ level: Contrast.Level, _ ratio: Double
) -> ContrastCase {
    ContrastCase(
        name: name, foreground: SRGBColor(hex: foreground),
        background: SRGBColor(hex: background), level: level, ratio: ratio
    )
}

/// The 100 pairs, in the order the old test walked them.
let measuredPairs: [ContrastCase] = [
    Case("textPrimary on surface, dark, standard", 0xEBEBF0, on: 0x1A1A1F, .aa, 14.59),
    Case("textPrimary on surfaceRaised, dark, standard", 0xEBEBF0, on: 0x212127, .aa, 13.48),
    Case("textPrimary on surfaceField, dark, standard", 0xEBEBF0, on: 0x2C2C32, .aa, 11.68),
    Case("textSecondary on surface, dark, standard", 0x939396, on: 0x1A1A1F, .aa, 5.66),
    Case("textSecondary on surfaceRaised, dark, standard", 0x939396, on: 0x212127, .aa, 5.23),
    Case("textSecondary on surfaceField, dark, standard", 0x939396, on: 0x2C2C32, .aa, 4.53),
    Case("textTertiary on surface, dark, standard", 0x939399, on: 0x1A1A1F, .aa, 5.67),
    Case("textTertiary on surfaceRaised, dark, standard", 0x939399, on: 0x212127, .aa, 5.24),
    Case("textTertiary on surfaceField, dark, standard", 0x939399, on: 0x2C2C32, .aa, 4.54),
    Case("accent on surface, dark, standard", 0xA495E8, on: 0x1A1A1F, .aa, 6.64),
    Case("accent on surfaceRaised, dark, standard", 0xA495E8, on: 0x212127, .aa, 6.13),
    Case("accent on surfaceField, dark, standard", 0xA495E8, on: 0x2C2C32, .aa, 5.31),
    Case("onlineText on surface, dark, standard", 0x4CD268, on: 0x1A1A1F, .aa, 8.85),
    Case("onlineText on surfaceRaised, dark, standard", 0x4CD268, on: 0x212127, .aa, 8.18),
    Case("onlineText on surfaceField, dark, standard", 0x4CD268, on: 0x2C2C32, .aa, 7.09),
    Case("warningText on surface, dark, standard", 0xD9A856, on: 0x1A1A1F, .aa, 8.00),
    Case("warningText on surfaceRaised, dark, standard", 0xD9A856, on: 0x212127, .aa, 7.39),
    Case("warningText on surfaceField, dark, standard", 0xD9A856, on: 0x2C2C32, .aa, 6.40),
    Case("infoText on surface, dark, standard", 0x6DB3D4, on: 0x1A1A1F, .aa, 7.47),
    Case("infoText on surfaceRaised, dark, standard", 0x6DB3D4, on: 0x212127, .aa, 6.90),
    Case("infoText on surfaceField, dark, standard", 0x6DB3D4, on: 0x2C2C32, .aa, 5.98),
    Case("onAccent on accent, dark, standard", 0x1A1A1F, on: 0xA495E8, .aa, 6.64),
    Case("textPrimary on surface, light, standard", 0x1D1D1F, on: 0xFFFFFF, .aa, 16.83),
    Case("textPrimary on surfaceRaised, light, standard", 0x1D1D1F, on: 0xEEEDF3, .aa, 14.46),
    Case("textPrimary on surfaceField, light, standard", 0x1D1D1F, on: 0xF0F0F0, .aa, 14.77),
    Case("textSecondary on surface, light, standard", 0x6B6B6E, on: 0xFFFFFF, .aa, 5.31),
    Case("textSecondary on surfaceRaised, light, standard", 0x6B6B6E, on: 0xEEEDF3, .aa, 4.56),
    Case("textSecondary on surfaceField, light, standard", 0x6B6B6E, on: 0xF0F0F0, .aa, 4.66),
    Case("textTertiary on surface, light, standard", 0x6A6A6E, on: 0xFFFFFF, .aa, 5.39),
    Case("textTertiary on surfaceRaised, light, standard", 0x6A6A6E, on: 0xEEEDF3, .aa, 4.63),
    Case("textTertiary on surfaceField, light, standard", 0x6A6A6E, on: 0xF0F0F0, .aa, 4.73),
    Case("accent on surface, light, standard", 0x6A58C9, on: 0xFFFFFF, .aa, 5.45),
    Case("accent on surfaceRaised, light, standard", 0x6A58C9, on: 0xEEEDF3, .aa, 4.68),
    Case("accent on surfaceField, light, standard", 0x6A58C9, on: 0xF0F0F0, .aa, 4.78),
    Case("onlineText on surface, light, standard", 0x217538, on: 0xFFFFFF, .aa, 5.73),
    Case("onlineText on surfaceRaised, light, standard", 0x217538, on: 0xEEEDF3, .aa, 4.92),
    Case("onlineText on surfaceField, light, standard", 0x217538, on: 0xF0F0F0, .aa, 5.03),
    Case("warningText on surface, light, standard", 0x8A6114, on: 0xFFFFFF, .aa, 5.53),
    Case("warningText on surfaceRaised, light, standard", 0x8A6114, on: 0xEEEDF3, .aa, 4.75),
    Case("warningText on surfaceField, light, standard", 0x8A6114, on: 0xF0F0F0, .aa, 4.85),
    Case("infoText on surface, light, standard", 0x256F90, on: 0xFFFFFF, .aa, 5.59),
    Case("infoText on surfaceRaised, light, standard", 0x256F90, on: 0xEEEDF3, .aa, 4.80),
    Case("infoText on surfaceField, light, standard", 0x256F90, on: 0xF0F0F0, .aa, 4.91),
    Case("onAccent on accent, light, standard", 0xFFFFFF, on: 0x6A58C9, .aa, 5.45),
    Case("textPrimary on surface, dark, increased", 0xEBEBF0, on: 0x1A1A1F, .aaa, 14.59),
    Case("textPrimary on surfaceRaised, dark, increased", 0xEBEBF0, on: 0x212127, .aaa, 13.48),
    Case("textPrimary on surfaceField, dark, increased", 0xEBEBF0, on: 0x2C2C32, .aaa, 11.68),
    Case("textSecondary on surface, dark, increased", 0xB8B8BB, on: 0x1A1A1F, .aaa, 8.76),
    Case("textSecondary on surfaceRaised, dark, increased", 0xB8B8BB, on: 0x212127, .aaa, 8.09),
    Case("textSecondary on surfaceField, dark, increased", 0xB8B8BB, on: 0x2C2C32, .aaa, 7.01),
    Case("textTertiary on surface, dark, increased", 0xB8B8BE, on: 0x1A1A1F, .aaa, 8.78),
    Case("textTertiary on surfaceRaised, dark, increased", 0xB8B8BE, on: 0x212127, .aaa, 8.11),
    Case("textTertiary on surfaceField, dark, increased", 0xB8B8BE, on: 0x2C2C32, .aaa, 7.03),
    Case("accent on surface, dark, increased", 0xBDAEFF, on: 0x1A1A1F, .aaa, 8.80),
    Case("accent on surfaceRaised, dark, increased", 0xBDAEFF, on: 0x212127, .aaa, 8.13),
    Case("accent on surfaceField, dark, increased", 0xBDAEFF, on: 0x2C2C32, .aaa, 7.05),
    Case("onlineText on surface, dark, increased", 0x4CD268, on: 0x1A1A1F, .aaa, 8.85),
    Case("onlineText on surfaceRaised, dark, increased", 0x4CD268, on: 0x212127, .aaa, 8.18),
    Case("onlineText on surfaceField, dark, increased", 0x4CD268, on: 0x2C2C32, .aaa, 7.09),
    Case("warningText on surface, dark, increased", 0xE2B15F, on: 0x1A1A1F, .aaa, 8.82),
    Case("warningText on surfaceRaised, dark, increased", 0xE2B15F, on: 0x212127, .aaa, 8.15),
    Case("warningText on surfaceField, dark, increased", 0xE2B15F, on: 0x2C2C32, .aaa, 7.06),
    Case("infoText on surface, dark, increased", 0x7CC2E3, on: 0x1A1A1F, .aaa, 8.82),
    Case("infoText on surfaceRaised, dark, increased", 0x7CC2E3, on: 0x212127, .aaa, 8.15),
    Case("infoText on surfaceField, dark, increased", 0x7CC2E3, on: 0x2C2C32, .aaa, 7.06),
    Case("separator on surface, dark, increased", 0x75757A, on: 0x1A1A1F, .nonText, 3.78),
    Case("separator on surfaceRaised, dark, increased", 0x75757A, on: 0x212127, .nonText, 3.49),
    Case("separator on surfaceField, dark, increased", 0x75757A, on: 0x2C2C32, .nonText, 3.03),
    Case("offlineRing on surface, dark, increased", 0x75757B, on: 0x1A1A1F, .nonText, 3.79),
    Case("offlineRing on surfaceRaised, dark, increased", 0x75757B, on: 0x212127, .nonText, 3.50),
    Case("offlineRing on surfaceField, dark, increased", 0x75757B, on: 0x2C2C32, .nonText, 3.03),
    Case("onAccent on accent, dark, increased", 0x1A1A1F, on: 0xBDAEFF, .aaa, 8.80),
    Case("textPrimary on surface, light, increased", 0x1D1D1F, on: 0xFFFFFF, .aaa, 16.83),
    Case("textPrimary on surfaceRaised, light, increased", 0x1D1D1F, on: 0xEEEDF3, .aaa, 14.46),
    Case("textPrimary on surfaceField, light, increased", 0x1D1D1F, on: 0xF0F0F0, .aaa, 14.77),
    Case("textSecondary on surface, light, increased", 0x4F4F52, on: 0xFFFFFF, .aaa, 8.16),
    Case("textSecondary on surfaceRaised, light, increased", 0x4F4F52, on: 0xEEEDF3, .aaa, 7.01),
    Case("textSecondary on surfaceField, light, increased", 0x4F4F52, on: 0xF0F0F0, .aaa, 7.16),
    Case("textTertiary on surface, light, increased", 0x4F4F53, on: 0xFFFFFF, .aaa, 8.15),
    Case("textTertiary on surfaceRaised, light, increased", 0x4F4F53, on: 0xEEEDF3, .aaa, 7.01),
    Case("textTertiary on surfaceField, light, increased", 0x4F4F53, on: 0xF0F0F0, .aaa, 7.15),
    Case("accent on surface, light, increased", 0x4E3CAD, on: 0xFFFFFF, .aaa, 8.16),
    Case("accent on surfaceRaised, light, increased", 0x4E3CAD, on: 0xEEEDF3, .aaa, 7.01),
    Case("accent on surfaceField, light, increased", 0x4E3CAD, on: 0xF0F0F0, .aaa, 7.16),
    Case("onlineText on surface, light, increased", 0x085C1F, on: 0xFFFFFF, .aaa, 8.20),
    Case("onlineText on surfaceRaised, light, increased", 0x085C1F, on: 0xEEEDF3, .aaa, 7.05),
    Case("onlineText on surfaceField, light, increased", 0x085C1F, on: 0xF0F0F0, .aaa, 7.20),
    Case("warningText on surface, light, increased", 0x6F4600, on: 0xFFFFFF, .aaa, 8.23),
    Case("warningText on surfaceRaised, light, increased", 0x6F4600, on: 0xEEEDF3, .aaa, 7.07),
    Case("warningText on surfaceField, light, increased", 0x6F4600, on: 0xF0F0F0, .aaa, 7.22),
    Case("infoText on surface, light, increased", 0x0B5576, on: 0xFFFFFF, .aaa, 8.15),
    Case("infoText on surfaceRaised, light, increased", 0x0B5576, on: 0xEEEDF3, .aaa, 7.01),
    Case("infoText on surfaceField, light, increased", 0x0B5576, on: 0xF0F0F0, .aaa, 7.16),
    Case("separator on surface, light, increased", 0x88888D, on: 0xFFFFFF, .nonText, 3.53),
    Case("separator on surfaceRaised, light, increased", 0x88888D, on: 0xEEEDF3, .nonText, 3.03),
    Case("separator on surfaceField, light, increased", 0x88888D, on: 0xF0F0F0, .nonText, 3.10),
    Case("offlineRing on surface, light, increased", 0x88888D, on: 0xFFFFFF, .nonText, 3.53),
    Case("offlineRing on surfaceRaised, light, increased", 0x88888D, on: 0xEEEDF3, .nonText, 3.03),
    Case("offlineRing on surfaceField, light, increased", 0x88888D, on: 0xF0F0F0, .nonText, 3.10),
    Case("onAccent on accent, light, increased", 0xFFFFFF, on: 0x4E3CAD, .aaa, 8.16),
]

@Suite("Contrast")
struct ContrastTests {
    @Test("Every pair the previous app measured comes out at the same ratio", arguments: measuredPairs)
    func reproducesTheTable(_ pair: ContrastCase) {
        let measured = Contrast.ratio(pair.foreground, pair.background)
        // Half a unit in the last printed place: the table is rounded to two decimals.
        #expect(abs(measured - pair.ratio) <= 0.005, "measured \(measured)")
    }

    @Test("Every pair the previous app measured meets its floor", arguments: measuredPairs)
    func meetsItsFloor(_ pair: ContrastCase) {
        #expect(Contrast.meets(pair.level, foreground: pair.foreground, on: pair.background))
    }

    @Test("The table is the whole table")
    func tableIsComplete() {
        // 7 text tokens × 3 surfaces × 2 themes × 2 tiers, 2 non-text × 3 × 2 at
        // increased, onAccent in 2 themes × 2 tiers. A truncated paste fails here
        // rather than passing on fewer cases.
        #expect(measuredPairs.count == 100)
        #expect(measuredPairs.filter { $0.level == .aa }.count == 44)
        #expect(measuredPairs.filter { $0.level == .aaa }.count == 44)
        #expect(measuredPairs.filter { $0.level == .nonText }.count == 12)
        #expect(Set(measuredPairs.map(\.name)).count == 100)
    }

    @Test("The artboard's own secondary text fails, by the margins it was caught at")
    func artboardValuesFail() {
        // The two values the design shipped with, before anyone measured them.
        let dark = Contrast.ratio(SRGBColor(hex: 0x65656C), SRGBColor(hex: 0x1A1A1F))
        let light = Contrast.ratio(SRGBColor(hex: 0xADADB0), SRGBColor(hex: 0xFFFFFF))
        #expect(abs(dark - 3.00) <= 0.005)
        #expect(abs(light - 2.24) <= 0.005)
        #expect(!Contrast.meets(.aa, foreground: SRGBColor(hex: 0x65656C), on: SRGBColor(hex: 0x1A1A1F)))
        #expect(!Contrast.meets(.aa, foreground: SRGBColor(hex: 0xADADB0), on: SRGBColor(hex: 0xFFFFFF)))
    }

    @Test("A colour right on one background is checked on every background it lands on")
    func eachBackgroundDecidesForItself() {
        // The defect this helper exists for. Asked about each of the three dark surfaces,
        // preferring the artboard's grey, then the corrected grey, then primary text:
        // the artboard grey fails everywhere, and the corrected grey holds at AA on all
        // three — on the field surface by 0.03.
        let surfaces: [UInt32] = [0x1A1A1F, 0x212127, 0x2C2C32]
        let preference = [0x65656C, 0x939396, 0xEBEBF0].map { SRGBColor(hex: $0) }
        for surface in surfaces {
            let choice = Contrast.foreground(
                on: SRGBColor(hex: surface), preferring: preference, level: .aa)
            #expect(choice?.foreground == SRGBColor(hex: 0x939396))
            #expect(choice?.meetsLevel == true)
        }
        // At AAA the corrected grey is not enough on any of them, so primary text wins.
        for surface in surfaces {
            let choice = Contrast.foreground(
                on: SRGBColor(hex: surface), preferring: preference, level: .aaa)
            #expect(choice?.foreground == SRGBColor(hex: 0xEBEBF0))
        }
    }

    @Test("White or black on a mid grey turns on a hair, and the hair is respected")
    func blackOrWhiteAtTheBoundary() {
        let whiteThenBlack = [SRGBColor(hex: 0xFFFFFF), SRGBColor(hex: 0x000000)]
        // #767676 is the lightest grey white text passes on (4.54); #777777 is not (4.48).
        let on767676 = Contrast.foreground(
            on: SRGBColor(hex: 0x767676), preferring: whiteThenBlack, level: .aa)
        #expect(on767676?.foreground == SRGBColor(hex: 0xFFFFFF))
        let on777777 = Contrast.foreground(
            on: SRGBColor(hex: 0x777777), preferring: whiteThenBlack, level: .aa)
        #expect(on777777?.foreground == SRGBColor(hex: 0x000000))
        #expect(on777777?.meetsLevel == true)
    }

    @Test("When nothing reads, the best is returned and says it falls short")
    func fallsShortHonestly() {
        // On #777777 neither white (4.48) nor black (4.69) reaches 7:1.
        let choice = Contrast.foreground(
            on: SRGBColor(hex: 0x777777),
            preferring: [SRGBColor(hex: 0xFFFFFF), SRGBColor(hex: 0x000000)],
            level: .aaa)
        #expect(choice?.foreground == SRGBColor(hex: 0x000000))
        #expect(choice?.meetsLevel == false)
        #expect(abs((choice?.ratio ?? 0) - 4.69) <= 0.005)
        #expect(Contrast.foreground(on: SRGBColor(hex: 0x777777), preferring: [], level: .aa) == nil)
    }

    @Test("The ratio has the bounds and symmetry WCAG defines")
    func ratioIdentities() {
        let black = SRGBColor(hex: 0x000000)
        let white = SRGBColor(hex: 0xFFFFFF)
        #expect(Contrast.ratio(black, white) == 21)
        #expect(Contrast.ratio(white, white) == 1)
        let a = SRGBColor(hex: 0xA495E8), b = SRGBColor(hex: 0x1A1A1F)
        #expect(Contrast.ratio(a, b) == Contrast.ratio(b, a))
        #expect(black.relativeLuminance == 0)
        #expect(white.relativeLuminance == 1)
    }

    @Test("Components outside sRGB are clamped, not measured as impossible light")
    func outOfGamutIsClamped() {
        let extended = SRGBColor(red: 1.2, green: -0.1, blue: 0.5)
        #expect(extended == SRGBColor(red: 1, green: 0, blue: 0.5))
    }

    @Test("Hex is read as 0xRRGGBB")
    func hexChannelOrder() {
        let colour = SRGBColor(hex: 0xFF8000)
        #expect(colour.red == 1)
        #expect(colour.green == 128.0 / 255)
        #expect(colour.blue == 0)
    }
}
