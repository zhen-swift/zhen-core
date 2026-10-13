// Contrast.swift — choosing a foreground that reads on a background, at runtime.
//
// The app's rule is that text is legible on any background, including ones the person
// chose, and that the choice is computed rather than assumed. The previous app derived
// its text colours by hand against one background, was right there, and was wrong on the
// other two it drew text on — a table cannot notice that and a function asked about each
// background can. So the decision is a function of the background, made when the
// background is known.
//
// Floors are WCAG 2's. "Large text" (3:1) is deliberately not offered: the app's largest
// type is below the 24 pt that would qualify, so every word it draws is body text.

import Foundation

/// WCAG 2 contrast: the ratio between two colours, and the choice of a readable one.
public enum Contrast {
    /// A WCAG floor.
    public enum Level: Sendable, Hashable, CaseIterable {
        /// 3:1 — WCAG 1.4.11, for a UI component or graphic that is not text.
        case nonText
        /// 4.5:1 — WCAG 1.4.3 (AA), for body text.
        case aa
        /// 7:1 — WCAG 1.4.6 (AAA), for body text; the bar Increase Contrast should clear.
        case aaa

        /// The smallest ratio that meets this level.
        public var minimumRatio: Double {
            switch self {
            case .nonText: 3
            case .aa: 4.5
            case .aaa: 7
            }
        }
    }

    /// A foreground picked for a background, with the evidence for the pick.
    public struct Choice: Sendable, Hashable {
        /// The chosen foreground.
        public let foreground: SRGBColor
        /// Its ratio against the background, `1...21`.
        public let ratio: Double
        /// Whether it meets the level that was asked for.
        ///
        /// False when no candidate did. The choice is then the best available rather than
        /// nothing, because a screen has to draw something — and the caller learns it fell
        /// short instead of believing it did not.
        public let meetsLevel: Bool
    }

    /// The contrast ratio between two colours, `1...21`. Order does not matter.
    public static func ratio(_ first: SRGBColor, _ second: SRGBColor) -> Double {
        let a = first.relativeLuminance
        let b = second.relativeLuminance
        return (max(a, b) + 0.05) / (min(a, b) + 0.05)
    }

    /// Whether a foreground meets a level on a background.
    public static func meets(
        _ level: Level, foreground: SRGBColor, on background: SRGBColor
    ) -> Bool {
        ratio(foreground, background) >= level.minimumRatio
    }

    /// The first candidate that meets `level` on `background`, in the order given.
    ///
    /// Order is preference: pass the colour the design wants first and the safe fallbacks
    /// after it, so the design's colour is kept wherever it reads. When none meets the
    /// level, the candidate with the highest ratio is returned with `meetsLevel` false;
    /// ties go to the earlier candidate. `nil` only when there are no candidates.
    public static func foreground(
        on background: SRGBColor, preferring candidates: [SRGBColor], level: Level
    ) -> Choice? {
        var best: Choice?
        for candidate in candidates {
            let measured = ratio(candidate, background)
            if measured >= level.minimumRatio {
                return Choice(foreground: candidate, ratio: measured, meetsLevel: true)
            }
            if measured > best?.ratio ?? -1 {
                best = Choice(foreground: candidate, ratio: measured, meetsLevel: false)
            }
        }
        return best
    }
}
