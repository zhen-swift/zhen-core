// SRGBColor.swift — a colour as WCAG measures it, and nothing more.
//
// Core cannot import SwiftUI, so it cannot see `Color`. That is the point rather than an
// obstacle: the contrast rule is arithmetic on three numbers, and keeping it here means it
// is tested on Linux, has no idea what a view is, and is the same function whichever
// front end asks. The app resolves its own colour (`Color.Resolved` carries gamma-encoded
// sRGB components) and hands the three numbers over.

import Foundation

/// A colour in gamma-encoded sRGB, each component in `0...1`.
///
/// Gamma-encoded is the space a hex code is written in and the one WCAG's formula expects
/// before its own linearisation step. A linear-light value passed in here would be
/// linearised twice and every ratio would come out wrong, quietly.
public struct SRGBColor: Sendable, Hashable {
    /// Red, gamma-encoded, `0...1`.
    public let red: Double
    /// Green, gamma-encoded, `0...1`.
    public let green: Double
    /// Blue, gamma-encoded, `0...1`.
    public let blue: Double

    /// A colour from gamma-encoded components.
    ///
    /// Clamped to `0...1`. A wide-gamut colour resolved into extended sRGB can carry a
    /// component outside the range, and WCAG's luminance is defined only inside it; the
    /// clamp measures the nearest colour sRGB can show, which is what a display that
    /// cannot show the original does too.
    public init(red: Double, green: Double, blue: Double) {
        self.red = min(max(red, 0), 1)
        self.green = min(max(green, 0), 1)
        self.blue = min(max(blue, 0), 1)
    }

    /// A colour from `0xRRGGBB`, the form an artboard or a colour picker reports.
    public init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }

    /// WCAG 2 relative luminance: 0 for black, 1 for white.
    public var relativeLuminance: Double {
        0.2126 * Self.linear(red) + 0.7152 * Self.linear(green) + 0.0722 * Self.linear(blue)
    }

    /// The sRGB transfer function, inverted.
    ///
    /// The threshold is IEC 61966-2-1's 0.04045. WCAG 2's text prints 0.03928, a value
    /// from an older sRGB draft; no 8-bit component lies between the two (10/255 is
    /// 0.0392, 11/255 is 0.0431), so for any hex colour they agree, and the standard's
    /// number is used for the components that are not hex.
    static func linear(_ component: Double) -> Double {
        component <= 0.04045
            ? component / 12.92
            : pow((component + 0.055) / 1.055, 2.4)
    }
}
