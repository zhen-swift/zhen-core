#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import Testing
@testable import zhen

// Terminal width, stage 1 of `PORTS-rendering.md`.
//
// ── Why this suite opens a real pseudo-terminal ────────────────────────────────
//
// The resolution ORDER can be tested with injected values, and the first suite below
// does that. But an injected `ioctlWidth` proves nothing about `TIOCGWINSZ` itself: it
// tests that a function returns the number it was handed. If the ioctl were wired to
// the wrong descriptor, or read `ws_row` instead of `ws_col`, every one of those tests
// would still pass.
//
// So the second suite opens a pty, sets its size to two different widths with
// `TIOCSWINSZ`, and asks the real code for the answer. That is the part that can fail
// for a real reason.

@Suite("Width resolution takes its sources in order")
struct TerminalWidthOrderTests {
    @Test("A redirected stream is 80, whatever the window it was launched from says")
    func redirectIsAlwaysEighty() {
        // The gate in `PORTS-rendering.md`: `zhen scan > out.txt` must produce the same
        // bytes from an 80-column and a 200-column window. A shell exports COLUMNS from
        // the window, so honouring it here would break exactly that.
        #expect(Terminal.width(isTTY: false, ioctlWidth: 200, columnsVariable: "200") == 80)
        #expect(Terminal.width(isTTY: false, ioctlWidth: nil, columnsVariable: "300") == 80)
        #expect(Terminal.width(isTTY: false, ioctlWidth: 120, columnsVariable: nil) == 80)
    }

    @Test("On a terminal the ioctl wins, and COLUMNS is only the fallback")
    func ioctlBeatsColumns() {
        #expect(Terminal.width(isTTY: true, ioctlWidth: 200, columnsVariable: "80") == 200)
        #expect(Terminal.width(isTTY: true, ioctlWidth: nil, columnsVariable: "132") == 132)
        #expect(Terminal.width(isTTY: true, ioctlWidth: nil, columnsVariable: nil) == 80)
    }

    @Test("An implausible answer falls through instead of being believed")
    func implausibleWidthsFallThrough() {
        // A pty that has never been sized answers 0 from a SUCCEEDING ioctl, so `nil`
        // is not the only way for this source to have nothing to say.
        #expect(Terminal.width(isTTY: true, ioctlWidth: 0, columnsVariable: "132") == 132)
        #expect(Terminal.width(isTTY: true, ioctlWidth: 0, columnsVariable: "0") == 80)
        #expect(Terminal.width(isTTY: true, ioctlWidth: nil, columnsVariable: "wide") == 80)
        #expect(Terminal.width(isTTY: true, ioctlWidth: 3, columnsVariable: nil) == 80)
    }
}

@Suite("TIOCGWINSZ reads the width of a real terminal")
struct TerminalWindowSizeTests {
    /// Opens a pty sized to `columns` and returns what `Terminal` reads back from it.
    ///
    /// Returns `nil` only if the pty could not be created, which is an environment
    /// failure rather than a result, and is reported as one by the tests.
    private func widthOfPTY(sizedTo columns: UInt16) -> Int? {
        var primary: Int32 = 0
        var replica: Int32 = 0
        var size = winsize(ws_row: 24, ws_col: columns, ws_xpixel: 0, ws_ypixel: 0)
        guard openpty(&primary, &replica, nil, nil, &size) == 0 else { return nil }
        defer { close(primary); close(replica) }
        return Terminal.windowSize(ofDescriptor: replica)
    }

    @Test("Two differently sized terminals give two different answers")
    func realPTYWidths() {
        let narrow = widthOfPTY(sizedTo: 80)
        let wide = widthOfPTY(sizedTo: 200)
        guard let narrow, let wide else {
            Issue.record("openpty failed; this suite measured nothing")
            return
        }
        #expect(narrow == 80, Comment(rawValue: "an 80-column pty read back \(narrow)"))
        #expect(wide == 200, Comment(rawValue: "a 200-column pty read back \(wide)"))
        // Stated separately because it is the property that would survive both of the
        // above being wrong in the same direction — reading ws_row, say, which is 24 on
        // both and would make the two agree.
        #expect(narrow != wide, "the two sizes read back the same number")
    }

    @Test("A descriptor that is not a terminal has no window size")
    func nonTerminalHasNoSize() {
        // The negative half. If `windowSize` returned a number here, the fallback chain
        // above would never be reached and the redirect gate would pass for the wrong
        // reason.
        let devnull = open("/dev/null", O_WRONLY)
        defer { close(devnull) }
        #expect(devnull >= 0, "could not open /dev/null")
        #expect(Terminal.windowSize(ofDescriptor: devnull) == nil,
                "a non-terminal descriptor reported a window size")
    }
}


@Suite("The width a run detects does not reach a redirected file")
struct RedirectedWidthTests {
    /// The stage 1 gate from `PORTS-rendering.md`, on a FIXED report.
    ///
    /// Two live scans cannot be byte-compared and that is not a width problem: the RTT
    /// column is sized to its widest value, so a run that measured 23.70ms and one that
    /// measured 9.12ms differ by a character. The first version of the verification
    /// script compared two live runs and reported exactly that as a failure. A fixture
    /// removes the only thing that was varying.
    private func rendered(at width: Int) -> String {
        Out.capturing {
            TextRenderer(quiet: true, color: false, progressColor: false, width: width)
                .finish(sampleReport())
        }.out
    }

    @Test("The same report renders identically at 80 and at 200 columns")
    func sameBytesAtBothWidths() {
        let narrow = rendered(at: 80)
        let wide = rendered(at: 200)
        #expect(narrow == wide,
                Comment(rawValue: "the device table changed with the terminal width. "
                        + "At 80: \(narrow.prefix(120)). At 200: \(wide.prefix(120))"))
        #expect(!narrow.isEmpty, "the renderer produced nothing, so this compared two empty strings")
    }

    /// What makes the test above mean something at stage 1, where it is otherwise
    /// satisfied by a renderer that ignores its width entirely — which is exactly what
    /// today's renderer does.
    ///
    /// **The prediction written here was wrong twice, and the correction is the point.**
    /// It said this would fail at stage 2, then at stage 3. It failed at neither.
    ///
    /// Stage 4 made the width load-bearing — `auto` chooses matrix or long form from it,
    /// and the SERVICE column is capped against it — and this test still passes,
    /// correctly. Its fixture has no ports, and **a report with no ports is
    /// width-independent by design**: the device table sizes its columns to its content
    /// and the terminal is not consulted. That is now the property rather than a
    /// placeholder waiting to be inverted.
    ///
    /// The inverted counterpart lives in `PortLongFormTests.longFormRespectsWidth`,
    /// which asserts three widths give three renderings.
    @Test("At stage 1 nothing consumes the width, and that is recorded rather than assumed")
    func nothingConsumesWidthYet() {
        let extremes = [Terminal.minimumUsableWidth, 80, 200, 10_000].map { rendered(at: $0) }
        #expect(Set(extremes).count == 1,
                Comment(rawValue: "some width now changes the device table — \(Set(extremes).count) "
                        + "distinct renderings across 20, 80, 200 and 10000 columns. If that is "
                        + "stage 2 landing, rewrite this test to cover a report with no ports."))
    }
}
