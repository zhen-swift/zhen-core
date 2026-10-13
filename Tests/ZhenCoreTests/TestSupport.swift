import Testing
@testable import ZhenCore

extension MACAddress {
    /// Parses a MAC the test author asserts is well-formed, failing the test if not.
    ///
    /// Exists because `try MACAddress.required("…")` passed straight into a
    /// `MACAddress?` parameter warns as redundant — the contextual type is already
    /// optional, so the macro sees nothing to unwrap. Dropping the `#require` would
    /// silence the warning by making a typo in a fixture literal decay to `nil` and
    /// the test assert something other than what it says. Hoisting the check into a
    /// non-optional return keeps the validation and loses the warning.
    static func required(
        _ text: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) throws -> MACAddress {
        try #require(MACAddress(text), "'\(text)' should parse as a MAC address",
                     sourceLocation: sourceLocation)
    }
}
