// RunTool.swift — `run.tool`: which build produced an artifact.
//
// Study 2 freezes one binary and measures it for weeks. An artifact that cannot say which
// build wrote it cannot be tied back to the code that produced its numbers, and "the one
// on JC's machine at the time" is not a citation.

/// The build that produced a run.
public struct RunTool: Sendable, Hashable, Codable {
    /// The program: `zhen`.
    public var name: String
    /// Its version, `ZhenVersion.current`.
    public var version: String
    /// The commit it was built from, with `-dirty` when the working tree had staged or
    /// tracked changes at build time. Nil when the build could not tell — built from a
    /// source tree with no git, or where git was not available.
    public var commit: String?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(name: String, version: String, commit: String?) {
        self.name = name
        self.version = version
        self.commit = commit
    }
}
