// ZhenVersion.swift — the version, in one place for the whole repository.
//
// It has been in two before, and they disagreed: the command line's embedded plist was
// corrected and its `--version` constant was not, so the binary reported two releases
// behind itself. Nothing failed, which is the whole problem — a version string is read
// precisely when somebody is trying to work out what they are holding, and that is not
// a moment when anyone is running the tests.
//
// A test then pinned those two together. That fixed the pair and left the shape: the
// command line declared a version, the app declared a version, and `CITATION.cff`
// declared a third, each free to drift from the others. Pinning every pair is how a
// project ends up with a lattice of tests holding copies in agreement instead of one
// value.
//
// So it lives here. Both packages already depend on core, which makes this the only
// place either of them can share. The one derived file left in this package — the
// command line's `Info.plist` — is still checked by a test, against *this*. The helper's
// `HelperBuild.version` is not, and is bumped by hand with it.
public enum ZhenVersion {
    /// The current version, and the only declaration of it in the repository.
    ///
    /// Semantic versioning, and the changelog follows it. The floor for a bump is
    /// whether the artifact or the command surface changed in a way a person would
    /// notice — not whether the code moved.
    public static let current = "0.7.0"
}
