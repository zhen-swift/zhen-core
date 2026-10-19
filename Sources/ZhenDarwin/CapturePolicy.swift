// CapturePolicy.swift — which routes to a capture device a scanner may use.
//
// Its own file, outside `CaptureSource.swift`'s macOS guard, because it is part of the
// public surface on every Apple platform: `ScanRunner` and `DarwinScanner.make` take one,
// and a caller that names a policy should compile whether or not this platform has a
// device to apply it to. On iPadOS there is no `/dev/bpf*` and no helper, so both cases
// mean the same thing there: compose without a capture device.
#if canImport(Darwin)

/// Which routes to a capture device a scanner may use.
public enum CapturePolicy: Sendable, Hashable {
    /// Open `/dev/bpf*` in this process, and nothing else.
    ///
    /// Exactly what this codebase did before the helper existed. The command line uses
    /// it, because it is the binary the study measures and an extra probe on the
    /// startup path is a change to what is being measured.
    case directOnly

    /// Try a direct open first, then ask the helper.
    ///
    /// Direct first, deliberately, though `Docs/04-privileged-helper.md` sketched it the
    /// other way round. Under `sudo` the direct open succeeds and the helper is never
    /// contacted, so a privileged run does not acquire a dependency on a daemon it does
    /// not need — and the path that `Scripts/verify-privileged.sh` has been measuring
    /// all along stays the path that runs.
    case helperThenDirect
}

#endif
