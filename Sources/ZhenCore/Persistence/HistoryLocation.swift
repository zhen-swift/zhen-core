// HistoryLocation.swift — where the history file goes, and who it belongs to.
//
// ── The `sudo` trap, which the spec lists as a risk and this is the answer to ────
//
// A privileged scan runs as root, and every "where is my home directory" API answers
// honestly: `/var/root`. So `sudo zhen scan` would write its history somewhere the
// person who typed it cannot read, cannot find, and will never be told about — and the
// unprivileged scan they run next would open an empty store and report every device on
// their network as newly appeared. Two stores, one of them invisible, and the symptom
// is history that resets whenever the privilege changes.
//
// `SUDO_USER` is what makes it recoverable. When it is set, the file belongs to that
// user rather than to root, and the path is rebuilt under their home.
//
// ── Why the path is derived rather than written out ─────────────────────────────
//
// `~/Library/Application Support` on macOS, something else on Linux, and core has to
// reach both — it is the one module where a stray `#if os(...)` would be worst.
// Foundation already knows the answer per platform, so the location comes from
// `.applicationSupportDirectory` and the sudo case swaps the home prefix underneath it.
// Both halves are computed by the same API on the same platform, so the suffix they
// share is whatever that platform's convention happens to be, and no code here has an
// opinion about it.
//
// ── Why this is in core rather than in the CLI that first needed it ─────────────
//
// The app and the command line are supposed to be looking at ONE history. A person who
// runs `zhen scan` in a terminal and then opens the app is entitled to see the same
// network, and two tools that each decide where history lives would agree right up until
// one of them was changed. There is one answer to "where is it", and it is here.

import Foundation

/// Where scan history is kept.
public enum HistoryLocation {
    /// The environment variable that overrides everything.
    ///
    /// The study's harness needs a store it can point somewhere disposable, and so does
    /// anyone comparing two histories side by side. An override that must be honoured
    /// exactly — no directory appended, no extension assumed — because a caller naming a
    /// path and getting a different one is worse than having no override at all.
    public static let overrideVariable = "ZHEN_HISTORY"

    /// The directory under application support that holds the store.
    public static let directoryName = "zhen"

    /// Resolves the store path, or nil when there is nowhere sensible to put it.
    ///
    /// Nil is a real answer rather than a failure: a scan with nowhere to write history
    /// is still a scan, and refusing to run one over a missing home directory would be
    /// the tool deciding that its filing is more important than its job.
    /// - Parameters:
    ///   - home: the home directory of the user this process is running as.
    ///   - support: the platform's application-support directory for that same user.
    ///
    /// Both are injectable, and they have to be injected together or not at all: the
    /// sudo correction works by finding `home` inside `support` and swapping the prefix,
    /// so a `home` from one source and a `support` from another describe no real machine
    /// and the correction silently declines. An earlier signature took only `home`,
    /// which made the case this function exists for the one case a test could not reach.
    public static func resolve(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: URL = URL(fileURLWithPath: NSHomeDirectory()),
        support: URL? = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: false
        )
    ) -> URL? {
        let override = environment[overrideVariable].flatMap { $0.isEmpty ? nil : $0 }
        if let override {
            return URL(fileURLWithPath: (override as NSString).expandingTildeInPath)
        }

        guard let support else { return nil }

        var base = support
        if let invoking = invokingUser(in: environment),
           let owned = rehome(support, from: home, to: invoking) {
            base = owned
        }
        return base.appendingPathComponent(directoryName, isDirectory: true)
            .appendingPathComponent("history.ndjson")
    }

    /// The user who typed `sudo`, when that is who this is really for.
    ///
    /// `SUDO_USER` is still set when someone runs `sudo` as root or `sudo -u root`, and
    /// in that case there is nothing to correct — rebuilding root's path under root's
    /// home is work that cannot change the answer, and doing it would mean the
    /// interesting case and the uninteresting one took different code paths.
    private static func invokingUser(in environment: [String: String]) -> String? {
        guard let user = environment["SUDO_USER"], !user.isEmpty, user != "root" else { return nil }
        return user
    }

    /// Rebuilds a path that sits under one home directory to sit under another's.
    ///
    /// Returns nil rather than guessing when the path is not under the home it was
    /// supposedly derived from, or when the target user has no resolvable home. Writing
    /// to a path assembled from a failed assumption is how the original problem happens
    /// twice.
    private static func rehome(_ path: URL, from home: URL, to user: String) -> URL? {
        let homePath = home.standardizedFileURL.path
        let full = path.standardizedFileURL.path
        guard full.hasPrefix(homePath) else { return nil }
        let suffix = String(full.dropFirst(homePath.count)).trimmingCharacters(
            in: CharacterSet(charactersIn: "/")
        )
        guard !suffix.isEmpty else { return nil }
        // `URL`'s, not `FileManager`'s: the same lookup, but the `FileManager` spelling is
        // unavailable on iOS and would stop core compiling there for a branch that only
        // `sudo` can reach.
        let target = URL.homeDirectory(forUser: user)
        guard let target, target.path != homePath else { return nil }
        return target.appendingPathComponent(suffix, isDirectory: true)
    }
}
