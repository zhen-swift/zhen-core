// LogHistoryStore.swift — where history lives, on every platform.
//
// The ruling of 2026-09-09 made this the everywhere-else half of a pair, with SwiftData
// on Darwin. The amendment of 2026-09-11 withdrew the other half for shipping nowhere,
// which makes this simply the store: the app and the command line both open it, and they
// open the same file. It is in core because that is the module that has to reach Linux,
// and that requirement is why it was the half that survived.
//
// It contains no rule about what recording a run means. `HistoryLedger` owns those, above
// every conformance. This owns a file.
//
// ── Why append-only, and not "write the state out each time" ─────────────────────
//
// The population is small enough that rewriting the whole thing on every scan would
// work, and that is exactly the argument that makes it tempting. What it costs is the
// property worth having: with an append-only file, a scan that is interrupted halfway
// through writing has lost the last run and nothing else, because everything before it
// was already durable and untouched. Rewriting in place makes every scan a moment when
// the entire history is one crash away from being a truncated file.
//
// The cost is that reading means replaying, and a log that only grows would eventually
// make opening the store the slowest thing the CLI does. So it compacts: past a
// threshold the file is rewritten from the ledger — as a snapshot that says the same
// thing in fewer lines — through a temporary file and an atomic rename, so the moment
// of rewriting is itself crash-safe. A reader either sees the old complete file or the
// new complete file, never a half-written one.
//
// ── The format is deliberately dull ─────────────────────────────────────────────
//
// One JSON object per line, each tagged with a type and a version. It can be read by
// `head`, diffed, grepped for an address, and truncated at a line boundary without
// becoming unparseable. A binary format would be smaller and would give up every one of
// those, for a file that holds a few hundred devices.
//
// The line types are declared here rather than by making `DerivedEvent` and friends
// carry `Codable`. Those are domain types; giving them a wire format would mean any
// change to them was silently a change to this file's format, and the compiler would
// not say so. `Device` and `ScanRun` are the exception — they are already `Codable`
// against the format the scan artifact pins, and reusing it is what stops the store
// from describing them a second, drifting way.
//
// ── Two processes, one file ─────────────────────────────────────────────────────
//
// The app and `zhen scan` open the same path deliberately: a person who scans in a
// terminal is entitled to see that network when they open the app. An actor serialises
// the writers inside one process and does nothing at all between two, and this store
// had both halves of that wrong.
//
// The append was `seekToEnd()` and then a write — two calls with a gap between them.
// Another process appending in that gap moved the end of the file, and this one then
// wrote over the run it had just added. O_APPEND closes it: the kernel resolves the
// offset and performs the write as one operation, so there is no gap for a run to be
// lost in.
//
// That is not sufficient on its own, because recording a run is not one write. It is
// read the file, fold the run into what it says, write the difference — and two
// processes interleaving THOSE lose an update however atomic each individual write is.
// So the whole read-fold-write is under an exclusive lock, and so is compaction, which
// is the one operation that can destroy history rather than merely misorder it: a
// snapshot computed from a stale ledger omits everything the other process recorded,
// and the rename makes the omission permanent.
//
// ── Why flock, and why the lock is not on the log ───────────────────────────────
//
// `flock` rather than `fcntl` record locks, and the reason is not portability — both
// exist on Darwin and Linux. POSIX record locks belong to the PROCESS: two stores
// inside one process would not exclude each other at all, and closing any descriptor
// on the file drops every lock that process holds on it, including one taken by an
// unrelated open somewhere else in the program. A `flock` belongs to the open file
// description, so two stores in one process exclude each other exactly as two processes
// do, and a lock lives and dies with the descriptor that took it.
//
// The lock is a sidecar file beside the log rather than the log itself, and compaction
// is what forces that. A lock attaches to an inode; compaction replaces the log's inode
// by rename. Two processes holding locks either side of that rename hold them on
// different inodes and exclude nobody — at precisely the moment exclusion matters most.
// So the lock has to outlive the file it protects: it is a file nothing ever replaces
// and nothing ever deletes. The first writer creates it before the log exists, and a
// reader that finds neither has nothing it could be excluded from.
//
// ── Nothing is cached between calls ─────────────────────────────────────────────
//
// Every operation re-reads the file under the lock. A ledger held across calls is a
// copy of a file another process is entitled to change, which is the same defect one
// level up: the app would show the history it read when it launched and never the scan
// you just ran in a terminal. The cost is parsing the file on each call, bounded by
// compaction and by the size of a home network — and the alternative is not a faster
// store, it is a store that is wrong about a file it shares.

import Foundation

// The lock is the only thing in this file that Foundation cannot do. There is no
// portable Foundation API for one: `NSFileCoordinator` is Darwin-only and coordinates
// between Apple processes rather than with a command line. Every branch below imports
// the same POSIX names to make the same calls — this is one behaviour spelled for
// several module maps, not a platform seam.
//
// `Musl` is here because the fallback path in `verify-linux.sh` uses the static Linux
// SDK, whose libc module is Musl rather than Glibc, and `#else import Glibc` failed
// there with "no such module". It went unnoticed because the check prefers a container,
// where Glibc is what exists — so the portability claim held on the path that usually
// runs and not on the one that runs when Docker is not installed. Named conditions
// rather than an `#else`, so the next libc that is neither produces the same honest
// error instead of silently taking a branch written for something else.
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// History in an append-only file.
///
/// An actor, which is what serialises the tasks inside this process. The file lock is
/// what serialises this process against the other one holding the same file open, and
/// the two are not substitutes for each other.
public actor LogHistoryStore: HistoryStore {
    /// Where the log lives.
    public nonisolated let url: URL

    /// Rewrite the file when it exceeds this many lines.
    ///
    /// A scan of a home network appends on the order of ten lines, so a few thousand is
    /// months of history before the first compaction, and compaction is one pass over a
    /// file that is small by construction. The number matters far less than that there
    /// is one: an uncompacted log is a store that gets slower forever.
    private let compactionThreshold: Int

    private var ledger: HistoryLedger
    private var lineCount: Int
    private var retention: RetentionPolicy

    /// Where "now" comes from when retention is applied on load.
    ///
    /// Injected rather than read from the clock directly, because a store that prunes
    /// against the wall clock cannot be tested for pruning without waiting.
    private let clock: @Sendable () -> Timestamp

    /// How many events the retention rule dropped the last time the file was replayed.
    ///
    /// Kept because a deletion cannot be appended. If a load dropped something, the file
    /// still holds those lines, and the next write has to rewrite the file rather than
    /// append to it — otherwise the next reader would see them again.
    private var prunedOnLoad: Int = 0
    /// How many records the replay above joined, for the same reason `prunedOnLoad`
    /// exists: the write that follows has to rewrite rather than append.
    private var reconciledOnLoad: Int = 0

    /// Opens the store at a path, creating nothing until something is written.
    ///
    /// Deliberately not `throws`. A store that cannot be opened is a real condition, but
    /// it is one every caller would have to handle at construction — before it has done
    /// anything — and the honest place to discover it is the first read or write. Until
    /// then this is just a URL.
    /// - Parameter retention: how long events are kept. Defaults to forever, which is
    ///   what the command line opens with — it has no retention setting and must not
    ///   acquire a behaviour from one.
    /// - Parameter clock: where "now" comes from when retention is applied on load.
    ///   Defaults to the system clock; tests pass a fixed one.
    public init(
        url: URL, compactionThreshold: Int = 4_000, retention: RetentionPolicy = .forever,
        clock: @escaping @Sendable () -> Timestamp = { .now }
    ) {
        self.url = url
        self.compactionThreshold = compactionThreshold
        self.retention = retention
        self.ledger = HistoryLedger(retention: retention)
        self.lineCount = 0
        self.clock = clock
    }

    /// Sets how long events are kept, from the next recorded run onward.
    ///
    /// Held here rather than on the ledger, because the ledger is rebuilt from the file
    /// on every call and a policy set on one of those would live exactly as long as the
    /// call that set it.
    public func setRetention(_ policy: RetentionPolicy) async {
        retention = policy
    }

    // ── HistoryStore ────────────────────────────────────────────────────────────

    public func latestRun() async -> ScanRun? {
        withLock(exclusive: false) {
            reload()
            return ledger.latestRun
        }
    }

    public func events() async -> [DerivedEvent] {
        withLock(exclusive: false) {
            reload()
            return ledger.events()
        }
    }

    public func devices() async -> [StoredDevice] {
        withLock(exclusive: false) {
            reload()
            return ledger.devices()
        }
    }

    public func firstSeen(
        for facts: [HostFacts], in network: IPv4Network
    ) async -> [IPv4Address: Timestamp] {
        withLock(exclusive: false) {
            reload()
            return ledger.firstSeen(for: facts, in: network)
        }
    }

    /// Folds a run in, under an exclusive lock held across the whole of it.
    ///
    /// The read and the write are one operation, and the lock is what makes them one.
    /// Reading the file, folding, and appending the difference is a read-modify-write;
    /// two of them interleaved lose whichever update landed first, which on this file
    /// means a scan that happened and left no trace.
    public func record(_ report: ScanReport) async -> [DerivedEvent] {
        withLock(exclusive: true) {
            reload()
            let fold = ledger.fold(report)
            if fold.prunedEvents > 0 || prunedOnLoad > 0
                || fold.mergedRecords > 0 || reconciledOnLoad > 0 {
                // A deletion cannot be appended. The file still holds the lines for the
                // events the retention rule just dropped, and appending the new ones on
                // top would leave both — retention that works until the next reopen.
                // Rewriting from the ledger is the operation that makes a deletion
                // durable, and compaction already is it.
                //
                // `prunedOnLoad` is in the condition because the replay above prunes
                // too. Without it the fold would find nothing left to drop, take the
                // append branch, and leave the load's deletions on disk forever.
                //
                // A merge is the same shape of write. It REMOVES a record, `append`
                // writes only the records the ledger still holds, and `reload` rebuilds
                // by stored key with the last line winning — so the loser's old device
                // line would be read straight back on the next open and the duplicate
                // would return. Only a rewrite makes a join durable.
                compact()
            } else {
                append(events: fold.events, run: report.run)
            }
            return fold.events
        }
    }

    // ── The lock ────────────────────────────────────────────────────────────────

    /// Runs `body` with the store locked against every other holder of this file.
    ///
    /// Shared for the reads, exclusive for the fold and for compaction. A reader takes
    /// a lock at all because the alternative is parsing a file in the middle of somebody
    /// else's write, and the honest outcome of that is not an error — it is a device
    /// silently missing from a list.
    ///
    /// A lock that cannot be taken is not fatal. Everything here still works on a file
    /// system with no locking, or in a directory that has become read-only; it works
    /// exactly as badly as it did before there was a lock, which is the right failure
    /// for a store whose job is to be readable rather than to be authoritative.
    ///
    /// The wait is unbounded in form and bounded in fact, which is worth stating because
    /// "nothing blocks indefinitely" is a rule everywhere else in this project. The lock
    /// is held across parsing a small file and writing a few kilobytes and never across
    /// a probe, a deadline or anything a person can sit in front of. And a `flock` is
    /// released by the kernel when the descriptor closes, which includes the holder
    /// dying — so unlike a lock file with a process id in it there is no stale state to
    /// detect and no recovery path to get wrong.
    private func withLock<T>(exclusive: Bool, _ body: () -> T) -> T {
        guard let handle = lockHandle(creating: exclusive) else { return body() }
        // LIFO: this unlocks first and then closes. Closing releases the lock anyway —
        // doing it explicitly is what makes the release visible where the lock is taken.
        defer { try? handle.close() }

        // `EINTR` is retried; everything else falls through to running unlocked.
        //
        // The two are not the same failure and the original code could not tell them
        // apart, because it did not look at the return value at all. `ENOLCK` on a file
        // system with no locking means the lock will never be available and the
        // documented fallback above is correct. `EINTR` means a signal arrived while
        // this thread was waiting and the lock is still perfectly gettable — treating
        // that as "no locking here" would run the read-modify-write this function exists
        // to make atomic with no lock held, and the `LOCK_UN` below would then release
        // something never taken.
        let operation = exclusive ? LOCK_EX : LOCK_SH
        var locked = false
        while true {
            if flock(handle.fileDescriptor, operation) == 0 { locked = true; break }
            if errno != EINTR { break }
        }
        defer { if locked { flock(handle.fileDescriptor, LOCK_UN) } }
        return body()
    }

    /// The sidecar the lock is taken on, opened but never read or written.
    ///
    /// A writer creates it; a reader does not, so an untouched store stays a path with
    /// nothing beside it. The second half covers the one ordering that would otherwise
    /// race: a reader that finds no lock file beside a log that exists has already been
    /// proved wrong about nobody having written here, so it creates the lock rather than
    /// reading unlocked.
    ///
    /// A `FileHandle` rather than a descriptor from `open`, because a path reaching C is
    /// a pointer and this module's rule is that it contains none. What is needed from the
    /// file is its descriptor, and Foundation will open a file and hand one over.
    ///
    /// **`FileManager.createFile` cannot be used here, and the race test is what found
    /// it.** It is not create-if-absent: called on a file that exists it leaves a
    /// DIFFERENT inode behind, which for a lock file is the whole failure this sidecar
    /// was introduced to avoid. Two writers starting together both found no lock file,
    /// both created one, and the second replaced the first's — so they locked two inodes,
    /// excluded nobody, and one of them lost its first run. `.withoutOverwriting` is
    /// O_EXCL: it creates the file or throws, and never touches one that is already
    /// there.
    private func lockHandle(creating: Bool) -> FileHandle? {
        let path = url.appendingPathExtension("lock").path
        if !creating {
            if let existing = FileHandle(forReadingAtPath: path) { return existing }
            guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try? Data().write(to: url.appendingPathExtension("lock"), options: .withoutOverwriting)
        return FileHandle(forUpdatingAtPath: path)
    }

    // ── Reading ─────────────────────────────────────────────────────────────────

    /// Replays the file. Every time, under the lock, without exception.
    ///
    /// Not once and cached: the file belongs to whoever else has it open as much as it
    /// belongs to this process, and a ledger kept between calls is a claim that it does
    /// not. What that buys is the property the shared file exists for — a scan run in a
    /// terminal is in the app's next read, rather than after its next relaunch.
    ///
    /// A malformed line is skipped rather than fatal, and the count of them is not
    /// reported anywhere — which is a deliberate limit on this design. The alternative,
    /// refusing to open, loses all of the history to protect one line of it, and the
    /// thing that goes wrong when a device's record is dropped is that it reappears as
    /// new. That is bad and it is survivable; an unopenable store is neither.
    private func reload() {
        ledger = HistoryLedger(retention: retention)
        lineCount = 0
        guard let data = try? Data(contentsOf: url) else { return }

        var records: [HostIdentifier: HistoryLedger.Record] = [:]
        var log: [DerivedEvent] = []
        var latest: ScanRun?
        var lines = 0

        for line in data.split(separator: UInt8(ascii: "\n")) where !line.isEmpty {
            lines += 1
            guard let entry = try? Self.decoder.decode(Line.self, from: Data(line))
            else { continue }
            switch entry.payload {
            case .device(let stored):
                guard let key = stored.key.identifier else { continue }
                records[key] = HistoryLedger.Record(
                    device: stored.device,
                    firstSeen: Timestamp(millisecondsSinceEpoch: stored.firstSeenMillis),
                    lastRunID: stored.lastRunID,
                    identifiers: Set(stored.identifiers.compactMap(\.identifier)),
                    ordinal: stored.ordinal
                )
            case .event(let stored):
                guard let kind = DerivedEvent.Kind(rawValue: stored.kind) else { continue }
                log.append(DerivedEvent(
                    id: stored.id, at: Timestamp(millisecondsSinceEpoch: stored.atMillis),
                    kind: kind, subject: stored.subject, detail: stored.detail,
                    runID: stored.runID
                ))
            case .run(let run):
                latest = run
            }
        }

        lineCount = lines
        ledger = HistoryLedger(
            records: records, log: log, latestRun: latest, retention: retention
        )
        // Retention applies here and not only at the fold. It used to apply only at the
        // fold, which meant "keep events for 30 days" kept them for 30 days *of
        // scanning*: open the store, read a three-week-old event under a seven-day
        // policy, and it was still there because nothing had been recorded since.
        prunedOnLoad = ledger.pruneEvents(asOf: clock())
        // Reconciliation applies here for the same reason retention does: a duplicate
        // already recorded in the file does not need a fresh scan to be provably a
        // duplicate. The evidence — two records sharing an identifier stronger than a
        // lease — is sitting in the lines just replayed, and a device that never
        // answers again would otherwise stay split for good.
        //
        // The run id is the latest one the file knows about, because the merge is a
        // conclusion drawn from history rather than from a run that just happened.
        reconciledOnLoad = ledger.reconcile(
            at: clock(), runID: latest?.id ?? UUID()
        ).count
    }

    // ── Writing ─────────────────────────────────────────────────────────────────

    /// Appends what changed, then compacts if the file has grown enough.
    ///
    /// Every device the ledger holds is written, not only the ones this run touched.
    /// A run changes `lastRunID` on everything it saw and leaves the rest alone, so the
    /// set that actually changed is nearly the whole set anyway, and computing the
    /// difference precisely would buy a few lines at the cost of being able to reason
    /// about what is in the file.
    private func append(events: [DerivedEvent], run: ScanRun) {
        var lines: [Line] = []
        for (key, record) in ledger.records.sorted(by: { $0.key < $1.key }) {
            lines.append(Line(payload: .device(StoredDeviceLine(
                key: StoredKey(key), device: record.device,
                firstSeenMillis: record.firstSeen.millisecondsSinceEpoch,
                lastRunID: record.lastRunID,
                identifiers: record.identifiers.sorted().map(StoredKey.init),
                ordinal: record.ordinal
            ))))
        }
        lines += events.map {
            Line(payload: .event(StoredEventLine(
                id: $0.id, atMillis: $0.at.millisecondsSinceEpoch, kind: $0.kind.rawValue,
                subject: $0.subject, detail: $0.detail, runID: $0.runID
            )))
        }
        lines.append(Line(payload: .run(run)))

        guard let encoded = Self.encode(lines) else { return }
        if appendBytes(encoded) {
            lineCount += lines.count
        }
        if lineCount > compactionThreshold { compact() }
    }

    /// Rewrites the file as a snapshot saying the same thing in fewer lines.
    ///
    /// Through a temporary file and a rename, so a reader sees either the whole old file
    /// or the whole new one. Compaction is the only moment this design rewrites rather
    /// than appends, which is why it is the only moment that needs the ceremony.
    ///
    /// Only ever called with the exclusive lock held, and that is what makes the rename
    /// survivable for the other process rather than merely atomic for this one. The
    /// snapshot is computed from a ledger reloaded under the same lock, so it cannot omit
    /// a run somebody else recorded; and because the lock lives on a file this never
    /// replaces, the process waiting for it is excluded across the rename rather than
    /// queueing on an inode that is about to stop being the store.
    private func compact() {
        var lines: [Line] = []
        for (key, record) in ledger.records.sorted(by: { $0.key < $1.key }) {
            lines.append(Line(payload: .device(StoredDeviceLine(
                key: StoredKey(key), device: record.device,
                firstSeenMillis: record.firstSeen.millisecondsSinceEpoch,
                lastRunID: record.lastRunID,
                identifiers: record.identifiers.sorted().map(StoredKey.init),
                ordinal: record.ordinal
            ))))
        }
        lines += ledger.log.map {
            Line(payload: .event(StoredEventLine(
                id: $0.id, atMillis: $0.at.millisecondsSinceEpoch, kind: $0.kind.rawValue,
                subject: $0.subject, detail: $0.detail, runID: $0.runID
            )))
        }
        if let run = ledger.latestRun { lines.append(Line(payload: .run(run))) }

        guard let encoded = Self.encode(lines) else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        // `.atomic` writes a temporary alongside and renames it over the target, which
        // is the whole requirement: a reader sees either the entire old file or the
        // entire new one. An earlier version did the temporary and the rename by hand
        // with `FileManager.replaceItemAt`, which works on Darwin and does NOT leave the
        // file at the original URL on swift-corelibs-foundation — the compaction test
        // passed on macOS and failed on Linux with "the file doesn't exist". This store
        // is the portable one, so that was the least affordable place to assume.
        if (try? encoded.write(to: url, options: .atomic)) != nil {
            lineCount = lines.count
        }
    }

    /// Appends bytes, creating the directory and the file if this is the first time.
    ///
    /// O_APPEND rather than `seekToEnd()` and a write. Those are two calls, and another
    /// process appending between them moves the end of the file that this one is about
    /// to write at — so the run it just added is written over by the next one and the
    /// file is shorter than the history it was given. With O_APPEND the kernel resolves
    /// the offset and performs the write together, and there is no between.
    ///
    /// The exclusive lock already serialises every writer that goes through this type,
    /// so this is the second of two answers to the same question. It is worth having
    /// because it is the one that does not depend on the other party's cooperation:
    /// a writer that never took the lock still cannot truncate a run out of the file.
    private func appendBytes(_ data: Data) -> Bool {
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        // O_EXCL, for the reason spelled out over `lockHandle`: `createFile` would
        // replace the log rather than leave the existing one alone.
        try? Data().write(to: url, options: .withoutOverwriting)
        guard let handle = try? FileHandle(forWritingTo: url) else { return false }
        defer { try? handle.close() }
        do {
            // Foundation opens O_WRONLY and leaves the offset at zero, so the flag is set
            // on the descriptor it hands back rather than passed to the open — which also
            // keeps the path out of C, and this module out of pointers. Preserving the
            // other status flags rather than assigning O_APPEND alone: F_SETFL replaces
            // all of them, and a store that silently cleared a flag it did not set would
            // be a nasty thing to find from the far end.
            let flags = fcntl(handle.fileDescriptor, F_GETFL, 0)
            if flags < 0 || fcntl(handle.fileDescriptor, F_SETFL, flags | O_APPEND) < 0 {
                // Correct under the lock, which is always held here, and wrong the moment
                // anything writes without it — which is the whole reason it is the
                // fallback rather than the mechanism.
                try handle.seekToEnd()
            }
            try handle.write(contentsOf: data)
            return true
        } catch {
            return false
        }
    }

    private static func encode(_ lines: [Line]) -> Data? {
        var out = Data()
        for line in lines {
            guard let encoded = try? encoder.encode(line) else { return nil }
            out.append(encoded)
            out.append(UInt8(ascii: "\n"))
        }
        return out
    }

    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()
}

// ── The file format ─────────────────────────────────────────────────────────────

extension LogHistoryStore {
    /// A `kind|value` identifier, as it appears on disk.
    ///
    /// A string rather than a nested object, so a line can be grepped for a MAC.
    struct StoredKey: Codable, Sendable {
        var raw: String

        init(_ identifier: HostIdentifier) {
            self.raw = "\(identifier.kind.rawValue)|\(identifier.value)"
        }

        init(from decoder: any Decoder) throws {
            self.raw = try decoder.singleValueContainer().decode(String.self)
        }

        func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(raw)
        }

        /// Only the FIRST bar separates, so a value containing one still round-trips.
        var identifier: HostIdentifier? {
            guard let separator = raw.firstIndex(of: "|"),
                  let kind = HostIdentifierKind(rawValue: String(raw[raw.startIndex..<separator]))
            else { return nil }
            return HostIdentifier(kind: kind, value: String(raw[raw.index(after: separator)...]))
        }
    }

    struct StoredDeviceLine: Codable, Sendable {
        var key: StoredKey
        var device: Device
        var firstSeenMillis: Int64
        var lastRunID: UUID
        var identifiers: [StoredKey]
        var ordinal: Int

        enum CodingKeys: String, CodingKey {
            case key
            case device
            case firstSeenMillis = "first_seen_millis"
            case lastRunID = "last_run_id"
            case identifiers
            case ordinal
        }
    }

    struct StoredEventLine: Codable, Sendable {
        var id: UUID
        var atMillis: Int64
        var kind: String
        var subject: String
        var detail: String
        var runID: UUID

        enum CodingKeys: String, CodingKey {
            case id
            case atMillis = "at_millis"
            case kind
            case subject
            case detail
            case runID = "run_id"
        }
    }

    /// One line: a version, a type, and the payload for that type.
    struct Line: Codable, Sendable {
        enum Payload: Sendable {
            case device(StoredDeviceLine)
            case event(StoredEventLine)
            case run(ScanRun)
        }

        var version: Int = 1
        var payload: Payload

        enum CodingKeys: String, CodingKey {
            case version = "v"
            case type
            case device
            case event
            case run
        }

        init(version: Int = 1, payload: Payload) {
            self.version = version
            self.payload = payload
        }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
            switch try container.decode(String.self, forKey: .type) {
            case "device":
                payload = .device(try container.decode(StoredDeviceLine.self, forKey: .device))
            case "event":
                payload = .event(try container.decode(StoredEventLine.self, forKey: .event))
            case "run":
                payload = .run(try container.decode(ScanRun.self, forKey: .run))
            default:
                throw DecodingError.dataCorruptedError(
                    forKey: .type, in: container, debugDescription: "unknown line type"
                )
            }
        }

        func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(version, forKey: .version)
            switch payload {
            case .device(let value):
                try container.encode("device", forKey: .type)
                try container.encode(value, forKey: .device)
            case .event(let value):
                try container.encode("event", forKey: .type)
                try container.encode(value, forKey: .event)
            case .run(let value):
                try container.encode("run", forKey: .type)
                try container.encode(value, forKey: .run)
            }
        }
    }
}
