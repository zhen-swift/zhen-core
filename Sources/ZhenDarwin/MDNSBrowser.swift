// MDNSBrowser.swift — dns_sd, contained.
//
// This file is the only place in the project that knows Bonjour is a C API. Above it
// there is an `AsyncStream<ServiceSighting>` and a protocol in core; below it there are
// callbacks, opaque pointers and a shared connection. Everything unpleasant about the
// second is supposed to stop at this line.
//
// ── Why dns_sd and not NWBrowser ────────────────────────────────────────────────
//
// `NWBrowser` has the nicer surface — Sendable results, no C, no manual lifetime — and
// it is the wrong tool here for one disqualifying reason: IT RETURNS NO IP ADDRESS. It
// hands back an endpoint naming a service instance, and the entire cascade in this
// system keys on the address, because the address is what joins a name to the host the
// sweep found. Recovering an address from an `NWBrowser` result means opening an
// `NWConnection` per instance and reading its resolved path — a connection per service
// per device, on a network with a few dozen instances — where `DNSServiceGetAddrInfo`
// is one more query on a connection that is already open.
//
// ── The shape, and why each part is not optional ─────────────────────────────────
//
//   * ONE shared connection. `DNSServiceCreateConnection` once, then every browse with
//     `kDNSServiceFlagsShareConnection`. Seventeen service types over one socket rather
//     than seventeen sockets, each with its own kernel buffer and its own wake-up.
//   * `DNSServiceSetDispatchQueue` for delivery. The alternative in every tutorial is a
//     `DispatchSourceRead` on `DNSServiceRefSockFD` calling `DNSServiceProcessResult` —
//     which is what this call does internally, correctly, including the parts about
//     draining and about not re-entering. Writing it by hand is a way to get it wrong.
//   * A `@convention(c)` callback cannot capture, so the session travels as a
//     `void *context`: `Unmanaged.passRetained` on the way in, recovered inside, and
//     released in `continuation.onTermination`. That termination handler fires on a
//     normal finish AND on a consumer walking away mid-browse, which is exactly the
//     lifetime a retained box and an open connection need — there is no other hook in
//     the language that covers both.
//
// ── The isolation rule for this file ─────────────────────────────────────────────
//
// Every field of `MDNSSession` is touched ONLY from `queue`, the serial queue handed to
// `DNSServiceSetDispatchQueue`. That is what makes an `@unchecked Sendable` class the
// right shape rather than a shortcut: the C library guarantees callbacks arrive
// serialized on that queue, so the queue is the isolation domain, and an actor would
// not be able to take part in it anyway — a `@convention(c)` callback cannot `await`.
//
// It is also a correctness requirement rather than tidiness. A shared connection may
// not be used from two threads at once, and the subordinate calls — the resolve issued
// from inside a browse reply, the address query issued from inside a resolve reply —
// are made from the callback itself precisely so they are on that queue. Hopping to an
// actor first and calling `DNSServiceResolve` from the cooperative pool would race the
// queue that is still delivering replies into the same connection.
//
// The actor below therefore accumulates COMPLETED sightings, which is where the
// concurrency actually is: sightings arrive from seventeen browses, the same device
// answers several of them, and the deduplication and the yield are the part that has to
// be safe against arbitrary tasks.
#if canImport(Darwin)

import Darwin
import Dispatch
import Foundation
import dnssd
import ZhenCore

/// Browses Bonjour over one shared `dns_sd` connection.
public struct DarwinServiceBrowser: ServiceBrowser {
    /// The types browsed, cleanest first. Comes from core, so a Linux browser and the
    /// CLI's `Info.plist` cannot drift from it.
    public var browsedTypes: [String] { BonjourVocabulary.browsedTypes }

    /// The interface index to browse on, or 0 for every interface.
    ///
    /// Scoped to the scanned interface for the same reason the SSDP socket is bound to
    /// it: a multi-homed machine with a VPN up would otherwise browse the tunnel and
    /// return names belonging to somebody else's network.
    public var interfaceIndex: UInt32

    /// Where a setup failure is recorded.
    ///
    /// The protocol says browsing never fails, and it does not — a browse that cannot
    /// start yields an empty stream. But "empty" and "unavailable" are different facts
    /// and the user is owed the difference, so the failure goes here, where the
    /// resolver collects it alongside every other source's.
    public var failures: DegradationLog

    /// Whether the browse ran cleanly or merely quietly.
    ///
    /// Separate from `failures` because it answers a question no degradation can: the
    /// naming stage needs to know, as a BOOLEAN, whether mDNS is entitled to be treated
    /// as evidence. A browse that died is not evidence that the network is silent, and
    /// letting the denial heuristic read it as such is how this tool ends up telling
    /// someone to change a privacy setting that was never the problem.
    public var health: BrowseHealth

    /// Creates a browser scoped to an interface.
    ///
    /// - Parameters:
    ///   - interface: the interface to browse on. Nil browses every interface, which is
    ///     what a caller with no target does.
    ///   - failures: the shared log for the naming stage.
    ///   - health: where asynchronous `dns_sd` errors are tallied.
    public init(
        interface: NetworkInterface?,
        failures: DegradationLog = DegradationLog(),
        health: BrowseHealth = BrowseHealth()
    ) {
        self.interfaceIndex = interface.map { unsafe if_nametoindex($0.name) } ?? 0
        self.failures = failures
        self.health = health
    }

    /// Sightings as they resolve, until the deadline or until the consumer stops.
    public func browse(deadline: Deadline) -> AsyncStream<ServiceSighting> {
        let (stream, continuation) = AsyncStream<ServiceSighting>.makeStream(
            // A browse on a home LAN yields tens of sightings, not thousands. The bound
            // exists so a consumer that stops consuming costs a fixed amount of memory,
            // which is the rule the whole project follows rather than a worry about
            // this particular number.
            bufferingPolicy: .bufferingNewest(1024)
        )
        let session = MDNSSession(
            interfaceIndex: interfaceIndex,
            types: browsedTypes,
            continuation: continuation,
            failures: failures,
            health: health
        )

        // The stage budget, armed on a queue that CANNOT be the session's own.
        //
        // The timer's whole job is to end a browse that is not going to end by itself,
        // and the way a browse fails to end is mDNSResponder wedging — which blocks the
        // session's serial queue. A timer scheduled there would be stuck behind exactly
        // the condition it exists to escape. Scheduled on a global queue it fires
        // regardless, and `finish()` is safe to call from anywhere.
        //
        // It is owned by the termination closure below: captured, so it stays alive as
        // long as the stream does, and cancelled exactly once when the stream ends.
        // That cancel is also what breaks the reference cycle it would otherwise form —
        // the stream retains the termination closure, which retains the timer, whose
        // event handler retains the continuation — because libdispatch releases a
        // source's handler blocks when the source is cancelled.
        let expiry = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        expiry.schedule(deadline: .now() + .nanoseconds(deadline.remaining.wholeNanoseconds))
        expiry.setEventHandler { continuation.finish() }

        continuation.onTermination = { _ in
            expiry.cancel()
            // Teardown is dispatched onto the session's own queue rather than run here,
            // because `onTermination` runs on whatever task dropped the stream and every
            // field of the session belongs to that queue. Deallocating the connection
            // from an arbitrary thread while the queue is mid-callback is the one way to
            // corrupt a shared connection. It is also where the session's retained box
            // is given back — `onTermination` fires on a normal finish AND on a consumer
            // walking away mid-browse, which is exactly the lifetime a retained context
            // and an open connection need.
            session.tearDown()
        }

        // Setup runs ON THE SESSION'S QUEUE, and this function does not wait for it.
        //
        // It used to be a `queue.sync`, called from a task-group child and therefore
        // from a COOPERATIVE POOL THREAD — and every call inside it is a synchronous IPC
        // round trip to mDNSResponder: create the connection, attach the queue, then
        // seventeen browses. A responder that is wedged, restarting, or slow parks that
        // pool thread with no cancellation point and no deadline, which is precisely the
        // hazard `PlatformSeam` cites as the reason `getnameinfo` was rejected in favour
        // of `DNSServiceQueryRecord`. The pool is sized to the core count; a handful of
        // those does not slow the scanner, it stops it.
        //
        // Nothing is lost by not waiting. The stream is the only channel a caller has,
        // a setup failure arrives on it as a finish plus a degradation, and the expiry
        // timer above is already armed on a queue this cannot block.
        session.start()
        // Armed last, so nothing can fire against a half-built session.
        expiry.resume()
        return stream
    }
}

/// A thread-safe collection point for degradations raised by name sources.
///
/// The three sources are constructed by the resolver and run concurrently; a plain
/// array would be a data race and an actor would force every source's setup path to be
/// async for the sake of appending a string. A lock over an array is the honest size of
/// this problem.
public final class DegradationLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [Degradation] = []

    /// Creates an empty log.
    public init() {}

    /// Appends one, ignoring an exact duplicate — three service types failing the same
    /// way is one fact, not three.
    public func record(_ degradation: Degradation) {
        lock.withLock {
            guard !entries.contains(degradation) else { return }
            entries.append(degradation)
        }
    }

    /// Everything recorded so far, in order.
    public var all: [Degradation] { lock.withLock { entries } }
}

/// Whether one name source failed outright.
///
/// The SSDP and NetBIOS equivalent of `BrowseHealth.didFail`, and it exists for the same
/// reason: a source that could not open its socket has already explained its own
/// silence, and the denial heuristic must not explain it a second time and differently.
/// Deliberately not derived from `DegradationLog` — that log also carries degradations
/// from sources that worked perfectly well, such as SSDP running out of time to fetch a
/// description, and reading "the log is non-empty" as "the source failed" would suppress
/// a true finding.
public final class FailureFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var raised = false

    /// Creates an unraised flag.
    public init() {}

    /// Marks the source as having failed.
    public func raise() { lock.withLock { raised = true } }

    /// Whether the source failed.
    public var isRaised: Bool { lock.withLock { raised } }
}

/// Whether a browse ran cleanly, and what went wrong if it did not.
///
/// `dns_sd` reports MOST failures asynchronously. `DNSServiceBrowse` returning
/// `kDNSServiceErr_NoError` means the request was accepted, not that it will work — and
/// the two errors that matter most in practice, `ServiceNotRunning` and
/// `DefunctConnection`, can only ever arrive later, through the callback. An earlier
/// version swallowed every one of them with a bare `return`, which meant the single
/// most common real-world failure of this stage was completely invisible: mDNSResponder
/// restarts (a VPN connecting will do it, so will changing network location), every
/// browse on the shared connection dies at once, the stream simply goes quiet — and the
/// silence was then handed to the denial heuristic, which told the user in confident
/// prose that their Local Network privacy setting was the likely cause. We sent people
/// to change a setting that was never the problem.
public final class BrowseHealth: @unchecked Sendable {
    private let lock = NSLock()
    private var codes: Set<DNSServiceErrorType> = []
    private var browseEnded = false

    /// Creates an empty tally.
    public init() {}

    /// Records one asynchronous error.
    ///
    /// - Parameters:
    ///   - code: the `dns_sd` error.
    ///   - endsBrowse: whether this kills the browse rather than one instance. True for
    ///     an error delivered to a browse callback, and for the connection-level codes
    ///     wherever they arrive.
    func record(_ code: DNSServiceErrorType, endsBrowse: Bool) {
        lock.withLock {
            codes.insert(code)
            if endsBrowse || MDNSError.isConnectionLevel(code) { browseEnded = true }
        }
    }

    /// Whether the browse stopped working, as opposed to hearing nothing.
    ///
    /// The naming stage reads this before it is allowed to attribute silence to a denied
    /// permission.
    public var didFail: Bool { lock.withLock { browseEnded } }

    /// The distinct error codes seen, for a report.
    public var errorCodes: [DNSServiceErrorType] { lock.withLock { codes.sorted() } }
}

/// Names for the `dns_sd` errors this code can actually meet.
enum MDNSError {
    /// Whether a code means the shared connection itself is gone.
    ///
    /// These are the ones that kill every browse at once rather than one lookup, so they
    /// end the browse whichever callback they arrive on.
    static func isConnectionLevel(_ code: DNSServiceErrorType) -> Bool {
        // The `kDNSServiceErr_*` constants import as `Int` while the callbacks hand back
        // `DNSServiceErrorType` (`Int32`), so the widening happens once, here, rather
        // than at every comparison.
        switch Int(code) {
        case kDNSServiceErr_ServiceNotRunning, kDNSServiceErr_DefunctConnection,
             kDNSServiceErr_BadReference, kDNSServiceErr_NotInitialized,
             kDNSServiceErr_BadState:
            true
        default:
            false
        }
    }

    /// A short phrase naming the error, for a degradation a person reads.
    ///
    /// The numeric code is kept alongside the phrase rather than replaced by it: the
    /// phrase is what makes the sentence readable, and the number is what makes a bug
    /// report actionable.
    static func describe(_ code: DNSServiceErrorType) -> String {
        let name: String
        switch Int(code) {
        case kDNSServiceErr_ServiceNotRunning: name = "the Bonjour service is not running"
        case kDNSServiceErr_DefunctConnection: name = "the connection to Bonjour was dropped"
        case kDNSServiceErr_BadReference: name = "a stale Bonjour reference"
        case kDNSServiceErr_NotInitialized: name = "Bonjour was not initialised"
        case kDNSServiceErr_BadState: name = "Bonjour was in a bad state"
        case kDNSServiceErr_Timeout: name = "the lookup timed out"
        case kDNSServiceErr_NoSuchName, kDNSServiceErr_NoSuchRecord: name = "no such record"
        case kDNSServiceErr_PolicyDenied: name = "policy denied the lookup"
        case kDNSServiceErr_NoAuth: name = "the lookup was not authorised"
        case kDNSServiceErr_Firewall: name = "a firewall blocked the lookup"
        case kDNSServiceErr_Refused: name = "the lookup was refused"
        case kDNSServiceErr_Transient: name = "a transient failure"
        default: name = "an unexpected failure"
        }
        return "\(name), error \(code)"
    }

    /// The degradation for one asynchronous error.
    static func degradation(_ code: DNSServiceErrorType, endsBrowse: Bool) -> Degradation {
        if endsBrowse || isConnectionLevel(code) {
            return Degradation(
                stage: .naming,
                reason: """
                    Bonjour stopped answering partway through this scan — \
                    \(describe(code)) — so Bonjour names are incomplete. Names that had \
                    already arrived are kept; anything still being looked up was lost. This \
                    is usually the system's Bonjour service restarting, which connecting a \
                    VPN or changing network location will do, and it is not a permissions \
                    problem.
                    """,
                recoverable: true
            )
        }
        return Degradation(
            stage: .naming,
            reason: """
                A Bonjour service could not be looked up — \(describe(code)) — so one device \
                may be reported without a name. The rest of the scan is unaffected.
                """,
            recoverable: true
        )
    }
}

/// Deduplicates and publishes completed sightings.
///
/// The same device answers several of the seventeen browses, `_device-info` in
/// particular arrives more than once per scan, and mDNSResponder re-reports records it
/// already gave us whenever a cache entry refreshes — so without this every repeat would
/// be yielded again and the "known by" list would stutter.
///
/// ── Why this is a lock and not an actor ─────────────────────────────────────────
///
/// It was an actor, and the actor was the bug. A `@convention(c)` callback cannot
/// `await`, so reaching an actor from one meant `Task { await accumulator.record(…) }` —
/// an UNSTRUCTURED task, with no parent, scheduled onto the cooperative pool and racing
/// the stage deadline. A sighting that completed within a scheduling hop of the timer
/// was simply dropped: the C side had the answer, the hand-off was queued, the timer
/// fired, `finish()` won, and a device that Bonjour had successfully named came out
/// unnamed. Intermittently, and more often on a busy machine, which is the worst way for
/// a bug to behave.
///
/// The fix is not to track the task — it is to not need one. The work here is a set
/// insert and a `yield`, both of which are safe to do synchronously from the delivery
/// queue, and `AsyncStream.Continuation` is designed to be yielded to from anywhere. So
/// the sighting is published on the same thread that produced it, before the callback
/// returns, and there is no hand-off left to outlive anything.
///
/// The trade is that this is a lock rather than a hop, and it is the right way round:
/// the critical section is one `Set.insert`, and it is held for nanoseconds by a queue
/// that is already serial.
final class MDNSAccumulator: @unchecked Sendable {
    /// One sighting's identity: the same instance of the same type at the same address
    /// is the same observation however many times it is reported.
    private struct Key: Hashable {
        let ip: IPv4Address
        let serviceType: String
        let instanceName: String
    }

    private let lock = NSLock()
    private var seen: Set<Key> = []
    private let continuation: AsyncStream<ServiceSighting>.Continuation

    init(continuation: AsyncStream<ServiceSighting>.Continuation) {
        self.continuation = continuation
    }

    /// Publishes a sighting unless it is an exact repeat.
    ///
    /// The `yield` is deliberately OUTSIDE the lock. Nothing about publishing needs the
    /// lock held, and a continuation is not a thing to call into while holding one.
    func record(_ sighting: ServiceSighting) {
        let key = Key(
            ip: sighting.ip,
            serviceType: sighting.serviceType,
            instanceName: sighting.instanceName
        )
        let isNew = lock.withLock { seen.insert(key).inserted }
        guard isNew else { return }
        continuation.yield(sighting)
    }
}

/// What a browse reply has learned so far, before the resolve and the address query
/// have filled the rest in.
///
/// Carried in a class because the operation's `void *context` has to point at something
/// with a stable address that outlives the call that created it.
final class MDNSOperation {
    /// Back-reference for the callback. `unowned` breaks the cycle with the session's
    /// own table, and it cannot dangle: operations are removed only by the session, and
    /// the session outlives every one of them by construction — teardown clears the
    /// table before the connection goes away.
    unowned let session: MDNSSession
    /// The instance name exactly as browsed, before cleaning.
    let instanceName: String
    /// The normalized service type — `_airplay._tcp`.
    let serviceType: String
    /// The domain the browse reply named, needed verbatim by `DNSServiceResolve`.
    let domain: String
    /// The regtype the browse reply named, likewise verbatim.
    let regtype: String
    /// Which interface it was seen on.
    let interfaceIndex: UInt32
    /// The TXT record, once the resolve has delivered it.
    var txt: [String: String] = [:]
    /// The host name the resolve pointed at.
    var hostname: String?

    init(
        session: MDNSSession,
        instanceName: String,
        serviceType: String,
        domain: String,
        regtype: String,
        interfaceIndex: UInt32
    ) {
        self.session = session
        self.instanceName = instanceName
        self.serviceType = serviceType
        self.domain = domain
        self.regtype = regtype
        self.interfaceIndex = interfaceIndex
    }
}

/// The shared connection, its subordinate operations, and their lifetimes.
///
/// `@unchecked Sendable` with a stated rule rather than a checked one: every stored
/// property is read and written only on `queue`. See the file header for why that is
/// the only arrangement the C API permits.
@safe final class MDNSSession: @unchecked Sendable {
    /// The serial queue `dns_sd` delivers every callback on, and therefore the
    /// isolation domain for every field below.
    private let queue = DispatchQueue(label: "com.jctec.zhen.mdns", qos: .userInitiated)
    private let interfaceIndex: UInt32
    private let types: [String]
    private let continuation: AsyncStream<ServiceSighting>.Continuation
    private let accumulator: MDNSAccumulator
    /// Where asynchronous failures are reported to the user.
    private let failures: DegradationLog
    /// Where they are tallied for the denial heuristic.
    private let health: BrowseHealth

    /// The one connection every browse, resolve and address query shares.
    private var shared: DNSServiceRef?
    /// Subordinate refs that are still live, by token. A ref is removed here at the
    /// moment it is deallocated, so teardown cannot deallocate one twice.
    private var operationRefs: [Int32: DNSServiceRef] = unsafe [:]
    /// The context objects those refs point at. The session owning them strongly is
    /// what lets the contexts be passed UNRETAINED — the pointer cannot outlive this
    /// table, and the table is cleared only on the queue.
    private var operations: [Int32: MDNSOperation] = [:]
    /// Instances already being resolved, so a re-reported browse reply does not open a
    /// second resolve for a service we are already asking about.
    private var resolving: Set<String> = []
    private var nextToken: Int32 = 0
    private var torn = false
    /// The session's own `void *context`, and the retain that keeps it alive while C
    /// holds a pointer to it.
    ///
    /// Created in `start()` and given back in `tearDown()`. Holding it here rather than
    /// in the caller's closure is what keeps the raw pointer out of a `@Sendable`
    /// capture — the pointer never leaves the queue that owns it.
    private var selfBox: UnsafeMutableRawPointer?

    init(
        interfaceIndex: UInt32,
        types: [String],
        continuation: AsyncStream<ServiceSighting>.Continuation,
        failures: DegradationLog,
        health: BrowseHealth
    ) {
        self.interfaceIndex = interfaceIndex
        self.types = types
        self.continuation = continuation
        self.failures = failures
        self.health = health
        self.accumulator = MDNSAccumulator(continuation: continuation)
    }

    /// Records one asynchronous `dns_sd` error, both for the user and for the heuristic.
    ///
    /// Callable from any callback on the delivery queue. `DegradationLog` drops exact
    /// duplicates, so seventeen browses dying of the same cause is reported as the one
    /// fact it is rather than seventeen times.
    func recordError(_ code: DNSServiceErrorType, endsBrowse: Bool) {
        health.record(code, endsBrowse: endsBrowse)
        failures.record(MDNSError.degradation(code, endsBrowse: endsBrowse))
    }

    /// Opens the connection and starts one browse per service type.
    ///
    /// Synchronous, because the caller needs to know whether Bonjour is reachable at all
    /// before it decides whether to report a degradation. Returns false when the
    /// connection could not be created, which on a Mac means mDNSResponder is not
    /// answering — a genuinely broken system rather than a denied permission, since a
    /// DENIED permission returns an open connection that reports nothing.
    func start() {
        queue.async { [self] in
            var connection: DNSServiceRef?
            // SAFETY: DNSServiceCreateConnection writes one opaque ref into storage we
            // own. Nothing escapes.
            guard unsafe DNSServiceCreateConnection(&connection) == kDNSServiceErr_NoError,
                  let connection = unsafe connection
            else { return unreachable() }
            // Hand delivery to GCD. From here every callback arrives on `queue`, which
            // is the guarantee the whole isolation rule rests on.
            guard unsafe DNSServiceSetDispatchQueue(connection, queue) == kDNSServiceErr_NoError else {
                unsafe DNSServiceRefDeallocate(connection)
                return unreachable()
            }
            unsafe shared = connection

            // SAFETY: passRetained balances exactly one release in `tearDown()`, which
            // runs exactly once — `torn` guards it and AsyncStream guarantees
            // `onTermination` fires once, on a normal finish, on consumer cancellation
            // and on the consumer being deallocated.
            let context = unsafe Unmanaged.passRetained(self).toOpaque()
            unsafe selfBox = context

            var anyStarted = false
            for type in types {
                // The documented shared-connection pattern: copy the shared ref into a
                // fresh variable and pass ITS address. The library overwrites the copy
                // with a subordinate ref and leaves the shared one alone.
                var operation: DNSServiceRef? = unsafe connection
                let status = unsafe type.withCString { typePointer in
                    unsafe DNSServiceBrowse(
                        &operation,
                        kDNSServiceFlagsShareConnection,
                        interfaceIndex,
                        typePointer,
                        nil,
                        mdnsBrowseReply,
                        context
                    )
                }
                if status == kDNSServiceErr_NoError, unsafe operation != nil {
                    anyStarted = true
                    let token = takeToken()
                    unsafe operationRefs[token] = operation
                }
            }
            guard anyStarted else {
                unsafe DNSServiceRefDeallocate(connection)
                unsafe shared = nil
                // SAFETY: the matching release for the passRetained above, on the path
                // where no callback was ever armed and so none can hold the pointer.
                unsafe Unmanaged<MDNSSession>.fromOpaque(context).release()
                unsafe selfBox = nil
                return unreachable()
            }
        }
    }

    /// Reports that Bonjour could not be reached at all, and ends the stream.
    ///
    /// The synchronous half of `dns_sd` failing is rare and means something structural —
    /// mDNSResponder not answering at all — as opposed to the asynchronous errors, which
    /// are the common case and arrive through the callbacks.
    private func unreachable() {
        health.record(DNSServiceErrorType(kDNSServiceErr_ServiceNotRunning), endsBrowse: true)
        failures.record(Degradation(
            stage: .naming,
            reason: """
                Bonjour could not be reached on this machine, so Bonjour names cannot be \
                read this scan. Devices that publish a name only over Bonjour will appear \
                unnamed; everything else about them is unaffected.
                """,
            recoverable: true
        ))
        continuation.finish()
    }

    /// Deallocates the connection and everything under it, then runs `afterward`.
    ///
    /// Only the SHARED ref is deallocated. `dns_sd` documents that deallocating a shared
    /// connection deallocates its subordinate operations too, so walking the table and
    /// deallocating each one would be a double free — the tables are cleared instead,
    /// which also drops the context objects the C side may no longer reference.
    func tearDown() {
        queue.async { [self] in
            guard !torn else { return }
            torn = true
            unsafe operationRefs.removeAll()
            operations.removeAll()
            tokensByOperation.removeAll()
            resolving.removeAll()
            if let shared = unsafe shared {
                unsafe DNSServiceRefDeallocate(shared)
                unsafe self.shared = nil
            }
            // The release happens LAST, after the connection is gone, so that no
            // callback can still be in flight holding this pointer. Doing it first
            // would be a use-after-free with a delivery queue still running.
            if let box = unsafe selfBox {
                // SAFETY: the matching release for the passRetained in `start()`.
                unsafe Unmanaged<MDNSSession>.fromOpaque(box).release()
                unsafe selfBox = nil
            }
        }
    }

    private func takeToken() -> Int32 {
        nextToken &+= 1
        return nextToken
    }

    // ── Cascade: browse → resolve → address ──────────────────────────────────────

    /// A browse reply arrived. Ask who it is.
    ///
    /// Called from the browse callback, on `queue`.
    func beginResolve(instanceName: String, regtype: String, domain: String, interfaceIndex: UInt32) {
        guard !torn, let shared = unsafe shared else { return }
        let serviceType = BonjourVocabulary.normalizeServiceType(regtype)
        // One resolve per (instance, type, interface). mDNSResponder re-reports a browse
        // reply whenever its cache entry is refreshed, and each repeat would otherwise
        // open another resolve against the same instance.
        let key = "\(instanceName)|\(serviceType)|\(interfaceIndex)"
        guard resolving.insert(key).inserted else { return }

        let operation = MDNSOperation(
            session: self,
            instanceName: instanceName,
            serviceType: serviceType,
            domain: domain,
            regtype: regtype,
            interfaceIndex: interfaceIndex
        )
        let token = takeToken()
        operations[token] = operation
        // SAFETY: unretained is correct BECAUSE the session's `operations` table holds
        // the only strong reference and is only mutated on this queue. The pointer is
        // handed back to us on this same queue, and the entry is removed only after the
        // ref that could deliver it has been deallocated.
        let context = unsafe Unmanaged.passUnretained(operation).toOpaque()

        var reference: DNSServiceRef? = unsafe shared
        let status = unsafe instanceName.withCString { namePointer in
            unsafe regtype.withCString { typePointer in
                unsafe domain.withCString { domainPointer in
                    unsafe DNSServiceResolve(
                        &reference,
                        kDNSServiceFlagsShareConnection,
                        interfaceIndex,
                        namePointer,
                        typePointer,
                        domainPointer,
                        mdnsResolveReply,
                        context
                    )
                }
            }
        }
        guard status == kDNSServiceErr_NoError, unsafe reference != nil else {
            operations[token] = nil
            resolving.remove(key)
            return
        }
        unsafe operationRefs[token] = reference
        tokensByOperation[ObjectIdentifier(operation)] = token
    }

    /// Reverse index so a callback holding only its context object can find the token
    /// its subordinate ref is filed under.
    private var tokensByOperation: [ObjectIdentifier: Int32] = [:]

    /// A resolve reply arrived. Ask for the address.
    ///
    /// Called from the resolve callback, on `queue`. The resolve ref is deallocated
    /// here — `dns_sd` permits deallocating a ref from inside its own callback, and a
    /// resolve left running keeps reporting the same instance forever.
    func beginAddressQuery(for operation: MDNSOperation, hostTarget: String) {
        guard !torn, let shared = unsafe shared else { return }
        let identity = ObjectIdentifier(operation)
        if let token = tokensByOperation[identity], let reference = unsafe operationRefs[token] {
            unsafe DNSServiceRefDeallocate(reference)
            unsafe operationRefs[token] = nil
        }
        operation.hostname = hostTarget.hasSuffix(".")
            ? String(hostTarget.dropLast())
            : hostTarget

        // SAFETY: same unretained contract as the resolve above — the object stays in
        // `operations` until this query is finished with it.
        let context = unsafe Unmanaged.passUnretained(operation).toOpaque()
        var reference: DNSServiceRef? = unsafe shared
        let status = unsafe hostTarget.withCString { hostPointer in
            unsafe DNSServiceGetAddrInfo(
                &reference,
                kDNSServiceFlagsShareConnection,
                operation.interfaceIndex,
                // IPv4 only. The cascade keys on `IPv4Address`, and asking for AAAA
                // records too would produce callbacks this code would immediately
                // discard while keeping the query open longer.
                DNSServiceProtocol(kDNSServiceProtocol_IPv4),
                hostPointer,
                mdnsAddressReply,
                context
            )
        }
        guard status == kDNSServiceErr_NoError, unsafe reference != nil else {
            retire(operation)
            return
        }
        let token = takeToken()
        unsafe operationRefs[token] = reference
        tokensByOperation[identity] = token
    }

    /// An address arrived. Publish the sighting and close the operation out.
    ///
    /// Called from the address callback, on `queue`.
    func complete(_ operation: MDNSOperation, address: IPv4Address) {
        let sighting = ServiceSighting(
            ip: address,
            serviceType: operation.serviceType,
            // Cleaned HERE rather than at the cascade, so that `ServiceSighting`'s
            // documented promise — "the instance name as advertised, after cleaning" —
            // is true of every value of the type, including one a Linux browser makes.
            instanceName: BonjourVocabulary.cleanInstanceName(operation.instanceName)
                ?? operation.instanceName,
            hostname: operation.hostname,
            txt: operation.txt,
            rank: BonjourVocabulary.rank(of: operation.serviceType)
        )
        retire(operation)
        // The hand-off from the C world to the Swift one, and it is a plain call.
        // Everything above this line is a serial queue and a pile of pointers;
        // everything below is a value type on an `AsyncStream`. See `MDNSAccumulator`
        // for why there is no `Task` here any more.
        accumulator.record(sighting)
    }

    /// Deallocates an operation's ref and drops its context.
    func retire(_ operation: MDNSOperation) {
        let identity = ObjectIdentifier(operation)
        if let token = tokensByOperation[identity] {
            if let reference = unsafe operationRefs[token] {
                unsafe DNSServiceRefDeallocate(reference)
            }
            unsafe operationRefs[token] = nil
            operations[token] = nil
            tokensByOperation[identity] = nil
        }
        // `resolving` is deliberately NOT cleared. Its job is to stop a re-reported
        // browse reply from opening a second resolve for an instance we have already
        // asked about, and that remains true after the answer arrives.
    }
}

// ── The C callbacks ──────────────────────────────────────────────────────────────
//
// Non-capturing by necessity: `@convention(c)` has no context beyond the `void *` it is
// handed. Each one does the same three things — recover the Swift object, copy the C
// strings while they are still valid, hand off — and nothing else. A C string parameter
// is only guaranteed for the duration of the call, so every one of them is copied into
// a Swift `String` before anything else happens.

/// A service instance appeared or disappeared.
private let mdnsBrowseReply: DNSServiceBrowseReply = {
    _, flags, interfaceIndex, errorCode, serviceName, regtype, replyDomain, context in
    guard let context = unsafe context else { return }
    // SAFETY: the pointer was made by passRetained in `browse(deadline:)` and is
    // released only in tearDown, after the connection that could deliver this callback
    // has been deallocated. takeUnretainedValue leaves that retain intact.
    let session = unsafe Unmanaged<MDNSSession>.fromOpaque(context).takeUnretainedValue()

    // AN ERROR HERE ENDS THIS BROWSE, AND IT IS REPORTED.
    //
    // This is the ONLY channel by which mDNSResponder can tell us that something went
    // wrong after setup — `DNSServiceBrowse` returning `NoError` means the request was
    // accepted, not that it will keep working. `ServiceNotRunning` and
    // `DefunctConnection` can arrive nowhere else. Returning silently here, as an
    // earlier version did, is what let a mid-scan responder restart look exactly like a
    // network with nothing on it.
    guard errorCode == kDNSServiceErr_NoError else {
        session.recordError(errorCode, endsBrowse: true)
        return
    }
    guard // A removal tells us a service went away. This scan reports what is present
          // now, and a device that withdrew a record mid-scan is not evidence about
          // anything else it advertises, so removals are ignored rather than used to
          // retract a name we already published.
          flags & kDNSServiceFlagsAdd != 0,
          let serviceName = unsafe serviceName,
          let regtype = unsafe regtype,
          let replyDomain = unsafe replyDomain
    else { return }
    // SAFETY: valid for the duration of this callback only, which is why each is copied
    // into a Swift String right here rather than being passed on as a pointer.
    let name = unsafe String(cString: serviceName)
    let type = unsafe String(cString: regtype)
    let domain = unsafe String(cString: replyDomain)
    session.beginResolve(
        instanceName: name, regtype: type, domain: domain, interfaceIndex: interfaceIndex
    )
}

/// An instance resolved to a host and a TXT record.
private let mdnsResolveReply: DNSServiceResolveReply = {
    _, _, _, errorCode, _, hostTarget, _, txtLen, txtRecord, context in
    guard let context = unsafe context else { return }
    // SAFETY: unretained recovery of an object the session's `operations` table holds
    // strongly, on the queue that owns that table.
    let operation = unsafe Unmanaged<MDNSOperation>.fromOpaque(context).takeUnretainedValue()
    // A failure here normally costs one device its name, not the browse — unless the
    // code is connection-level, which `recordError` works out for itself. Either way it
    // is said out loud rather than swallowed.
    guard errorCode == kDNSServiceErr_NoError else {
        operation.session.recordError(errorCode, endsBrowse: false)
        operation.session.retire(operation)
        return
    }
    guard let hostTarget = unsafe hostTarget else {
        operation.session.retire(operation)
        return
    }
    if let txtRecord = unsafe txtRecord {
        unsafe operation.txt = parseTXTRecord(length: txtLen, bytes: txtRecord)
    }
    let host = unsafe String(cString: hostTarget)
    operation.session.beginAddressQuery(for: operation, hostTarget: host)
}

/// A host resolved to an address.
private let mdnsAddressReply: DNSServiceGetAddrInfoReply = {
    _, _, _, errorCode, _, address, _, context in
    guard let context = unsafe context else { return }
    // SAFETY: as above.
    let operation = unsafe Unmanaged<MDNSOperation>.fromOpaque(context).takeUnretainedValue()
    guard errorCode == kDNSServiceErr_NoError else {
        operation.session.recordError(errorCode, endsBrowse: false)
        operation.session.retire(operation)
        return
    }
    guard let address = unsafe address else {
        operation.session.retire(operation)
        return
    }
    // SAFETY: an AF_INET sockaddr is a sockaddr_in, and its address sits four bytes in.
    // Read by offset rather than by binding memory: the kernel's alignment is not ours
    // to assume, and `bindMemory` on a pointer we did not allocate is undefined
    // behaviour rather than merely unwise.
    guard unsafe address.pointee.sa_family == sa_family_t(AF_INET) else { return }
    let raw = unsafe UnsafeRawPointer(address).loadUnaligned(fromByteOffset: 4, as: UInt32.self)
    operation.session.complete(operation, address: IPv4Address(raw: UInt32(bigEndian: raw)))
}

/// Decodes a DNS-SD TXT record into key/value pairs.
///
/// Uses the library's own accessors rather than walking the length-prefixed strings by
/// hand. The wire format is simple enough to parse in ten lines and has two details that
/// are easy to get wrong — a key with no `=` is present with an empty value and is NOT
/// the same as an absent key, and a value may contain `=` — and `TXTRecordGetItemAtIndex`
/// already knows both.
private func parseTXTRecord(length: UInt16, bytes: UnsafePointer<UInt8>) -> [String: String] {
    var result: [String: String] = [:]
    // SAFETY: every call below reads the buffer the library handed us, bounded by the
    // length it handed us with it. The key buffer is ours and is sized to the protocol
    // maximum for a single key.
    let count = unsafe TXTRecordGetCount(length, bytes)
    guard count > 0 else { return result }
    var key = [CChar](repeating: 0, count: 256)
    for index in 0..<count {
        var valueLength: UInt8 = 0
        var value: UnsafeRawPointer?
        let status = unsafe key.withUnsafeMutableBufferPointer { buffer -> DNSServiceErrorType in
            unsafe TXTRecordGetItemAtIndex(
                length, bytes, index, UInt16(buffer.count), buffer.baseAddress, &valueLength, &value
            )
        }
        guard status == kDNSServiceErr_NoError else { continue }
        // `key` is a C string in a buffer we own: decode up to the terminator rather
        // than over the whole 256 bytes, which would append 250 nulls to every key.
        let name = String(decoding: key.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        guard !name.isEmpty else { continue }
        if let value = unsafe value, valueLength > 0 {
            // SAFETY: `valueLength` bytes at `value`, both supplied by the call above.
            let buffer = unsafe UnsafeRawBufferPointer(start: value, count: Int(valueLength))
            result[name] = unsafe String(decoding: buffer, as: UTF8.self)
        } else {
            // A present key with no value. Distinct from absence, and the distinction
            // is load-bearing in DNS-SD, so it is preserved here rather than skipped.
            result[name] = ""
        }
    }
    return result
}

#endif
