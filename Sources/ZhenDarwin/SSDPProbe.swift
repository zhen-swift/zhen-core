// SSDPProbe.swift — the source that names everything Bonjour does not.
//
// On a network of Apple hardware mDNS carries almost all the naming value, and it is
// easy to conclude from that network that SSDP is redundant. It is not: televisions,
// printers, games consoles, NAS boxes and most smart-home bridges speak UPnP and never
// touch Bonjour at all. SSDP is what turns those rows from an address into a device.
//
// The protocol is two steps and both are simple. An M-SEARCH datagram to the multicast
// group 239.255.255.250:1900 makes every UPnP device on the segment answer with an
// HTTP-shaped response carrying a `LOCATION:` URL, and fetching that URL yields an XML
// document whose `<friendlyName>` is the name a person set and whose `<modelName>` is
// what the thing is.
//
// ── The binding rule, which is not optional ──────────────────────────────────────
//
// The socket binds to the SELECTED INTERFACE'S ADDRESS and sets `IP_MULTICAST_IF` to
// the same address. Binding `INADDR_ANY` and letting the kernel choose is the obvious
// version and it is wrong on exactly the machines this tool is for. A multicast send
// from an unbound socket leaves through whichever interface the kernel's multicast
// route names, and on a laptop with a VPN up that is routinely the tunnel — so the
// M-SEARCH goes to the corporate network, the responses describe somebody else's
// printers, and the report attributes them to addresses on the home LAN. The failure
// is silent and the output looks plausible, which is the worst combination available.
//
// ── The budget split ─────────────────────────────────────────────────────────────
//
// Roughly 60% listening, 40% fetching. Both halves are necessary and neither is worth
// much alone: a responder that is never asked for its description contributes only a
// `SERVER:` string like "Linux/4.4 UPnP/1.0", which is an OS and not a device. The
// listen half is also what the `MX:` header tells the devices — they spread their
// replies uniformly over that many seconds to avoid a broadcast storm — so the header
// is computed from the budget rather than pinned to a constant, and a shorter scan asks
// the network to answer faster rather than simply hearing less of it.
#if canImport(Darwin)

import Darwin
import Dispatch
import Foundation
import ZhenCore

/// Discovers UPnP devices by M-SEARCH, then describes them.
public struct DarwinSSDPDiscovery: SSDPDiscovery {
    /// Where setup failures are recorded, shared with the other name sources.
    public var failures: DegradationLog
    /// Raised when the search could not run at all, so the denial heuristic knows this
    /// source's silence is already explained.
    public var failed: FailureFlag
    /// How many description documents are fetched at once.
    ///
    /// Small on purpose. These are embedded HTTP servers on televisions and printers;
    /// a dozen simultaneous requests is not a load test the scanner needs to run, and
    /// the fetch half of the budget is bounded anyway.
    public var fetchConcurrency: Int

    /// How many M-SEARCH datagrams go out per search.
    ///
    /// Three, all early in the listen window. See the send loop for why a bounded,
    /// front-loaded number is the only defensible choice here.
    public static let searchTransmissions = 3

    /// Creates the discoverer.
    public init(
        failures: DegradationLog = DegradationLog(),
        failed: FailureFlag = FailureFlag(),
        fetchConcurrency: Int = 8
    ) {
        self.failures = failures
        self.failed = failed
        self.fetchConcurrency = fetchConcurrency
    }

    /// Responders, described where a description could be fetched.
    public func search(from interface: NetworkInterface, deadline: Deadline) -> AsyncStream<SSDPSighting> {
        let (stream, continuation) = AsyncStream<SSDPSighting>.makeStream(
            bufferingPolicy: .bufferingNewest(512)
        )
        let log = failures
        let failureFlag = failed
        let concurrency = fetchConcurrency

        let work = Task {
            let socket: UDPProbe
            do {
                socket = try SSDPSocket.open(on: interface)
            } catch {
                failureFlag.raise()
                log.record(Degradation(
                    stage: .naming,
                    reason: """
                        A multicast socket could not be opened on \(interface.name) (\(error)), so \
                        UPnP names cannot be read this scan. Televisions, printers, consoles and \
                        NAS boxes that do not speak Bonjour will appear unnamed.
                        """,
                    recoverable: true
                ))
                continuation.finish()
                return
            }

            // 60/40. `fraction` clamps to the parent, so neither half can outlive the
            // stage however the arithmetic comes out.
            let listenDeadline = deadline.fraction(0.60)
            let listenSeconds = max(1, min(3, Int(listenDeadline.remaining.milliseconds / 1000)))

            // The reader RETURNS its table rather than mutating a captured one. A
            // captured `var` written from the reader and read by the fetch phase is a
            // data race the compiler will not let through, and papering over it with a
            // lock would hide the real structure: the listen phase has a definite end,
            // and its output is a value handed to the phase after it.
            let replies = socket.events()
            let reader = Task { () -> [IPv4Address: SSDPResponse] in
                var found: [IPv4Address: SSDPResponse] = [:]
                for await event in replies {
                    guard case .datagram(let reply) = event,
                          let parsed = SSDPResponse.parse(
                            String(decoding: reply.payload, as: UTF8.self), from: reply.source)
                    else { continue }
                    // First response per address wins. A device answering `ssdp:all`
                    // sends one datagram per service it hosts — a television will send
                    // six — and every one of them carries the same LOCATION.
                    if found[reply.source] == nil { found[reply.source] = parsed }
                }
                return found
            }

            // Sent three times, all of them EARLY, and then the socket only listens.
            //
            // More than once because this is UDP to a multicast group and a lost request
            // is indistinguishable from a device that is not there. But a bounded number
            // of times, and this is the part worth stating: an earlier version resent
            // every 250 ms for the whole window, which on a 1.9-second listen is eight
            // M-SEARCHes — and every UPnP device on the segment answers every one of
            // them, with one datagram per service it hosts. That is a multicast storm
            // this tool has no business creating on somebody's network to learn the same
            // three names.
            //
            // Early, because `MX` is counted by each device from the moment IT receives
            // the request. A send late in the window asks for replies that arrive after
            // the window has closed.
            let request = SSDPSocket.searchRequest(mx: listenSeconds)
            socket.send(request, to: SSDPSocket.group, port: SSDPSocket.port)
            var transmissions = 1
            while !Task.isCancelled, !listenDeadline.isExpired {
                try? await Task.sleep(for: min(.milliseconds(200), listenDeadline.remaining))
                let more = transmissions < DarwinSSDPDiscovery.searchTransmissions
                if more, listenDeadline.remaining > .milliseconds(600) {
                    socket.send(request, to: SSDPSocket.group, port: SSDPSocket.port)
                    transmissions += 1
                }
            }
            // Stop the socket FIRST. That finishes the datagram stream, so the reader's
            // `for await` ends on its own and `value` returns the complete table —
            // where cancelling the reader would discard whatever it had.
            socket.stop()
            let responders = await reader.value

            guard !Task.isCancelled else { continuation.finish(); return }

            // ── Fetch half ───────────────────────────────────────────────────────
            //
            // What is left of the stage budget, which is the 40% the listen half did
            // not use plus whatever it gave back by finishing early.
            let fetchDeadline = deadline
            let addresses = responders.keys.sorted()

            // Validation happens HERE, before the pool, because it is pure and
            // synchronous and because a refusal should cost no network at all. Every
            // LOCATION is an attacker-controlled string; `permittedURL` is what stops
            // this scanner being used to make requests on somebody else's behalf.
            var building: [IPv4Address: URL] = [:]
            var refusals: [String] = []
            for address in addresses {
                guard let location = responders[address]?.location else { continue }
                switch UPnPDescription.permittedURL(location, from: address) {
                case .permitted(let url):
                    building[address] = url
                case .refused(let why):
                    refusals.append("\(address) was not described because \(why)")
                }
            }
            // Frozen before the pool sees it. The fetch closure runs concurrently, and a
            // captured `var` would be a data race — but more to the point, the set of
            // addresses this scan is allowed to contact must be decided once and then be
            // incapable of growing.
            let permitted = building

            let run = await boundedPool(
                over: addresses,
                concurrency: concurrency,
                deadline: fetchDeadline
            ) { address -> ProbeOutcome<SSDPSighting> in
                guard let response = responders[address] else { return .silent }
                var sighting = SSDPSighting(
                    ip: address,
                    server: response.server,
                    location: response.location
                )
                if let url = permitted[address],
                   let document = await UPnPDescription.fetch(url, within: fetchDeadline) {
                    sighting.friendlyName = document.friendlyName
                    sighting.modelName = document.modelName
                }
                return .observed(sighting)
            }
            if !refusals.isEmpty {
                // Surfaced rather than logged. A refused LOCATION is either a broken
                // device or an attempt to use this scanner as a proxy, and both are
                // things the person running it should be able to see.
                log.record(Degradation(
                    stage: .naming,
                    reason: """
                        \(refusals.count) UPnP responder\(refusals.count == 1 ? "" : "s") \
                        advertised a description address that this scan refused to fetch, so \
                        \(refusals.count == 1 ? "it is" : "they are") reported without a name. \
                        A device may only describe itself: \(refusals.sorted().joined(separator: "; ")).
                        """,
                    recoverable: false
                ))
            }
            for address in addresses {
                guard let sighting = run.results[address] else { continue }
                continuation.yield(sighting)
            }
            if run.termination == .deadlineExpired, run.abandoned > 0 {
                log.record(Degradation(
                    stage: .naming,
                    reason: """
                        \(run.abandoned) UPnP device\(run.abandoned == 1 ? "" : "s") answered the \
                        search but there was no time left to fetch \
                        \(run.abandoned == 1 ? "its description" : "their descriptions"), so \
                        \(run.abandoned == 1 ? "it is" : "they are") reported without a name. A \
                        longer --deadline would name \(run.abandoned == 1 ? "it" : "them").
                        """,
                    recoverable: true
                ))
            }
            continuation.finish()
        }

        // Cancelling the consumer tears the search down rather than leaving a socket
        // open with nowhere to report to. Fires on a normal finish too, which is
        // harmless — the task has already returned.
        continuation.onTermination = { _ in work.cancel() }
        return stream
    }
}

/// One M-SEARCH response, parsed.
struct SSDPResponse: Sendable, Hashable {
    /// The URL of the device description document.
    var location: String?
    /// The `SERVER:` header — an OS and UPnP stack string.
    var server: String?

    /// Parses an M-SEARCH response.
    ///
    /// The wire format is HTTP-shaped without being HTTP: a status line, then headers,
    /// then nothing. Header names are matched case-insensitively because devices are
    /// wildly inconsistent about them — `LOCATION`, `Location` and `location` all
    /// appear on the same network — and a case-sensitive match silently loses the
    /// device rather than failing.
    static func parse(_ text: String, from source: IPv4Address) -> SSDPResponse? {
        var lines = text.split(whereSeparator: \.isNewline).makeIterator()
        guard let status = lines.next() else { return nil }
        // Both shapes are seen: a response to our search, and a NOTIFY a device sends
        // unprompted. Both carry a LOCATION and both are worth keeping.
        let head = status.uppercased()
        guard head.hasPrefix("HTTP/1.1 200") || head.hasPrefix("NOTIFY") || head.hasPrefix("HTTP/1.0 200")
        else { return nil }

        var result = SSDPResponse()
        while let line = lines.next() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[line.startIndex..<colon]).trimmed.lowercased()
            let value = String(line[line.index(after: colon)...]).trimmed
            guard !value.isEmpty else { continue }
            switch key {
            case "location": if result.location == nil { result.location = value }
            case "server": if result.server == nil { result.server = value }
            default: break
            }
        }
        guard result.location != nil || result.server != nil else { return nil }
        return result
    }
}

/// A UPnP device description document.
struct UPnPDescription: Sendable, Hashable {
    /// `<friendlyName>` — the name the owner set, or the manufacturer's default.
    var friendlyName: String?
    /// `<modelName>` — what the thing is.
    var modelName: String?

    /// Extracts the two fields this system cares about.
    ///
    /// A substring scan rather than an XML parser, and deliberately. These documents
    /// are a fixed, shallow schema; `XMLParser` is delegate-based, needs a class and a
    /// bridge back to async, and would buy correctness on constructs — namespaces,
    /// CDATA in a name, entity declarations — that a device description does not use.
    ///
    /// The FIRST occurrence of each element is taken, which is the one detail that
    /// matters: a document may nest `<deviceList>` with embedded devices inside it, and
    /// the root device's name comes first. Taking the last would name a television
    /// after one of its internal media services.
    static func parse(_ xml: String) -> UPnPDescription {
        UPnPDescription(
            friendlyName: element("friendlyName", in: xml),
            modelName: element("modelName", in: xml)
        )
    }

    /// The most a description document may be, in bytes.
    ///
    /// A UPnP device description is a page of XML — one to four kilobytes in practice,
    /// and the largest this project has seen is under twenty. 256 KB is generous by an
    /// order of magnitude and still bounded, which is the only property that matters:
    /// the byte count on the other end of this transfer is chosen by whoever sent the
    /// datagram, not by us.
    static let maximumDescriptionBytes = 256 * 1024

    /// Whether a `LOCATION` may be fetched, and why not when it may not.
    enum LocationVerdict: Sendable, Hashable {
        /// Safe to fetch.
        case permitted(URL)
        /// Refused, with a reason fit for a user to read.
        case refused(String)
    }

    /// Decides whether a `LOCATION` advertised by a responder may be fetched.
    ///
    /// ── THIS IS A SERVER-SIDE REQUEST FORGERY CONTROL ────────────────────────────
    ///
    /// `LOCATION` is an attacker-controlled string. It arrives in an unauthenticated
    /// UDP datagram from anything on the segment, and the parser deliberately accepts
    /// unsolicited `NOTIFY` as well as replies to our own search — so nothing has to
    /// wait to be asked. Handing that string to `URLSession` unvalidated, as an earlier
    /// version did, turns this scanner into a confused deputy that will issue an
    /// authenticated-from-this-host GET at anything the sender names:
    /// `http://127.0.0.1:PORT/` to reach services bound to loopback, a router's admin
    /// endpoint that trusts requests from the LAN, or `file:///Users/…/.ssh/id_rsa`.
    ///
    /// It also quietly undoes the routing discipline the rest of this file is built on.
    /// The search socket cannot leak out of a VPN because it is pinned to the interface
    /// and sets `IP_MULTICAST_IF` — but `URLSession` consults the system routing table
    /// and knows nothing about that, so a `LOCATION` naming a tunnel-side address sends
    /// the fetch straight down the tunnel the search was so careful to avoid.
    ///
    /// Three rules, and a device that breaks any of them is simply not described:
    ///
    ///   1. **`http` only.** Not `file`, not `ftp`, not `data`. Not `https` either: a
    ///      UPnP description is plaintext HTTP by specification, and every scheme this
    ///      list does not name is one whose failure modes have not been thought about.
    ///   2. **A numeric IPv4 host.** A NAME IS NOT RESOLVED — deliberately. Resolving
    ///      would mean a blocking `getaddrinfo` on the cooperative pool, which is the
    ///      exact hazard `PlatformSeam` rejects, and a name is also the easiest way to
    ///      point rule 3 somewhere else. In practice `LOCATION` always carries a
    ///      literal, because UPnP cannot assume a name server exists.
    ///   3. **That address must be the source of the datagram.** The strongest of the
    ///      three, and the one that makes the others hard to work around: a device may
    ///      describe ITSELF and nothing else. Loopback, the gateway, a tunnel-side
    ///      address and any other host on the subnet are all refused by the same rule,
    ///      because none of them sent the datagram.
    static func permittedURL(_ location: String, from source: IPv4Address) -> LocationVerdict {
        guard let url = URL(string: location) else {
            return .refused("its LOCATION was not a URL")
        }
        guard url.scheme?.lowercased() == "http" else {
            return .refused("its LOCATION used the \(url.scheme ?? "missing") scheme rather than http")
        }
        // Credentials in a description URL have no legitimate use and are a way to make
        // a host component read as something it is not.
        guard url.user == nil, url.password == nil else {
            return .refused("its LOCATION carried credentials")
        }
        guard let host = url.host, !host.isEmpty else {
            return .refused("its LOCATION named no host")
        }
        guard let address = IPv4Address(host) else {
            return .refused("its LOCATION named the host '\(host)' rather than an address")
        }
        guard address == source else {
            return .refused("its LOCATION pointed at \(address) rather than at itself")
        }
        return .permitted(url)
    }

    /// Reads at most `cap` bytes, refusing anything longer.
    ///
    /// Enforced DURING the transfer, not after. The distinction is the whole point: a
    /// check on the finished `Data` has already let the bytes into memory, and with
    /// eight fetches in flight against a hostile responder on a gigabit link that is
    /// more than a gigabyte resident before anything looks at a length. Iterating and
    /// stopping means the connection is dropped the moment the budget is exceeded.
    ///
    /// Generic over the sequence so it can be tested against a synthetic one. There is
    /// no other way to exercise the refusal path without standing up a hostile server.
    static func collect<Bytes: AsyncSequence>(
        upTo cap: Int, from bytes: Bytes
    ) async throws -> [UInt8]? where Bytes.Element == UInt8 {
        var buffer: [UInt8] = []
        buffer.reserveCapacity(min(cap, 16 * 1024))
        for try await byte in bytes {
            buffer.append(byte)
            // Exactly `cap` is allowed; one more is not, and returning here ends the
            // iteration, which tears the transfer down.
            if buffer.count > cap { return nil }
        }
        return buffer
    }

    /// Fetches and parses a description document.
    ///
    /// `URLSession` rather than a hand-rolled client: chunked encoding, header folding
    /// and connection handling are all things an embedded UPnP server does and a
    /// fifty-line client gets wrong. The request timeout comes from the remaining
    /// budget, so a device that accepts a connection and then says nothing cannot hold
    /// the stage open.
    ///
    /// Redirects are REFUSED rather than followed. `permittedURL` proves the first
    /// request goes to the device that advertised itself, and a 302 the device chooses
    /// would defeat that proof entirely — it is the same forgery one hop later, and
    /// `URLSession` follows redirects by default.
    static func fetch(_ url: URL, within deadline: Deadline) async -> UPnPDescription? {
        let remaining = deadline.remaining
        guard remaining > .milliseconds(50) else { return nil }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = remaining.milliseconds / 1000
        configuration.timeoutIntervalForResource = remaining.milliseconds / 1000
        // A device that is not answering must fail now rather than be queued until it
        // does. The default would wait for connectivity and outlive the scan.
        configuration.waitsForConnectivity = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        guard let (bytes, response) = try? await session.bytes(
            from: url, delegate: RefuseRedirects.shared
        ) else { return nil }
        if let http = response as? HTTPURLResponse, http.statusCode != 200 { return nil }
        // A declared length over the cap is refused before a byte is read. Cheap, and
        // an honest server saves us the transfer; a lying one is caught by `collect`.
        if response.expectedContentLength > Int64(maximumDescriptionBytes) { return nil }

        // `try?` flattens, so a nil here is either a transfer error or the cap being
        // exceeded. Both mean the same thing to the caller: no description.
        guard let data = try? await collect(upTo: maximumDescriptionBytes, from: bytes)
        else { return nil }
        // Description documents declare UTF-8 and occasionally lie. Lossy decoding
        // keeps a name with one bad byte in it rather than discarding the device.
        let parsed = parse(String(decoding: data, as: UTF8.self))
        guard parsed.friendlyName != nil || parsed.modelName != nil else { return nil }
        return parsed
    }

    /// The text content of the first `<name>` element, with entities decoded.
    static func element(_ name: String, in xml: String) -> String? {
        guard let openRange = xml.range(of: "<\(name)>"),
              let closeRange = xml.range(of: "</\(name)>", range: openRange.upperBound..<xml.endIndex)
        else { return nil }
        let inner = String(xml[openRange.upperBound..<closeRange.lowerBound])
        let decoded = decodeEntities(inner).trimmed
        return decoded.isEmpty ? nil : decoded
    }

    /// Decodes the five predefined XML entities.
    ///
    /// `&amp;` last is not a stylistic choice: decoding it first would turn `&amp;lt;`
    /// — the correct escaping of the literal text "&lt;" — into `<`, which is the
    /// classic double-unescaping bug. Every other entity is expanded before the
    /// ampersand that could have produced it.
    static func decodeEntities(_ text: String) -> String {
        var result = text
        for (entity, character) in [("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&apos;", "'")] {
            result = result.replacingOccurrences(of: entity, with: character)
        }
        return result.replacingOccurrences(of: "&amp;", with: "&")
    }
}

/// Refuses every HTTP redirect.
///
/// `permittedURL` proves the first request goes to the device that advertised itself.
/// Following a redirect the device chose would hand that proof straight back — the
/// second request goes wherever it says, which is the forgery the validation exists to
/// prevent, one hop later. `URLSession` follows redirects unless told otherwise, so
/// this has to be said out loud.
///
/// Stateless and shared: it holds nothing and answers every task identically.
final class RefuseRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    /// The shared instance.
    static let shared = RefuseRedirects()

    /// Declines the redirect by handing back no request.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// The M-SEARCH socket's constants and its one extra rule, over the shared `UDPProbe`.
enum SSDPSocket {
    /// The multicast group and port every UPnP device listens on.
    static let group = IPv4Address(raw: 0xEF_FF_FF_FA)   // 239.255.255.250
    static let port: UInt16 = 1900

    /// Opens the search socket: a `UDPProbe` bound to the interface, plus the multicast
    /// options a search needs.
    static func open(on interface: NetworkInterface) throws(PlatformError) -> UDPProbe {
        try UDPProbe(
            interface: interface,
            queue: DispatchQueue(label: "com.jctec.zhen.ssdp", qos: .userInitiated)
        ) { descriptor in
            var reuse: Int32 = 1
            // SAFETY: setsockopt reads one Int32 from storage we own and sized.
            _ = unsafe setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR,
                                  &reuse, socklen_t(MemoryLayout<Int32>.size))
            // Name the interface for multicast explicitly. Binding the address alone is
            // NOT enough: the multicast egress interface is a separate socket option,
            // and without it the kernel consults its multicast route — which on a
            // machine with a VPN up names the tunnel.
            var multicastInterface = in_addr(s_addr: interface.address.raw.bigEndian)
            // SAFETY: setsockopt reads one in_addr from storage we own and sized.
            guard unsafe setsockopt(descriptor, IPPROTO_IP, IP_MULTICAST_IF,
                                    &multicastInterface, socklen_t(MemoryLayout<in_addr>.size)) == 0
            else { return "setsockopt(IP_MULTICAST_IF)" }
            // Two hops. The UPnP specification's default, and correct: SSDP describes a
            // link, and a search that crosses routers finds devices the scan is not about.
            var ttl: UInt8 = 2
            _ = unsafe setsockopt(descriptor, IPPROTO_IP, IP_MULTICAST_TTL,
                                  &ttl, socklen_t(MemoryLayout<UInt8>.size))
            // Do not hear our own search echoed back.
            var loop: UInt8 = 0
            _ = unsafe setsockopt(descriptor, IPPROTO_IP, IP_MULTICAST_LOOP,
                                  &loop, socklen_t(MemoryLayout<UInt8>.size))
            return nil
        }
    }

    /// The M-SEARCH request text.
    ///
    /// `MX` is the number of seconds a device may wait before answering; they spread
    /// their replies uniformly across it so a hundred devices do not answer in the same
    /// millisecond. Deriving it from the listen budget rather than pinning it means a
    /// short scan asks the network to hurry instead of simply hearing less of it.
    ///
    /// `ssdp:all` rather than `upnp:rootdevice` because it is a strict superset — a
    /// device answers once per service it hosts, which is redundant on the wire and
    /// deduplicated on arrival, and it catches devices that answer only their own
    /// service type.
    static func searchRequest(mx: Int) -> [UInt8] {
        let text = """
            M-SEARCH * HTTP/1.1\r
            HOST: 239.255.255.250:1900\r
            MAN: "ssdp:discover"\r
            MX: \(max(1, min(5, mx)))\r
            ST: ssdp:all\r
            USER-AGENT: Darwin/26 UPnP/1.1 zhen/0.3\r
            \r

            """
        return Array(text.utf8)
    }
}
#endif
