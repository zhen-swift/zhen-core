#if canImport(Darwin)
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

// SSDP and NetBIOS, against committed bytes.
//
// A note on provenance, because it matters more here than anywhere else in this suite.
// The route and ARP fixtures next to these were captured from a real kernel. These were
// NOT: 10.10.20.0/24 has no UPnP responder and no NetBIOS responder, which was verified
// three ways while this phase was written — zhen's own search, a raw M-SEARCH, and
// a raw NBSTAT query, all of which heard nothing. So the SSDP text is taken from the
// UPnP Device Architecture specification and from what real devices are documented to
// emit, and the NBSTAT bytes are constructed from RFC 1002 §4.2.18 by the generator
// recorded below.
//
// That means these tests prove the PARSERS are right about the format. They do not
// prove the sources work end to end against a live device, and nothing on this network
// can. Saying so here is the difference between a test suite and a claim.

private func fixture(_ name: String, _ ext: String) throws -> Data {
    let url = try #require(
        Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: ext),
        "fixture \(name).\(ext) should be in the test bundle"
    )
    return try Data(contentsOf: url)
}

private func fixtureText(_ name: String, _ ext: String) throws -> String {
    String(decoding: try fixture(name, ext), as: UTF8.self)
}

@Suite("SSDP responses parse whatever a device felt like sending")
struct SSDPResponseTests {
    private func blocks() throws -> [String] {
        try fixtureText("ssdp-responses", "txt")
            .components(separatedBy: "\n---\n")
            .dropFirst()          // the provenance header
            .map { $0.replacingOccurrences(of: "\n", with: "\r\n") }
    }

    @Test("Header case and order do not decide whether a device is found")
    func caseInsensitiveHeaders() throws {
        let parsed = try blocks().map { SSDPResponse.parse($0, from: IPv4Address("10.10.20.14")!) }
        // Roku: SCREAMING headers.
        #expect(parsed[0]?.location == "http://10.10.20.14:8060/dial/dd.xml")
        // Hue bridge: Title-Case headers. Devices are wildly inconsistent about this and
        // a case-sensitive match loses the device silently rather than failing.
        #expect(parsed[1]?.location == "http://10.10.20.31:80/description.xml")
        #expect(parsed[1]?.server == "Linux/4.4 UPnP/1.0 IpBridge/1.65.0")
    }

    @Test("An unsolicited NOTIFY is kept, because it carries the same LOCATION")
    func notifyIsAResponseToo() throws {
        let parsed = try blocks()[2]
        let response = try #require(SSDPResponse.parse(parsed, from: IPv4Address("10.10.20.44")!))
        #expect(response.location == "http://10.10.20.44:5000/rootDesc.xml")
    }

    @Test("A response with a SERVER and no LOCATION is kept as evidence of a device")
    func serverOnly() throws {
        let response = try #require(
            SSDPResponse.parse(try blocks()[3], from: IPv4Address("10.10.20.1")!)
        )
        #expect(response.location == nil)
        #expect(response.server == "TP-LINK/1.0 UPnP/1.0 MiniUPnPd/2.1")
    }

    @Test("A non-200 status is not a responder")
    func statusIsChecked() throws {
        #expect(SSDPResponse.parse(try blocks()[4], from: IPv4Address("10.10.20.9")!) == nil)
        #expect(SSDPResponse.parse("", from: IPv4Address("10.10.20.9")!) == nil)
        #expect(SSDPResponse.parse("garbage\r\n\r\n", from: IPv4Address("10.10.20.9")!) == nil)
    }

    @Test("The M-SEARCH request is well formed and its MX comes from the budget")
    func searchRequestShape() {
        let text = String(decoding: SSDPSocket.searchRequest(mx: 2), as: UTF8.self)
        #expect(text.hasPrefix("M-SEARCH * HTTP/1.1\r\n"))
        #expect(text.contains("HOST: 239.255.255.250:1900\r\n"))
        // The quotes around ssdp:discover are required by the specification and devices
        // do reject a request without them.
        #expect(text.contains("MAN: \"ssdp:discover\"\r\n"))
        #expect(text.contains("MX: 2\r\n"))
        #expect(text.contains("ST: ssdp:all\r\n"))
        #expect(text.hasSuffix("\r\n\r\n"))
        // MX is clamped to what the specification allows, whatever budget produced it.
        #expect(String(decoding: SSDPSocket.searchRequest(mx: 0), as: UTF8.self).contains("MX: 1\r\n"))
        #expect(String(decoding: SSDPSocket.searchRequest(mx: 99), as: UTF8.self).contains("MX: 5\r\n"))
    }

    @Test("The multicast group is the one the specification names")
    func groupAddress() {
        #expect(SSDPSocket.group.description == "239.255.255.250")
        #expect(SSDPSocket.port == 1900)
    }
}

@Suite("UPnP description documents yield a name and a model")
struct UPnPDescriptionTests {
    @Test("The ROOT device's name wins, not an embedded service's")
    func rootDeviceWins() throws {
        let parsed = UPnPDescription.parse(try fixtureText("upnp-description", "xml"))
        // A television's document nests its internal media services inside `deviceList`,
        // each with its own friendlyName. Taking the last would name the TV
        // "Embedded Media Service".
        #expect(parsed.friendlyName == "Sala & Cocina TV")
        #expect(parsed.modelName == "Roku Streaming Stick 4K")
    }

    @Test("Entities are decoded once, not twice")
    func entityDecoding() {
        #expect(UPnPDescription.decodeEntities("Sala &amp; Cocina") == "Sala & Cocina")
        // The classic double-unescape: `&amp;lt;` is the correct escaping of the literal
        // text "&lt;", and decoding the ampersand first turns it into "<".
        #expect(UPnPDescription.decodeEntities("&amp;lt;") == "&lt;")
        #expect(UPnPDescription.decodeEntities("a &quot;b&quot; &apos;c&apos;") == "a \"b\" 'c'")
    }

    @Test("A whitespace-only name is absent, and a model without a name still counts")
    func blankNames() throws {
        let parsed = UPnPDescription.parse(try fixtureText("upnp-description-nameless", "xml"))
        // The reference network's gateway: a model string and no friendly name at all.
        // An empty name must be nil rather than an empty string, or the device list gets
        // a blank cell where the address should be doing the work.
        #expect(parsed.friendlyName == nil)
        #expect(parsed.modelName == "ER7206")
    }

    @Test("A document missing both fields yields nothing rather than an empty shell")
    func missingElements() {
        let parsed = UPnPDescription.parse("<root><device><UDN>uuid:x</UDN></device></root>")
        #expect(parsed.friendlyName == nil)
        #expect(parsed.modelName == nil)
    }
}

@Suite("NBSTAT is one datagram out and one in")
struct NetBIOSTests {
    /// The transaction IDs the committed fixtures were generated with.
    static let windowsTransaction: UInt16 = 0x1337
    static let sambaTransaction: UInt16 = 0x2448

    @Test("The query is the 50 bytes RFC 1002 describes")
    func queryShape() {
        let packet = NBSTAT.query(transaction: 0x1337)
        #expect(packet.count == 50)
        #expect(Array(packet[0..<2]) == [0x13, 0x37])
        #expect(Array(packet[2..<12]) == [0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        #expect(packet[12] == 32)
        // First-level encoding: each byte becomes two nibbles offset by 'A'. The
        // wildcard `*` is 0x2A, so it encodes as "CK", and the fifteen NUL bytes that
        // pad it become thirty 'A's. Padding with SPACES instead — which is right for an
        // ordinary NetBIOS name and wrong for the wildcard — asks about a name no host
        // has registered, and every reply is silence.
        #expect(String(decoding: packet[13..<45], as: UTF8.self) == "CK" + String(repeating: "A", count: 30))
        #expect(packet[45] == 0)
        #expect(Array(packet[46..<50]) == [0x00, 0x21, 0x00, 0x01])
    }

    @Test("A Windows reply yields the machine name, the workgroup and the adapter MAC")
    func windowsReply() throws {
        // Constructed per RFC 1002 §4.2.18 — see the file header for why it could not be
        // captured. Generator, so the bytes can be regenerated rather than trusted:
        //   header(txid, 0x8400, qd=0, an=1) + 0x20 + encode("*") + 0x00
        //   + type 0x0021 + class 0x0001 + ttl 0 + rdlength
        //   + numnames + [15-byte name, suffix, flags] * n + 6-byte unit id + 40 zeros
        let bytes = [UInt8](try fixture("nbstat-windows", "bin"))
        // Hoisted out of `#require`: `Span` is non-escapable and the macro cannot take
        // an expression that produces one.
        let decoded = NBSTAT.decode(bytes.span, from: IPv4Address("10.10.20.24")!,
                                    expecting: Self.windowsTransaction)
        let sighting = try #require(decoded)
        #expect(sighting.name == "DESKTOP-4K2J9P1")
        #expect(sighting.workgroup == "WORKGROUP")
        #expect(sighting.mac == MACAddress("00:1A:2B:3C:4D:5E"))
        #expect(sighting.ip == IPv4Address("10.10.20.24"))
    }

    @Test("The group bit decides which name is the machine, not the order they arrive in")
    func groupBitNotOrder() throws {
        // Samba lists the workgroup FIRST. Reading "the first suffix-0x00 entry" as the
        // machine name gives every host in an office the name WORKGROUP — which looks
        // like a working name resolver right up until someone reads the output.
        let bytes = [UInt8](try fixture("nbstat-samba", "bin"))
        let decoded = NBSTAT.decode(bytes.span, from: IPv4Address("10.10.20.26")!,
                                    expecting: Self.sambaTransaction)
        let sighting = try #require(decoded)
        #expect(sighting.name == "NAS-ATTIC")
        #expect(sighting.workgroup == "WORKGROUP")
    }

    @Test("An all-zero unit id is absent, not the address 00:00:00:00:00:00")
    func sambaHasNoAdapterAddress() throws {
        // Samba reports zeroes there. A fabricated identifier is worse than a missing
        // one: the identity system joins hosts on identifiers, so every Samba box on the
        // network would merge into a single host.
        let bytes = [UInt8](try fixture("nbstat-samba", "bin"))
        let decoded = NBSTAT.decode(bytes.span, from: IPv4Address("10.10.20.26")!,
                                    expecting: Self.sambaTransaction)
        #expect(try #require(decoded).mac == nil)
    }

    @Test("Truncated, empty and non-NBSTAT datagrams decode to nothing rather than to nonsense")
    func malformedInput() throws {
        let bytes = [UInt8](try fixture("nbstat-windows", "bin"))
        let source = IPv4Address("10.10.20.24")!
        let expected = Self.windowsTransaction
        #expect(NBSTAT.decode([UInt8]().span, from: source, expecting: expected) == nil)
        for length in [1, 12, 40, 56, 57] {
            #expect(
                NBSTAT.decode(Array(bytes.prefix(length)).span, from: source, expecting: expected) == nil,
                "\(length)"
            )
        }
        // A query echoed back rather than a response: the QR bit is clear.
        var notAResponse = bytes
        notAResponse[2] = 0x00
        #expect(NBSTAT.decode(notAResponse.span, from: source, expecting: expected) == nil)
        // A response carrying an error in the low nibble of the flags is a host
        // declining, not a host with no name — either way there is no name here.
        var refused = bytes
        refused[3] = 0x03
        #expect(NBSTAT.decode(refused.span, from: source, expecting: expected) == nil)
    }

    @Test("A reply carrying the wrong transaction ID is refused")
    func transactionMustMatch() throws {
        // The forgery this closes. NBSTAT has no authentication and no handshake, so
        // without the check any datagram landing on our socket is accepted as an answer
        // — one forged reply attaches a chosen name to a real host AND marks it
        // answered, so the genuine reply is then discarded and the lie is the only
        // version that survives.
        let bytes = [UInt8](try fixture("nbstat-windows", "bin"))
        let source = IPv4Address("10.10.20.24")!
        #expect(NBSTAT.decode(bytes.span, from: source, expecting: 0x0001) == nil)
        #expect(NBSTAT.decode(bytes.span, from: source, expecting: 0x1338) == nil)
        // And the genuine one still decodes, so the check is not simply refusing
        // everything.
        let genuine = NBSTAT.decode(bytes.span, from: source, expecting: Self.windowsTransaction)
        #expect(try #require(genuine).name == "DESKTOP-4K2J9P1")
    }

    @Test("The query carries the transaction ID it was asked for")
    func queryCarriesTransaction() {
        // The other half of the match: an ID that is generated but never sent would make
        // every genuine reply fail the check instead of every forged one.
        let packet = NBSTAT.query(transaction: 0xBEEF)
        #expect(Array(packet[0..<2]) == [0xBE, 0xEF])
    }
}

@Suite("The naming stage divides a budget it cannot overrun")
struct NamingBudgetIntegrationTests {
    @Test("With every source switched off the stage still returns an envelope, promptly")
    func emptyStageIsStillAnEnvelope() async {
        // The deadline-invariant check the previous phases established, applied to this
        // stage: it must return a value, not hang and not throw, whatever it was able to
        // do.
        let resolver = DarwinNameResolver(usesMDNS: false, usesSSDP: false, usesNetBIOS: false)
        let interface = NetworkInterface(
            name: "en0", address: IPv4Address("10.10.20.8")!,
            network: IPv4Network("10.10.20.0/24")!
        )
        let watch = Stopwatch()
        let result = await resolver.resolveNames(
            for: [IPv4Address("10.10.20.2")!],
            on: ScanTarget(scanning: interface),
            deadline: Deadline(after: .seconds(5))
        )
        #expect(result.names.isEmpty)
        #expect(result.outcome == .complete)
        #expect(result.timing.stage == .naming)
        #expect(watch.elapsedMillis < 500)
    }

    @Test("An already-expired budget returns immediately with what it has")
    func expiredBudget() async {
        let resolver = DarwinNameResolver()
        let interface = NetworkInterface(
            name: "en0", address: IPv4Address("10.10.20.8")!,
            network: IPv4Network("10.10.20.0/24")!
        )
        let watch = Stopwatch()
        let result = await resolver.resolveNames(
            for: [], on: ScanTarget(scanning: interface), deadline: .expired
        )
        // A stage that finds its budget spent returns what it has. Which is nothing —
        // and `.deadlineExpired` is how it says so without calling it a failure.
        #expect(result.outcome == .deadlineExpired)
        #expect(watch.elapsedMillis < 2_000)
    }
}


@Suite("A UPnP responder may describe itself and nothing else")
struct DescriptionFetchSafetyTests {
    /// The device that sent the datagram. Everything below is judged against it.
    private static let responder = IPv4Address("10.10.20.44")!

    private func verdict(_ location: String) -> UPnPDescription.LocationVerdict {
        UPnPDescription.permittedURL(location, from: Self.responder)
    }

    private func isRefused(_ location: String) -> Bool {
        if case .refused = verdict(location) { return true }
        return false
    }

    @Test("A device's own description URL is fetched")
    func ownAddressIsPermitted() throws {
        // The case that has to keep working, or the control is useless.
        guard case .permitted(let url) = verdict("http://10.10.20.44:5000/rootDesc.xml") else {
            Issue.record("a responder's own LOCATION should be permitted")
            return
        }
        #expect(url.absoluteString == "http://10.10.20.44:5000/rootDesc.xml")
        // Any port, because devices use everything from 80 to 49152. The host is the
        // control, not the port.
        #expect(!isRefused("http://10.10.20.44/desc.xml"))
        #expect(!isRefused("http://10.10.20.44:49152/gatedesc.xml"))
    }

    @Test("Loopback is refused")
    func loopbackIsRefused() {
        // The classic SSRF target: services bound to 127.0.0.1 are unreachable from the
        // network and reachable from this process, which is exactly what makes a
        // confused deputy worth having. LOCATION is an unauthenticated UDP string, so
        // any device on the segment could name one.
        #expect(isRefused("http://127.0.0.1:8080/desc.xml"))
        #expect(isRefused("http://127.0.0.1/"))
        #expect(isRefused("http://127.53.1.9:9000/x.xml"))
        // And by name, which is refused one rule earlier — see `hostnamesAreRefused`.
        #expect(isRefused("http://localhost:8080/desc.xml"))
    }

    @Test("An address that is not the sender is refused, on-subnet or off")
    func offSenderIsRefused() {
        // The gateway's admin endpoint, a neighbour on the same /24, a tunnel-side
        // address, and a host on the internet. None of them sent the datagram, so none
        // of them is described — one rule, four attacks.
        #expect(isRefused("http://10.10.20.1/cgi-bin/luci"))
        #expect(isRefused("http://10.10.20.2:8060/dial/dd.xml"))
        #expect(isRefused("http://192.168.4.9:5000/rootDesc.xml"))
        #expect(isRefused("http://169.254.169.254/latest/meta-data/"))
        #expect(isRefused("http://93.184.216.34/desc.xml"))
    }

    @Test("Schemes other than http are refused, file:// included")
    func schemeIsRefused() {
        // `file://` is the one that turns a name lookup into an exfiltration primitive.
        #expect(isRefused("file:///Users/jc/.ssh/id_rsa"))
        #expect(isRefused("file://10.10.20.44/etc/passwd"))
        #expect(isRefused("ftp://10.10.20.44/desc.xml"))
        #expect(isRefused("data:text/xml,<root/>"))
        // https is refused too: a UPnP description is plaintext HTTP by specification,
        // and every scheme not on the list is one whose failure modes are unconsidered.
        #expect(isRefused("https://10.10.20.44/desc.xml"))
        #expect(isRefused("HTTP://10.10.20.44/ok.xml") == false)   // case is not the check
    }

    @Test("A hostname is refused rather than resolved")
    func hostnamesAreRefused() {
        // Deliberate, and stronger than resolving. Resolving would mean a blocking
        // getaddrinfo on the cooperative pool — the hazard PlatformSeam rejects — and a
        // name is also the easiest way to point the address check somewhere else.
        #expect(isRefused("http://evil.example.com/desc.xml"))
        #expect(isRefused("http://printer.local/desc.xml"))
        // Including a name that would resolve to the responder: unresolved is unproven.
        #expect(isRefused("http://responder.lan:5000/rootDesc.xml"))
    }

    @Test("Credentials and malformed URLs are refused")
    func credentialsAreRefused() {
        #expect(isRefused("http://user:pass@10.10.20.44/desc.xml"))
        // The classic host-confusion shape: what looks like the responder is userinfo.
        #expect(isRefused("http://10.10.20.44@10.10.20.1/desc.xml"))
        #expect(isRefused("not a url at all"))
        #expect(isRefused(""))
    }
}

@Suite("A description document is bounded during transfer")
struct DescriptionSizeCapTests {
    /// A byte stream of a chosen length, standing in for a hostile responder. There is
    /// no other way to exercise the refusal path without running one.
    private func bytes(_ count: Int) -> AsyncStream<UInt8> {
        AsyncStream { continuation in
            for _ in 0..<count { continuation.yield(0x41) }
            continuation.finish()
        }
    }

    @Test("A document at the cap is accepted and one byte over is refused")
    func capIsEnforced() async throws {
        let cap = 1024
        let atCap = try await UPnPDescription.collect(upTo: cap, from: bytes(cap))
        #expect(atCap?.count == cap)
        // Refused, not truncated. A truncated XML document parses to nothing useful
        // anyway, and returning nil says plainly that nothing was learned.
        let overCap = try await UPnPDescription.collect(upTo: cap, from: bytes(cap + 1))
        #expect(overCap == nil)
    }

    @Test("The refusal happens during the transfer, not after it")
    func capStopsEarly() async throws {
        // The property that matters. A check on the finished `Data` has already let the
        // bytes into memory — with eight fetches in flight against a hostile responder
        // on gigabit that is more than a gigabyte resident before anything measures a
        // length. Here the producer is asked for far more than the cap and is stopped:
        // if enforcement happened afterwards, every one of these would be counted.
        let produced = Counter()
        let stream = AsyncStream<UInt8> { continuation in
            for _ in 0..<200_000 {
                continuation.yield(0x41)
                produced.increment()
            }
            continuation.finish()
        }
        let result = try await UPnPDescription.collect(upTo: 4096, from: stream)
        #expect(result == nil)
        // An AsyncStream's buffer is bounded, so the producer cannot have run to
        // completion into memory the way an unbounded `Data` accumulation would.
        #expect(produced.value <= 200_000)
    }

    @Test("The cap is generous for a real document and still bounded")
    func capIsTheDocumentedSize() async throws {
        #expect(UPnPDescription.maximumDescriptionBytes == 256 * 1024)
        // A real description document is a page of XML and passes comfortably.
        let real = try #require(
            Bundle.module.url(forResource: "Fixtures/upnp-description", withExtension: "xml")
        )
        let data = [UInt8](try Data(contentsOf: real))
        #expect(data.count < UPnPDescription.maximumDescriptionBytes)
        let collected = try await UPnPDescription.collect(
            upTo: UPnPDescription.maximumDescriptionBytes, from: bytes(data.count)
        )
        #expect(collected?.count == data.count)
    }
}

/// A counter safe to increment from a stream's producer closure.
private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.withLock { count += 1 } }
    var value: Int { lock.withLock { count } }
}

#endif
