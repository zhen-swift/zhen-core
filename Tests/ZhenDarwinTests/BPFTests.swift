// BPFTests.swift — the two parts of the privileged engine that can be tested without
// root, which is where its bugs live.
//
// The live path needs a free `/dev/bpf*` node and a segment with something on it, so it
// is one test at the bottom of this file, gated on being root and saying so when it is
// skipped. Everything above it is the arithmetic:
//
//   * **Frame construction, byte for byte.** An ARP request with a field in the wrong
//     place is not answered, and a sweep that is not answered looks exactly like a
//     segment with nothing on it. The expected bytes below are written out from RFC 826
//     and the Ethernet II layout rather than produced by calling the builder, because a
//     test that asks the builder what it built checks nothing.
//
//   * **The record walk.** One `read` returns many packets and getting the step between
//     them wrong yields plausible garbage rather than an error — hardware addresses
//     assembled out of the middle of the previous frame, from addresses that do not
//     exist.
//
// ── Why the buffers here are constructed rather than captured ───────────────────
//
// Every other fixture in this target is real bytes off a real kernel, and that is the
// right default: `route-dump.bin` exists because the alignment hazard in the routing
// parser only shows up on genuinely packed, genuinely variable-length input.
//
// A BPF buffer is different in the one way that matters. The cases the walk has to
// survive — a read that ends in the middle of a record, a tail too short to hold a
// header, a `bh_hdrlen` that is not the struct's size — are precisely the cases a
// healthy kernel never produces, so a capture would contain none of them however long
// it ran. They have to be built on purpose or they are not tested at all.
//
// What is NOT invented is the geometry. `headerLayoutMatchesTheSDK` pins the offsets
// these buffers are written at against `offsetof` on the SDK being compiled for, so the
// builder below and the parser under test cannot drift together into agreeing about a
// layout the kernel does not use.
#if canImport(Darwin)

import CBPFShim
import Darwin
import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

// MARK: - Fixtures

/// Builds BPF read buffers by hand, at literal offsets.
///
/// The offsets are spelled out rather than taken from `CBPFShim`, which is the whole
/// point: the parser reads what the SDK says and this writes what this file says, so a
/// disagreement between them is a failure rather than a shared mistake.
enum BPFFixture {
    /// What the kernel writes into `bh_hdrlen`, which is **not** `sizeof(struct
    /// bpf_hdr)`. The struct pads to 20; its fields end at 18; macOS writes 18. The
    /// fixture emits 18 because emitting 20 is what let a walk that required the struct
    /// size pass every test here and reject every real record.
    static let kernelHeaderLength = 18
    static let structSize = 20
    static let capturedOffset = 8
    static let wireOffset = 12
    static let headerLengthOffset = 16

    /// Rounds up to the four-byte boundary every record starts on.
    static func wordAlign(_ value: Int) -> Int { (value + 3) & ~3 }

    /// One record: a header, its packet, and the padding to the next boundary.
    ///
    /// - Parameters:
    ///   - packet: the captured bytes.
    ///   - wireLength: what `bh_datalen` claims, defaulting to the captured length.
    ///     A larger value is the snap length having truncated the frame.
    ///   - headerLength: what `bh_hdrlen` claims. Defaults to the struct size; a larger
    ///     value is padding the kernel is entitled to insert and the walk must honour.
    static func record(
        _ packet: [UInt8], wireLength: Int? = nil, headerLength: Int = kernelHeaderLength
    ) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: headerLength)
        write(&bytes, at: capturedOffset, UInt32(packet.count))
        write(&bytes, at: wireOffset, UInt32(wireLength ?? packet.count))
        bytes[headerLengthOffset] = UInt8(headerLength & 0xFF)
        bytes[headerLengthOffset + 1] = UInt8((headerLength >> 8) & 0xFF)
        bytes.append(contentsOf: packet)
        bytes.append(contentsOf: [UInt8](
            repeating: 0, count: wordAlign(headerLength + packet.count) - headerLength - packet.count
        ))
        return bytes
    }

    /// Native byte order, because these are the kernel's own integers rather than
    /// anything off a wire. Darwin is little-endian on every architecture it ships on.
    private static func write(_ bytes: inout [UInt8], at offset: Int, _ value: UInt32) {
        bytes[offset] = UInt8(truncatingIfNeeded: value)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    /// An ARP reply as it appears on the wire, laid out field by field.
    static func reply(
        from senderIP: IPv4Address, senderMAC: MACAddress,
        to targetIP: IPv4Address, targetMAC: MACAddress
    ) -> [UInt8] {
        var frame: [UInt8] = []
        frame += targetMAC.bytes                       // 0..6   destination
        frame += senderMAC.bytes                       // 6..12  source
        frame += [0x08, 0x06]                          // 12..14 ethertype ARP
        frame += [0x00, 0x01]                          // 14..16 hardware type Ethernet
        frame += [0x08, 0x00]                          // 16..18 protocol type IPv4
        frame += [6, 4]                                // 18,19  address lengths
        frame += [0x00, 0x02]                          // 20..22 operation: reply
        frame += senderMAC.bytes                       // 22..28 sender hardware
        frame += octets(senderIP)                      // 28..32 sender protocol
        frame += targetMAC.bytes                       // 32..38 target hardware
        frame += octets(targetIP)                      // 38..42 target protocol
        return frame
    }

    static func octets(_ address: IPv4Address) -> [UInt8] {
        let o = address.octets
        return [o.0, o.1, o.2, o.3]
    }
}

// MARK: - Frame construction

@Suite("ARP frames are built to the letter")
struct ARPFrameTests {
    static let ourMAC = MACAddress(raw: 0x0A_1B_2C_3D_4E_5F)
    static let ourIP = IPv4Address("10.10.20.42")!
    static let targetIP = IPv4Address("10.10.20.7")!

    @Test("A request matches RFC 826 byte for byte")
    func requestBytes() {
        let frame = ARPFrame.request(
            target: Self.targetIP, senderMAC: Self.ourMAC, senderIP: Self.ourIP
        )

        // Written out here rather than derived, so this is a check and not a mirror.
        let expected: [UInt8] =
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]        // broadcast destination
            + [0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F]      // our hardware address
            + [0x08, 0x06]                              // ethertype ARP
            + [0x00, 0x01]                              // hardware type Ethernet
            + [0x08, 0x00]                              // protocol type IPv4
            + [0x06, 0x04]                              // address lengths
            + [0x00, 0x01]                              // operation: request
            + [0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F]      // sender hardware
            + [10, 10, 20, 42]                          // sender protocol
            + [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]      // target hardware: the question
            + [10, 10, 20, 7]                           // target protocol

        #expect(frame == expected)
        #expect(frame.count == 42)
    }

    @Test("The target hardware address is zero, because that is what makes it a question")
    func targetHardwareIsEmpty() {
        let frame = ARPFrame.request(
            target: Self.targetIP, senderMAC: Self.ourMAC, senderIP: Self.ourIP
        )
        #expect(frame[32..<38].allSatisfy { $0 == 0 })
        // And the destination is broadcast, because nobody knows who holds the address
        // yet — that is the thing being asked.
        #expect(frame[0..<6].allSatisfy { $0 == 0xFF })
    }

    @Test("A reply parses into the fields the sweep matches on")
    func parseReply() throws {
        let theirMAC = MACAddress(raw: 0xAA_BB_CC_DD_EE_01)
        let bytes = BPFFixture.reply(
            from: Self.targetIP, senderMAC: theirMAC,
            to: Self.ourIP, targetMAC: Self.ourMAC
        )
        // Bound before the macro: `#require` captures its argument expression, and a
        // `Span` is non-escapable, so the parse has to land in an ordinary optional
        // first. Every check below does the same for the same reason.
        let parsed = ARPFrame.parse(bytes.span)
        let message = try #require(parsed)
        #expect(message.isReply)
        #expect(message.senderIP == Self.targetIP)
        #expect(message.senderMAC == theirMAC)
        #expect(message.targetIP == Self.ourIP)
        #expect(message.targetMAC == Self.ourMAC)
    }

    @Test("A request we built parses back to the request we meant")
    func roundTrip() throws {
        let frame = ARPFrame.request(
            target: Self.targetIP, senderMAC: Self.ourMAC, senderIP: Self.ourIP
        )
        let parsed = ARPFrame.parse(frame.span)
        let message = try #require(parsed)
        #expect(!message.isReply)
        #expect(message.operation == 1)
        #expect(message.senderMAC == Self.ourMAC)
        #expect(message.senderIP == Self.ourIP)
        #expect(message.targetIP == Self.targetIP)
        #expect(message.targetMAC == MACAddress(raw: 0))
    }

    @Test("Ethernet padding to the 60-byte minimum does not change what the frame says")
    func paddedFrameParsesTheSame() throws {
        // A driver pads a 42-byte ARP frame out to Ethernet's 46-byte payload minimum,
        // so a capture taken below the driver shows 60 bytes. Both are the same frame
        // and a parser that only accepted one of them would read half a network.
        var padded = BPFFixture.reply(
            from: Self.targetIP, senderMAC: MACAddress(raw: 0xAA_BB_CC_DD_EE_02),
            to: Self.ourIP, targetMAC: Self.ourMAC
        )
        padded += [UInt8](repeating: 0, count: 18)
        #expect(padded.count == 60)
        let parsed = ARPFrame.parse(padded.span)
        let message = try #require(parsed)
        #expect(message.senderIP == Self.targetIP)
    }

    @Test("Anything that is not IPv4-over-Ethernet ARP is refused")
    func refusesForeignFrames() {
        var frame = ARPFrame.request(
            target: Self.targetIP, senderMAC: Self.ourMAC, senderIP: Self.ourIP
        )
        // The kernel filter should already have rejected these. It is the second of two
        // checks rather than the only one, because a filter that failed to install must
        // not turn every frame on the segment into a host.
        func refuses(_ bytes: [UInt8]) -> Bool { ARPFrame.parse(bytes.span) == nil }

        var wrongEthertype = frame
        wrongEthertype[12] = 0x08; wrongEthertype[13] = 0x00     // IPv4, not ARP
        #expect(refuses(wrongEthertype))

        var wrongHardware = frame
        wrongHardware[15] = 0x06                                 // hardware type 6
        #expect(refuses(wrongHardware))

        var wrongProtocol = frame
        wrongProtocol[16] = 0x86; wrongProtocol[17] = 0xDD       // IPv6
        #expect(refuses(wrongProtocol))

        var wrongLengths = frame
        wrongLengths[18] = 8                                     // hlen 8
        #expect(refuses(wrongLengths))

        // And a frame too short to hold the payload at all.
        frame.removeLast(3)
        #expect(refuses(frame))
    }
}

// MARK: - The record walk

@Suite("A BPF read is many packets, and the step between them is where it goes wrong")
struct BPFBufferTests {
    static let ourMAC = MACAddress(raw: 0x0A_1B_2C_3D_4E_5F)
    static let ourIP = IPv4Address("10.10.20.42")!

    static func reply(_ host: UInt8) -> [UInt8] {
        BPFFixture.reply(
            from: IPv4Address(raw: 0x0A0A_1400 | UInt32(host)),
            senderMAC: MACAddress(raw: 0xAA_BB_CC_00_00_00 | UInt64(host)),
            to: ourIP, targetMAC: ourMAC
        )
    }

    @Test("The header layout this file writes is the one the SDK says it has")
    func headerLayoutMatchesTheSDK() {
        // The pin. Everything below writes headers at these offsets by hand while the
        // parser reads them through `offsetof`, so an SDK that moved a field fails here
        // — loudly, once — instead of letting the two drift into agreeing about a
        // layout the kernel does not use.
        #expect(Int(ns_bpf_hdr_size()) == BPFFixture.structSize)
        #expect(Int(ns_bpf_hdr_min_length()) == BPFFixture.kernelHeaderLength)
        #expect(Int(ns_bpf_hdr_off_caplen()) == BPFFixture.capturedOffset)
        #expect(Int(ns_bpf_hdr_off_datalen()) == BPFFixture.wireOffset)
        #expect(Int(ns_bpf_hdr_off_hdrlen()) == BPFFixture.headerLengthOffset)
        #expect(Int(ns_bpf_hdr_off_tstamp_sec()) == 0)
        #expect(ns_bpf_alignment() == 4)
        // The one arithmetic operation the walk depends on.
        #expect(ns_bpf_wordalign(62) == 64)
        #expect(ns_bpf_wordalign(64) == 64)
        #expect(ns_bpf_wordalign(65) == 68)
    }

    @Test("bh_hdrlen is 18 and sizeof(struct bpf_hdr) is 20, and the walk must use the first")
    func headerLengthIsNotTheStructSize() throws {
        // The bug this test exists for, and it shipped: the walk required
        // `bh_hdrlen >= sizeof(struct bpf_hdr)`, the kernel writes 18 against a struct
        // that pads to 20, so the guard rejected the first record of every read. The
        // sweep sent 759 ARP requests, nine hosts answered, and it reported an empty
        // segment — which is indistinguishable from a segment that is empty, so nothing
        // failed anywhere. It took a packet capture taken beside a live run to see it.
        //
        // Every fixture in this file emits 18 for the same reason: at 20 they all passed
        // while the real thing found nothing.
        #expect(BPFFixture.kernelHeaderLength < BPFFixture.structSize)
        #expect(BPFBuffer.minimumHeaderLength == BPFFixture.kernelHeaderLength)
        #expect(BPFBuffer.structSize == BPFFixture.structSize)

        let buffer = BPFFixture.record(Self.reply(1), headerLength: 18)
        let records = BPFBuffer.records(in: buffer.span)
        #expect(records.count == 1, "a record with the kernel's own bh_hdrlen must parse")
        let parsed = ARPFrame.parse(buffer.span.extracting(records[0].packet))
        let message = try #require(parsed)
        #expect(message.senderIP == IPv4Address("10.10.20.1")!)
    }

    @Test("Three packets in one read come back as three, at the right extents")
    func walksEveryRecord() throws {
        let packets = [Self.reply(1), Self.reply(2), Self.reply(3)]
        let buffer = packets.flatMap { BPFFixture.record($0) }
        let records = BPFBuffer.records(in: buffer.span)

        #expect(records.count == 3)
        // 20-byte header plus a 42-byte frame is 62, which rounds up to 64 — so the
        // second record does NOT begin at 62. A walk that advanced by 62 would read the
        // third header out of the middle of the second packet.
        #expect(records[0].packet == 18..<60)
        #expect(records[1].packet == 78..<120)
        #expect(records[2].packet == 138..<180)
        let nothingWasTruncated = records.allSatisfy { !$0.isTruncated }
        #expect(nothingWasTruncated)
    }

    @Test("A capture length that is not a multiple of four still lands the next record")
    func alignmentPadding() {
        // 18 + 43 = 61, which pads to 64. This is the case the whole word-align exists
        // for, and the one a naive walk gets wrong by exactly three bytes.
        let odd = [UInt8](repeating: 0xAB, count: 43)
        let buffer = BPFFixture.record(odd) + BPFFixture.record(Self.reply(9))
        let records = BPFBuffer.records(in: buffer.span)

        #expect(records.count == 2)
        #expect(records[0].packet == 18..<61)
        // 64, not 61: the second record begins on the next four-byte boundary.
        #expect(records[1].packet == 82..<124)
    }

    @Test("A header longer than the struct is honoured rather than assumed away")
    func honoursHeaderLength() throws {
        // `bh_hdrlen` is this record's real header length, which the kernel is entitled
        // to pad beyond `sizeof(struct bpf_hdr)`. Using the struct size instead would
        // read the packet starting four bytes early.
        let buffer = BPFFixture.record(Self.reply(4), headerLength: 24)
        let records = BPFBuffer.records(in: buffer.span)
        #expect(records.count == 1)
        #expect(records[0].packet == 24..<66)
        let parsed = ARPFrame.parse(buffer.span.extracting(records[0].packet))
        let message = try #require(parsed)
        #expect(message.senderIP == IPv4Address("10.10.20.4")!)
    }

    @Test("A short read keeps the records that arrived whole and stops at the one that did not")
    func shortRead() {
        let full = BPFFixture.record(Self.reply(1))
            + BPFFixture.record(Self.reply(2))
            + BPFFixture.record(Self.reply(3))
        // Cut in the middle of the third packet. The kernel does not do this; a caller
        // that mis-sized a buffer, or a fixture cut on purpose, does — and the records
        // before the cut are real observations that must not be thrown away over a byte
        // count.
        let truncated = Array(full.prefix(160))
        let records = BPFBuffer.records(in: truncated.span)

        #expect(records.count == 2)
        #expect(records[0].packet == 18..<60)
        #expect(records[1].packet == 78..<120)
    }

    @Test("A tail too short to hold a header is left alone")
    func misalignedTail() {
        // Nineteen bytes: one less than a header. There is nothing here to parse and
        // nothing to be gained by guessing, and a walk that read past it would be
        // reading whatever the allocator left behind.
        let buffer = BPFFixture.record(Self.reply(5)) + [UInt8](repeating: 0x7F, count: 19)
        let records = BPFBuffer.records(in: buffer.span)
        #expect(records.count == 1)
        #expect(records[0].packet == 18..<60)
    }

    @Test("An impossible header stops the walk instead of manufacturing packets")
    func refusesImpossibleHeaders() {
        // `bh_hdrlen` smaller than a header can be means the cursor is no longer on a
        // record boundary, so nothing after it can be trusted — including the record
        // this header claims to introduce.
        func records(_ bytes: [UInt8]) -> [BPFBuffer.Record] {
            BPFBuffer.records(in: bytes.span)
        }

        var buffer = BPFFixture.record(Self.reply(6))
        buffer[BPFFixture.headerLengthOffset] = 8
        #expect(records(buffer).isEmpty)

        // A capture length that runs past the end of the buffer is the same situation
        // arriving from the other direction.
        var overlong = BPFFixture.record(Self.reply(7))
        overlong[BPFFixture.capturedOffset] = 0xFF
        overlong[BPFFixture.capturedOffset + 1] = 0xFF
        #expect(records(overlong).isEmpty)
    }

    @Test("A zero-length capture advances rather than looping forever")
    func zeroLengthCapture() {
        // 20 + 0 rounds to 20, so the cursor moves by a whole header. A walk that
        // advanced by `caplen` alone would sit on this record until the process was
        // killed.
        let buffer = BPFFixture.record([]) + BPFFixture.record(Self.reply(8))
        let records = BPFBuffer.records(in: buffer.span)
        #expect(records.count == 2)
        #expect(records[0].packet.isEmpty)
        #expect(records[1].packet == 38..<80)
    }

    @Test("A truncated capture is flagged, because half an ARP payload invents a host")
    func truncationIsVisible() {
        let full = Self.reply(2)
        let clipped = Array(full.prefix(30))
        let buffer = BPFFixture.record(clipped, wireLength: full.count)
        let records = BPFBuffer.records(in: buffer.span)
        #expect(records.count == 1)
        #expect(records[0].isTruncated)
        #expect(records[0].wireLength == 42)
    }

    @Test("The whole path: a read buffer becomes the ARP messages it holds")
    func endToEnd() {
        let buffer = [1, 2, 3].map { Self.reply(UInt8($0)) }.flatMap { BPFFixture.record($0) }
        let bytes = buffer.span
        let messages = BPFBuffer.records(in: bytes).compactMap {
            ARPFrame.parse(bytes.extracting($0.packet))
        }
        #expect(messages.count == 3)
        #expect(messages.map(\.senderIP) == [
            IPv4Address("10.10.20.1")!,
            IPv4Address("10.10.20.2")!,
            IPv4Address("10.10.20.3")!,
        ])
        let everyOneIsAReply = messages.allSatisfy(\.isReply)
        #expect(everyOneIsAReply)
    }
}

// MARK: - What the engine claims about itself

@Suite("The privileged engine claims exactly what it does")
struct BPFEngineDescriptorTests {
    @Test("It sweeps layer 2 and says so, and claims nothing else")
    func descriptor() {
        let engine = BPFDiscoveryEngine().descriptor
        #expect(engine.kind == .privilegedBPF)
        #expect(engine.name == "bpf-arp")
        // The capability the unprivileged engine was wrongly claiming until a capture
        // taken on 2026-09-12 showed it emitting no ARP of its own. This engine is the
        // thing that claim should have described.
        #expect(engine.capabilities.contains(.arpSweep))
        // And NOT the neighbour table: reading what the kernel already learned is a
        // different capability, the unprivileged engine has it, and an engine claiming
        // both would make the distinction meaningless again.
        #expect(!engine.capabilities.contains(.neighborTable))
        #expect(!engine.capabilities.contains(.icmpSweep))
        #expect(!engine.capabilities.contains(.synScan))
    }

    @Test("A refused open is never fatal, and only sometimes worth saying")
    func refusalsBecomeNotices() throws {
        // Not being root is the documented default and the reason this tool needs no
        // password. Announcing it on every scan would train a reader to skip the
        // degradation list, which is where the real problems are.
        #expect(DarwinScanner.notice(for: .notPrivileged) == nil)
        #expect(DarwinScanner.notice(for: nil) == nil)

        // A capability that was reachable and got taken is worth saying, and is always
        // recoverable — the unprivileged sweep ran.
        let busy = try #require(DarwinScanner.notice(for: .allDevicesBusy(tried: 4)))
        #expect(busy.stage == .setup)
        #expect(busy.recoverable)
        #expect(busy.reason.contains("in use by another process"))

        let tunnel = try #require(DarwinScanner.notice(for: .notEthernet(dataLinkType: 12)))
        #expect(tunnel.recoverable)
        #expect(tunnel.reason.contains("not Ethernet"))
    }
}

// MARK: - The live path

@Suite("The layer-2 sweep, against a real device")
struct BPFLiveTests {
    @Test(
        "A real device opens, binds and delivers frames this engine put on the wire",
        .enabled(
            if: geteuid() == 0,
            """
            Needs root. /dev/bpf* is crw------- root:wheel on a stock macOS and there is \
            no ChmodBPF daemon here, so this test cannot open a device as an ordinary \
            user. Run it with: sudo swift test --filter BPFLiveTests
            """
        )
    )
    func liveSweep() async throws {
        let interface = try DarwinInterfaceProvider().primaryInterface()
        let device = try BPFDevice.open(interface: interface.name)
        #expect(device.interfaceName == interface.name)
        #expect(device.devicePath.hasPrefix("/dev/bpf"))

        let engine = BPFDiscoveryEngine(concurrency: 128)
        let result = await engine.discover(
            ScanTarget(scanning: interface), deadline: Deadline(after: .seconds(10))
        )

        // The gateway must answer ARP. It is how this machine has been reaching the
        // internet, so if nothing at all replied the sweep is not on the wire.
        #expect(!result.hosts.isEmpty, "no host answered ARP on \(interface.name)")
        #expect(result.usedCapabilities.contains(.arpSweep))
        // Every host found this way came from a reply frame, so every one has the
        // hardware address that reply carried. A host with no MAC here would mean the
        // engine invented it.
        let everyHostCarriesItsHardwareAddress = result.hosts.allSatisfy { $0.mac != nil }
        #expect(everyHostCarriesItsHardwareAddress)
        // And no round trip, deliberately: see the note at the top of BPFSweep.swift on
        // why an ARP interval schedules the sweep and does not describe a host.
        let noHostCarriesARoundTrip = result.hosts.allSatisfy { $0.rtt == nil }
        #expect(noHostCarriesARoundTrip)
        #expect(result.timing.probesSent > 0)
    }

    @Test(
        "Composed, root finds every host the unprivileged sweep finds and never fewer",
        .enabled(
            if: geteuid() == 0,
            """
            Needs root, for the BPF half. Run it with: sudo swift test --filter BPFLiveTests
            """
        )
    )
    func compositeIsASuperset() async throws {
        // The property the whole composite exists to hold, measured against a real
        // segment rather than against stubs. The three engines run back to back on the
        // same network seconds apart, so a host may genuinely arrive or leave between
        // them — which is why the assertion is about the composite containing what the
        // unprivileged run found *in the same composite run*, not about comparing two
        // separate scans.
        let interface = try DarwinInterfaceProvider().primaryInterface()
        let target = ScanTarget(scanning: interface)
        func budget() -> Deadline { Deadline(after: .seconds(10)) }

        let arpOnly = await BPFDiscoveryEngine().discover(target, deadline: budget())
        let icmpOnly = await ICMPSweepEngine().discover(target, deadline: budget())
        let composed = await CompositeDiscoveryEngine([
            BPFDiscoveryEngine(), ICMPSweepEngine(),
        ]).discover(target, deadline: budget())

        let arp = Set(arpOnly.hosts.map(\.ip))
        let icmp = Set(icmpOnly.hosts.map(\.ip))
        let both = Set(composed.hosts.map(\.ip))

        // Printed rather than only asserted: on a home LAN where everything answers
        // ICMP the two sets are equal and ARP adds nothing, which is a true and
        // uninteresting result. What would be interesting — a host only ARP reaches —
        // needs a segment with an ICMP-filtered host on it, and saying how many there
        // were is how a reader tells the two situations apart.
        print("""
              ARP alone \(arp.count), ICMP alone \(icmp.count), composed \(both.count); \
              only ARP reached \(arp.subtracting(icmp).count), \
              only ICMP reached \(icmp.subtracting(arp).count)
              """)

        #expect(composed.usedCapabilities.contains(.arpSweep))
        #expect(composed.usedCapabilities.contains(.icmpSweep))
        // The one thing the composition may never do.
        let composedIsASuperset = both.isSuperset(of: arp) && both.isSuperset(of: icmp)
        #expect(composedIsASuperset,
                "composed \(both.sorted()) lost hosts from ARP \(arp.sorted()) or ICMP \(icmp.sorted())")
    }
}

#endif
