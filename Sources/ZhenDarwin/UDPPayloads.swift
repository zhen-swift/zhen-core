// UDPPayloads.swift — what to send to a UDP port so that an open one answers.
//
// An open UDP port usually says nothing to an empty datagram. A payload the service
// understands turns that silence into an answer, and an answer is the only thing that
// makes a UDP port `open` rather than `open_filtered`. So the table is short and every
// entry is a real request in the service's own protocol, built here from its RFC:
//
//   53    DNS       a query for the root's NS records             RFC 1035
//   123   NTP       a client-mode request                         RFC 5905
//   137   NetBIOS   a node-status query — the one the naming stage already sends
//   161   SNMP      a v3 engine-discovery request                 RFC 3412, 3414
//   1900  SSDP      an M-SEARCH — the one the naming stage already sends
//   5353  mDNS      a legacy-unicast query for the service list   RFC 6762 §6.7
//
// SNMP is v3 discovery, deliberately, and not a v1 GetRequest with community `public`.
// Discovery carries no credential and every v3 agent must answer it with a Report. A
// community string is a password, and trying the default one is a login attempt — which
// is not this tool's business, and on a managed network raises an authentication-failure
// trap for every host scanned.
//
// A port not in the table is sent an empty datagram. An answer still makes it open and
// an ICMP port-unreachable still makes it closed; the table only widens how often an open
// port is heard.
//
// **A recognizer names a service; a table entry never does.** An answer that parses as
// DNS is DNS, and the result says so with `protocol_handshake` evidence. An answer that
// does not parse is still an answer — the port is open — and the service is left nil,
// because port 53 is not evidence of anything. Same rule as A2: a name selects, it never
// names a result.

#if canImport(Darwin)
import ZhenCore

/// A request to send to one UDP port, and how to tell its answer apart from noise.
struct UDPPayload: Sendable {
    /// The service the answer proves, when `recognizes` accepts it.
    var service: String
    /// The datagram to send.
    var bytes: [UInt8]
    /// Whether a reply is this protocol's answer to `bytes`.
    var recognizes: @Sendable ([UInt8]) -> Bool
}

enum UDPPayloads {
    /// The request for a port, or nil for a port not in the table.
    static func payload(for port: UInt16) -> UDPPayload? { table[port] }

    /// Fixed so the recognizers can check it: a reply must echo the request's ID. Not
    /// secret and not needed to be — a connected socket already only hears the peer.
    static let transactionID: UInt16 = 0x7A68   // "zh"

    static let table: [UInt16: UDPPayload] = [
        53: UDPPayload(service: "dns", bytes: dnsQuery(name: [], type: 2),
                       recognizes: { isDNSResponse($0) }),
        123: UDPPayload(service: "ntp", bytes: ntpRequest,
                        recognizes: { isNTPServerReply($0) }),
        137: UDPPayload(service: "netbios-ns", bytes: NBSTAT.query(transaction: transactionID),
                        recognizes: { isDNSResponse($0) }),   // NBNS is DNS-shaped
        161: UDPPayload(service: "snmp", bytes: snmpV3Discovery,
                        recognizes: { isSNMPv3Message($0) }),
        1900: UDPPayload(service: "ssdp", bytes: SSDPSocket.searchRequest(mx: 1),
                         recognizes: { reply in
                             SSDPResponse.parse(String(decoding: reply, as: UTF8.self),
                                                from: IPv4Address(raw: 0)) != nil
                         }),
        5353: UDPPayload(service: "mdns",
                         bytes: dnsQuery(name: ["_services", "_dns-sd", "_udp", "local"], type: 12),
                         recognizes: { isDNSResponse($0) }),
    ]

    // ── DNS, and the three things shaped like it ────────────────────────────────────

    /// A standard query, recursion not desired, for one name and type, class IN.
    static func dnsQuery(name labels: [String], type: UInt16) -> [UInt8] {
        var packet = bigEndian(transactionID)
        packet += [0x00, 0x00]              // flags: standard query, RD clear
        packet += [0x00, 0x01]              // qdcount
        packet += [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]   // an, ns, ar
        for label in labels {
            packet.append(UInt8(label.utf8.count))
            packet += Array(label.utf8)
        }
        packet.append(0x00)                 // root
        packet += bigEndian(type)
        packet += [0x00, 0x01]              // class IN
        return packet
    }

    /// A DNS-shaped response to our query: our ID, the response bit set, and a header's
    /// worth of bytes. An error RCODE still counts — a server saying "refused" is a
    /// server.
    static func isDNSResponse(_ reply: [UInt8]) -> Bool {
        reply.count >= 12
            && UInt16(reply[0]) << 8 | UInt16(reply[1]) == transactionID
            && reply[2] & 0x80 != 0
    }

    // ── NTP ─────────────────────────────────────────────────────────────────────────

    /// 48 bytes, the first saying leap 0, version 4, mode 3 (client). The rest zero:
    /// a server answers a request carrying no timestamps.
    static let ntpRequest: [UInt8] = [0x23] + [UInt8](repeating: 0, count: 47)

    /// A server-mode reply (mode 4) of at least the fixed header's length.
    static func isNTPServerReply(_ reply: [UInt8]) -> Bool {
        reply.count >= 48 && reply[0] & 0x07 == 4
    }

    // ── SNMP v3 discovery ───────────────────────────────────────────────────────────

    /// An unauthenticated GetRequest with an empty engine ID and user, flagged
    /// reportable. RFC 3414 §4: an agent receiving it answers with a Report carrying its
    /// engine ID. Built from BER rather than pasted, so each field can be read.
    static let snmpV3Discovery: [UInt8] = {
        let usm = ber(0x30, [                               // UsmSecurityParameters
            ber(0x04, []),                                  //   msgAuthoritativeEngineID ""
            berInteger(0),                                  //   msgAuthoritativeEngineBoots
            berInteger(0),                                  //   msgAuthoritativeEngineTime
            ber(0x04, []),                                  //   msgUserName ""
            ber(0x04, []),                                  //   msgAuthenticationParameters
            ber(0x04, []),                                  //   msgPrivacyParameters
        ].flatMap { $0 })
        return ber(0x30, [                                  // SNMPv3Message
            berInteger(3),                                  //   msgVersion
            ber(0x30, [                                     //   msgGlobalData
                berInteger(Int(transactionID)),             //     msgID
                berInteger(65_507),                         //     msgMaxSize
                ber(0x04, [0x04]),                          //     msgFlags: reportable
                berInteger(3),                              //     msgSecurityModel: USM
            ].flatMap { $0 }),
            ber(0x04, usm),                                 //   msgSecurityParameters
            ber(0x30, [                                     //   ScopedPDU
                ber(0x04, []),                              //     contextEngineID ""
                ber(0x04, []),                              //     contextName ""
                ber(0xA0, [                                 //     GetRequest-PDU
                    berInteger(Int(transactionID)),         //       request-id
                    berInteger(0),                          //       error-status
                    berInteger(0),                          //       error-index
                    ber(0x30, []),                          //       variable-bindings
                ].flatMap { $0 }),
            ].flatMap { $0 }),
        ].flatMap { $0 })
    }()

    /// A BER SEQUENCE whose first element is INTEGER 3 — an SNMPv3 message. The Report
    /// an agent sends back to discovery is one; nothing else on 161 is.
    static func isSNMPv3Message(_ reply: [UInt8]) -> Bool {
        guard reply.count >= 5, reply[0] == 0x30 else { return false }
        // Skip the SEQUENCE's length, short or long form.
        var offset = 2
        if reply[1] & 0x80 != 0 { offset += Int(reply[1] & 0x7F) }
        guard offset + 3 <= reply.count else { return false }
        return reply[offset] == 0x02 && reply[offset + 1] == 0x01 && reply[offset + 2] == 0x03
    }

    /// One BER tag-length-value. Lengths up to 65,535, which is every length here.
    static func ber(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        let length: [UInt8] = switch value.count {
        case ..<0x80: [UInt8(value.count)]
        case ..<0x100: [0x81, UInt8(value.count)]
        default: [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)]
        }
        return [tag] + length + value
    }

    /// A non-negative BER INTEGER in the fewest octets, with a leading zero where the
    /// high bit would otherwise make it negative.
    static func berInteger(_ value: Int) -> [UInt8] {
        var octets: [UInt8] = []
        var remaining = value
        repeat {
            octets.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        } while remaining > 0
        if octets[0] & 0x80 != 0 { octets.insert(0x00, at: 0) }
        return ber(0x02, octets)
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }
}
#endif
