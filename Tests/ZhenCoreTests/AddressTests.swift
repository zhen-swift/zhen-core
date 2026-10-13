import Testing
@testable import ZhenCore

@Suite("MAC addresses")
struct MACAddressTests {
    @Test("Unpadded ARP-table forms normalize to the same value")
    func unpaddedParsing() throws {
        let short = try MACAddress.required("0:92:35:30:a:1")
        let padded = try MACAddress.required("00:92:35:30:0A:01")
        #expect(short == padded)
        #expect(short.description == "00:92:35:30:0A:01")
    }

    @Test("Hyphen separators parse")
    func hyphenSeparators() throws {
        let mac = try MACAddress.required("30-DE-4B-5E-03-10")
        #expect(mac.description == "30:DE:4B:5E:03:10")
    }

    @Test("Malformed input is rejected")
    func rejectsGarbage() {
        #expect(MACAddress("") == nil)
        #expect(MACAddress("00:11:22:33:44") == nil)
        #expect(MACAddress("00:11:22:33:44:55:66") == nil)
        #expect(MACAddress("00:11:22:33:44:ZZ") == nil)
        #expect(MACAddress("000:11:22:33:44:55") == nil)
    }

    @Test("The locally administered bit is what separates a rotating MAC from a stable one")
    func locallyAdministered() throws {
        // Real gateway hardware address — globally administered.
        let stable = try MACAddress.required("30:DE:4B:5E:03:10")
        #expect(stable.isLocallyAdministered == false)

        // Private Wi-Fi addresses observed on this network.
        for rotating in ["DA:5C:22:5E:08:0A", "F2:3A:91:5E:0A:44", "6E:F0:9D:5E:0B:52"] {
            let mac = try #require(MACAddress(rotating))
            #expect(mac.isLocallyAdministered, "\(rotating) should read as locally administered")
        }
    }

    @Test("Bytes round-trip")
    func byteRoundTrip() throws {
        let mac = try MACAddress.required("A8:51:AB:5E:09:6C")
        #expect(mac.bytes == [0xA8, 0x51, 0xAB, 0x5E, 0x09, 0x6C])
        #expect(MACAddress(bytes: mac.bytes) == mac)
    }
}

@Suite("IPv4")
struct IPv4Tests {
    @Test("Parsing and ordering")
    func parseAndOrder() throws {
        let low = try #require(IPv4Address("10.10.20.2"))
        let high = try #require(IPv4Address("10.10.20.112"))
        #expect(low < high)
        #expect(low.description == "10.10.20.2")
        #expect(IPv4Address("10.10.20.256") == nil)
        #expect(IPv4Address("10.10.20") == nil)
        #expect(IPv4Address("10.10.20.") == nil)
    }

    @Test("A /24 yields 254 scannable hosts, excluding network and broadcast")
    func hostEnumeration() throws {
        let network = try #require(IPv4Network("10.10.20.0/24"))
        let hosts = network.hosts
        #expect(hosts.count == 254)
        #expect(hosts.first?.description == "10.10.20.1")
        #expect(hosts.last?.description == "10.10.20.254")
        #expect(network.broadcastAddress.description == "10.10.20.255")
    }

    @Test("Membership uses the mask, and the base is normalized on init")
    func membership() throws {
        let network = try #require(IPv4Network("10.10.20.57/24"))
        #expect(network.description == "10.10.20.0/24")
        #expect(network.contains(try #require(IPv4Address("10.10.20.254"))))
        #expect(!network.contains(try #require(IPv4Address("10.10.21.1"))))
    }

    @Test("A /32 covers exactly itself")
    func singleHost() throws {
        let network = try #require(IPv4Network("10.10.20.1/32"))
        #expect(network.hosts.count == 1)
    }
}
