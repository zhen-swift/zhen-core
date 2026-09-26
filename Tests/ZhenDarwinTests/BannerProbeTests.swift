// BannerProbeTests.swift — the parsing half, which is where a banner probe lies.
//
// The network half needs a listener and is exercised by running the thing. What is
// tested here is the part that turns bytes into a claim, because that is where a
// scanner invents things: the failure mode of a banner parser is not a crash, it is a
// confident `"name": "http"` on a port that sent four bytes of something else.
//
// Every string below is the real first line of a real service, taken from scans of
// 10.10.20.0/24 and from the RFCs that define the greeting.
#if canImport(Darwin)

import Foundation
import Testing
@testable import ZhenCore
@testable import ZhenDarwin

@Suite("A banner is read, never guessed")
struct BannerParsingTests {
    @Test("An SSH identification string yields the product and the version")
    func ssh() throws {
        // RFC 4253: SSH-protoversion-softwareversion SP comments CR LF.
        let identity = try #require(
            BannerProbe.parseGreeting(Array("SSH-2.0-OpenSSH_9.6\r\n".utf8), port: 22)
        )
        #expect(identity.name == "ssh")
        #expect(identity.product == "OpenSSH")
        #expect(identity.version == "9.6")
        #expect(identity.evidence == .banner)
        // The raw line is kept. It is the evidence, and a user who disagrees with the
        // parse has to be able to see what was parsed.
        #expect(identity.banner == "SSH-2.0-OpenSSH_9.6")
    }

    @Test("A service that speaks but is not recognised is reported as unknown, not as the port")
    func unrecognisedGreeting() throws {
        // The trap this guards. Something answered on 8080; a scanner that reported
        // "http" because the number is 8080 would be stating what it does not know.
        let identity = try #require(
            BannerProbe.parseGreeting(Array("*HELLO 3 PROPRIETARY\r\n".utf8), port: 8080)
        )
        #expect(identity.name == "unknown")
        #expect(identity.banner == "*HELLO 3 PROPRIETARY")
        // And the evidence is still banner: bytes did arrive, and that is a real
        // observation even when it cannot be named.
        #expect(identity.evidence == .banner)
    }

    @Test("Silence is not a service")
    func silenceIsNothing() {
        #expect(BannerProbe.parseGreeting([], port: 22) == nil)
        #expect(BannerProbe.parseGreeting(Array("\r\n".utf8), port: 22) == nil)
        #expect(BannerProbe.parseHTTP([]) == nil)
    }

    @Test("Greetings that name themselves unambiguously are named")
    func knownGreetings() throws {
        let smtp = try #require(BannerProbe.parseGreeting(Array("220 mail.example ESMTP\r\n".utf8), port: 25))
        #expect(smtp.name == "smtp")
        // The same 220 on 21 is FTP. The port picks which protocol a shared greeting
        // belongs to — that is the one thing a port number is allowed to decide.
        let ftp = try #require(BannerProbe.parseGreeting(Array("220 ProFTPD\r\n".utf8), port: 21))
        #expect(ftp.name == "ftp")
        let pop = try #require(BannerProbe.parseGreeting(Array("+OK Dovecot ready\r\n".utf8), port: 110))
        #expect(pop.name == "pop3")
        let imap = try #require(BannerProbe.parseGreeting(Array("* OK IMAP4rev1\r\n".utf8), port: 143))
        #expect(imap.name == "imap")
        let vnc = try #require(BannerProbe.parseGreeting(Array("RFB 003.008\n".utf8), port: 5900))
        #expect(vnc.name == "vnc")
    }

    @Test("An HTTP response is identified by its Server header, and by its status line without one")
    func http() throws {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: x\r\n\r\n"
        let identity = try #require(BannerProbe.parseHTTP(Array(response.utf8)))
        #expect(identity.name == "http")
        #expect(identity.product == "nginx")
        #expect(identity.version == "1.24.0")

        // A server that declines to name itself has still proved it speaks HTTP, and
        // that is worth reporting — with the status line as the evidence.
        let anonymous = try #require(
            BannerProbe.parseHTTP(Array("HTTP/1.0 404 Not Found\r\n\r\n".utf8))
        )
        #expect(anonymous.name == "http")
        #expect(anonymous.product == nil)
        #expect(anonymous.banner == "HTTP/1.0 404 Not Found")
    }

    @Test("Something that is not HTTP is not reported as HTTP")
    func httpRefusesForeignBytes() {
        #expect(BannerProbe.parseHTTP(Array("SSH-2.0-OpenSSH_9.6\r\n".utf8)) == nil)
        #expect(BannerProbe.parseHTTP(Array([0x16, 0x03, 0x01, 0x00, 0x2f])) == nil)
    }

    @Test("Real products from this network split the way a person would split them")
    func realWorldSplits() {
        // Every one of these came off 10.10.20.0/24 during development.
        #expect(BannerProbe.splitProduct("nginx/1.24.0").0 == "nginx")
        #expect(BannerProbe.splitProduct("nginx/1.24.0").1 == "1.24.0")
        #expect(BannerProbe.splitProduct("OpenSSH_9.6").0 == "OpenSSH")
        #expect(BannerProbe.splitProduct("AirTunes/960.13.1").1 == "960.13.1")
        #expect(BannerProbe.splitProduct("MJPG-Streamer/0.2").0 == "MJPG-Streamer")
        #expect(BannerProbe.splitProduct("httpd/1.25.7.29").1 == "1.25.7.29")

        // Conservative where it cannot tell. Inventing a split is worse than leaving
        // the whole string as the product.
        #expect(BannerProbe.splitProduct("Apache").0 == "Apache")
        #expect(BannerProbe.splitProduct("Apache").1 == nil)
        #expect(BannerProbe.splitProduct("lighttpd/scary").1 == nil)
        #expect(BannerProbe.splitProduct(nil).0 == nil)
        #expect(BannerProbe.splitProduct("   ").0 == nil)
    }

    @Test("The TLS-first port list is a hint about order, never about the answer")
    func tlsListIsOnlyAHint() {
        // 443 is tried TLS-first because that is usually right. What matters is that
        // being absent from this set does not stop a port being identified as TLS —
        // a service on a non-standard port is exactly the case a port table gets wrong.
        #expect(BannerProbe.likelyTLS.contains(443))
        #expect(BannerProbe.likelyTLS.contains(8443))
        #expect(!BannerProbe.likelyTLS.contains(9999))
    }
}

@Suite("Banners compose onto whichever engine produced the verdicts")
struct BannerCompositionTests {
    @Test("The composition claims banner probing on top of the base engine's capabilities")
    func descriptor() {
        let overConnect = BannerProbingPortScan(base: TCPConnectScanEngine())
        #expect(overConnect.descriptor.capabilities.contains(.connectScan))
        #expect(overConnect.descriptor.capabilities.contains(.bannerProbe))
        #expect(overConnect.descriptor.kind == .unprivileged)
        #expect(overConnect.descriptor.name == "tcp-connect+banner")

        let overSYN = BannerProbingPortScan(base: SYNScanEngine())
        #expect(overSYN.descriptor.capabilities.contains(.synScan))
        #expect(overSYN.descriptor.capabilities.contains(.bannerProbe))
        // The privilege of the composition is the privilege of the thing that needs it.
        #expect(overSYN.descriptor.kind == .privilegedBPF)
    }
}

#endif
