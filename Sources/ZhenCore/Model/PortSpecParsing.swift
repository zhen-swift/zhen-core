// PortSpecParsing.swift — turning what a person types into a probe order.
//
// This lived inline in the command line as a `split(separator: ",")` over integers,
// which meant `--ports 1-1024` was a usage error and `--ports common` was one too. It
// is here because `zhen ports` and `zhen scan --deep` both need it and neither should
// own it, and because a grammar with rejection cases in it deserves unit tests rather
// than a round trip through argument parsing.
//
// ── Order is meaning ──────────────────────────────────────────────────────────
//
// `PortSpec.ports` is documented as "the ports, in the order they will be probed", and
// that order survives here: `80,22` probes 80 first. What is removed is duplication —
// asking for a port twice probes it once — and the FIRST position wins, because a
// person writing `80,1-1024` has said something about 80 that they have not said about
// the rest.
//
// ── What this will not do ─────────────────────────────────────────────────────
//
// It does not name services. `Ports.swift` refuses to identify a service from its port
// number — *"a port-number table is a guess dressed as a fact"* — and a parser that
// accepted `--ports http` would be the same guess wearing a different hat. A named set
// here is a SET, defined by this project and labelled as ours: `common` is the 36 ports
// `commonServices` already carries.

import Foundation

extension PortSpec {
    /// Why a spec was refused, with the message a person sees.
    public struct ParseError: Error, Equatable, Sendable {
        /// What to print. A whole sentence, because it is printed as one.
        public var message: String
        public init(_ message: String) { self.message = message }
    }

    /// The named sets. Ours, and labelled as ours.
    ///
    /// `all` is absent deliberately: it parses, but it is 65,535 ports and the guard
    /// that refuses it without confirmation is the caller's, not the parser's. The
    /// parser's job is to say what was asked for, not whether it is wise.
    /// The named sets. Ours, and labelled as ours.
    ///
    /// `all` is present deliberately: it parses, but 65,535 ports is not the parser's
    /// business to refuse — `ProbeBudget` is what counts the probes and asks.
    ///
    /// **There is no `top-100`, and its absence is a decision.** A top-N set needs
    /// frequency data. nmap's is under the Nmap Public Source License and is not ours to
    /// copy; IANA's registry, which is what `iana` comes from, records WHICH ports have
    /// an assignment and publishes no ranking at all. Shipping IANA's list under the
    /// name `top-100` would be a frequency claim the source cannot support — the same
    /// guess-dressed-as-a-fact that `Ports.swift` refuses when it declines to name a
    /// service from its port number.
    public static let namedSets: [String: [UInt16]] = [
        "common": PortSpec.commonServices.ports,
        // 682 of the 1,023 well-known ports carry a real assignment; the rest are
        // Unassigned or Reserved. So `iana` is `1-1023` minus a third of the probes,
        // and it loses nothing that was ever going to answer.
        "iana": PortSpec.ianaWellKnown,
        "all": Array(1...65_535),
    ]

    /// Parses a spec, or says why it cannot.
    ///
    /// Grammar, as `PORTS-plan.md`'s port spec section gives it:
    ///
    /// | Spec | Means |
    /// |---|---|
    /// | `22,80,443` | those three |
    /// | `1-1024` | inclusive range |
    /// | `common` | this project's 36 |
    /// | `all` | 1-65535 |
    /// | `T:80,U:53` | protocol-qualified |
    /// | `1-1024,!135-139` | exclusion |
    ///
    /// - Parameter text: what the user typed.
    /// - Returns: the ports in probe order, deduplicated, first position winning.
    public static func parse(_ text: String) throws(ParseError) -> PortSpec {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw ParseError("--ports was empty.") }

        var included: [UInt16] = []
        var excluded: Set<UInt16> = []
        var sawInclusion = false

        // `omittingEmptySubsequences: false`, or the guard below can never fire:
        // Swift's default drops the empty entry in `22,,80` and the typo scans silently.
        for rawPiece in trimmed.split(separator: ",", omittingEmptySubsequences: false) {
            let piece = rawPiece.trimmingCharacters(in: .whitespaces)
            guard !piece.isEmpty else {
                throw ParseError("'\(trimmed)' has an empty entry between commas.")
            }
            let isExclusion = piece.hasPrefix("!")
            let body = isExclusion ? String(piece.dropFirst()) : piece
            guard !body.isEmpty else {
                throw ParseError("'!' needs a port or range after it.")
            }
            // A protocol prefix qualifies which transport is probed. The transport is
            // carried separately from the numbers, so it is accepted and recorded here
            // and the engine decides what to do with it — today, TCP only.
            let (transport, numbersText) = splitTransport(body)
            if transport == .udp {
                throw ParseError("UDP is not scannable yet, so 'U:' has nothing to do. "
                                 + "See PORTS-plan.md on why UDP needs a fourth port state.")
            }
            let numbers = try expand(numbersText, whole: piece)
            if isExclusion {
                excluded.formUnion(numbers)
            } else {
                sawInclusion = true
                included.append(contentsOf: numbers)
            }
        }

        guard sawInclusion else {
            throw ParseError("'\(trimmed)' only excludes ports; there is nothing to scan.")
        }

        // Deduplicated with the FIRST position winning, so `80,1-1024` still probes 80
        // first. An ordered set rather than `Set`, because probe order is a documented
        // property of `PortSpec`.
        var seen: Set<UInt16> = []
        let ports = included.filter { seen.insert($0).inserted && !excluded.contains($0) }

        guard !ports.isEmpty else {
            throw ParseError("'\(trimmed)' excludes every port it includes.")
        }
        return PortSpec(ports)
    }

    /// Splits a `T:`/`U:` prefix off, case-insensitively.
    private static func splitTransport(_ body: String) -> (TransportProtocol?, String) {
        let lowered = body.lowercased()
        if lowered.hasPrefix("t:") { return (.tcp, String(body.dropFirst(2))) }
        if lowered.hasPrefix("u:") { return (.udp, String(body.dropFirst(2))) }
        return (nil, body)
    }

    /// One piece — a number, a range, a named set, or a service name — as its ports.
    private static func expand(_ text: String, whole: String) throws(ParseError) -> [UInt16] {
        let body = text.trimmingCharacters(in: .whitespaces)
        guard !body.isEmpty else { throw ParseError("'\(whole)' has no port in it.") }

        if let named = namedSets[body.lowercased()] { return named }

        // A service name SELECTS a port; it never names a result.
        //
        // `Ports.swift` refuses port-to-service — "something answered on 22, therefore
        // SSH" — which is a claim about what is running, made from a number, with no
        // evidence behind it. This is the opposite direction and asserts nothing: `ssh`
        // is a way of spelling 22 in the request, and what comes back is still whatever
        // the banner actually said, or nothing at all.
        //
        // Checked after the named sets so `common` and `iana` keep their meaning even
        // if the registry ever assigns those strings to a port.
        if let port = ianaServiceNames[body.lowercased()] { return [port] }

        if body.contains("-") {
            let bounds = body.split(separator: "-", omittingEmptySubsequences: false)
            guard bounds.count == 2 else {
                throw ParseError("'\(whole)' is not a range; a range is two numbers, like 1-1024.")
            }
            let low = try port(String(bounds[0]), whole: whole)
            let high = try port(String(bounds[1]), whole: whole)
            guard low <= high else {
                throw ParseError("'\(whole)' runs backwards; a range is low-high, like \(high)-\(low).")
            }
            return Array(low...high)
        }

        return [try port(body, whole: whole)]
    }

    /// One port number, with the two failures spelled differently because they are.
    private static func port(_ text: String, whole: String) throws(ParseError) -> UInt16 {
        let body = text.trimmingCharacters(in: .whitespaces)
        guard let value = Int(body) else {
            // Named here rather than left as "not a number", because by this point a
            // service name has already been tried and failed — and "'htp' is not a port
            // number" reads as though the user typed arithmetic wrong rather than
            // misspelling a service.
            throw ParseError(
                "'\(body)' is not a port number, a range, or a service name.")
        }
        // Out of range is a different mistake from not being a number, and 0 is not a
        // port you can connect to — saying "not a port number" about 70000 would be
        // telling someone their arithmetic is a typo.
        guard value >= 1, value <= 65_535 else {
            throw ParseError("\(value) is not a port; ports run from 1 to 65535.")
        }
        return UInt16(value)
    }
}
