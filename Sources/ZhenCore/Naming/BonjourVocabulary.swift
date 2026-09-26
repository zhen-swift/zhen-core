// BonjourVocabulary.swift — the naming knowledge, kept away from the wire.
//
// Everything in this file is domain knowledge about what Bonjour records MEAN. None
// of it is Darwin-specific: an Avahi-backed Linux browser would need the identical
// table, the identical TXT keys and the identical cleaning rules, and duplicating them
// in each platform target is how the two would drift. So the C interop lives in
// `ZhenDarwin/MDNSBrowser.swift` and the meaning lives here, in the package that
// already holds `NameSource` and `NameCandidate`.
//
// It is also the part that was expensive to learn. Each rule below was paid for once
// against a real network, and a comment saying only *what* the code does would let the
// next person delete it as redundant. Every one of them says why.

/// One browsed Bonjour service type, and how clean a name it carries.
public struct BonjourServiceType: Sendable, Hashable {
    /// The type as `dns_sd` spells it — `_googlecast._tcp`.
    public let name: String
    /// Quality rank. Lower is cleaner, and it becomes `NameCandidate.rank`, where it
    /// breaks ties between two mDNS candidates for the same host.
    public let rank: Int
    /// A TXT key whose value is a better name than the instance name.
    ///
    /// Only `_googlecast._tcp` has one. Its instance name is a factory string —
    /// `Chromecast-6f3a1d…` — while its TXT `fn` is the name the owner typed into the
    /// Home app. Reading the instance name for that type gets the ugly half of the
    /// only record on the network that carries a genuinely user-authored name.
    public let friendlyNameKey: String?

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(name: String, rank: Int, friendlyNameKey: String? = nil) {
        self.name = name
        self.rank = rank
        self.friendlyNameKey = friendlyNameKey
    }
}

/// The service types worth browsing, the TXT keys worth reading, and the instance-name
/// cleaning rules — all of it platform-independent.
public enum BonjourVocabulary {
    /// The browsed types, cleanest first. The array index IS the rank.
    ///
    /// Ranking exists because ONE DEVICE ADVERTISES ITSELF UNDER SEVERAL TYPES AND THE
    /// NAMES DISAGREE. The Apple TV on the reference network is
    /// `"Sala de entretenimiento"` on `_companion-link._tcp` and
    /// `"70-35-60-63.1 Sala de entretenimiento"` on `_sleep-proxy._udp` — same device,
    /// same instant, two names. Without a rank the winner is whichever record arrived
    /// first, which is a race, and the device's name would flip between runs.
    ///
    /// The ordering principle is name cleanliness, not protocol importance:
    ///
    ///   * `_googlecast` first, because its TXT `fn` is the only field on this list a
    ///     human deliberately typed.
    ///   * `_companion-link`, `_homekit`, `_airplay`, `_sonos`, `_spotify-connect`,
    ///     `_androidtvremote2` carry the device's user-visible name verbatim.
    ///   * `_device-info` next: the name is clean but it is the host name rather than
    ///     the device name, and it exists mainly for its `model` key.
    ///   * the file and login services — `_smb`, `_ssh` — carry the host name.
    ///   * `_workstation` below them because avahi appends ` [aa:bb:cc:dd:ee:ff]`.
    ///   * the print services, whose instance names are often the queue rather than
    ///     the device.
    ///   * `_raop` and `_sleep-proxy` last: both carry a prefix that has to be cut off
    ///     before the name is readable at all, and a cleaning rule that fails leaves
    ///     rubbish in the artifact. Ranking them last means a cleaner record wins
    ///     whenever there is one.
    ///
    /// Anything added here must also be added to the CLI's embedded `Info.plist` under
    /// `NSBonjourServices`. A type that is browsed but not declared there returns
    /// nothing, silently, which looks exactly like a device that is not present.
    public static let serviceTypes: [BonjourServiceType] = [
        BonjourServiceType(name: "_googlecast._tcp", rank: 0, friendlyNameKey: "fn"),
        BonjourServiceType(name: "_companion-link._tcp", rank: 1),
        BonjourServiceType(name: "_homekit._tcp", rank: 2),
        BonjourServiceType(name: "_airplay._tcp", rank: 3),
        BonjourServiceType(name: "_sonos._tcp", rank: 4),
        BonjourServiceType(name: "_spotify-connect._tcp", rank: 5),
        BonjourServiceType(name: "_androidtvremote2._tcp", rank: 6),
        BonjourServiceType(name: "_device-info._tcp", rank: 7),
        BonjourServiceType(name: "_esphomelib._tcp", rank: 8),
        BonjourServiceType(name: "_hue._tcp", rank: 9),
        BonjourServiceType(name: "_smb._tcp", rank: 10),
        BonjourServiceType(name: "_ssh._tcp", rank: 11),
        BonjourServiceType(name: "_workstation._tcp", rank: 12),
        BonjourServiceType(name: "_ipp._tcp", rank: 13),
        BonjourServiceType(name: "_printer._tcp", rank: 14),
        BonjourServiceType(name: "_raop._tcp", rank: 15),
        BonjourServiceType(name: "_sleep-proxy._udp", rank: 16),
    ]

    /// The type names, in rank order. This is the list a browser iterates and the list
    /// the `Info.plist` must match.
    public static let browsedTypes: [String] = serviceTypes.map(\.name)

    /// Looks a type up, tolerating the trailing-dot and domain-suffixed spellings that
    /// `dns_sd` hands back — a browse reply's `regtype` is `_airplay._tcp.` with the
    /// dot, and a resolve's is sometimes `_airplay._tcp.local.`.
    public static func serviceType(_ name: String) -> BonjourServiceType? {
        let normalized = normalizeServiceType(name)
        return serviceTypes.first { $0.name == normalized }
    }

    /// Strips the trailing dot and any `.local` suffix from a `dns_sd` type string.
    public static func normalizeServiceType(_ name: String) -> String {
        var text = name
        while text.hasSuffix(".") { text.removeLast() }
        if text.hasSuffix(".local") { text.removeLast(6) }
        while text.hasSuffix(".") { text.removeLast() }
        return text
    }

    /// The rank for a type, or one past the end of the table for a type not in it.
    ///
    /// Unknown types sort behind every known one rather than being dropped: a name is
    /// still a name, and the cascade keeps losing candidates anyway.
    public static func rank(of serviceType: String) -> Int {
        self.serviceType(serviceType)?.rank ?? serviceTypes.count
    }

    // ── TXT model keys ───────────────────────────────────────────────────────────

    /// TXT keys that hold a model string, in the order they are tried. First non-empty
    /// wins.
    ///
    /// `am` is what `_airplay` and `_raop` use (`AppleTV5,3`); `model` is
    /// `_device-info`'s (`Mac16,9`); `rpMd` is the remote-pairing model on
    /// `_companion-link`; `ty` is the printer types' human model string; `device` is
    /// what esphome publishes; `md` is `_googlecast`'s (`Chromecast Ultra`) and is last
    /// because it is the one key whose meaning depends on the service type — see
    /// `forbiddenModelKeys(for:)`.
    public static let modelKeys = ["am", "model", "rpMd", "ty", "device", "md"]

    /// TXT keys that must never be read as a model ON A GIVEN SERVICE TYPE.
    ///
    /// **`md` MEANS TWO DIFFERENT THINGS AND THE SERVICE TYPE IS WHAT DISAMBIGUATES.**
    ///
    /// On `_raop` it is the supported-metadata list and its value is the literal string
    /// `"0,1,2"` — three integers naming which metadata formats the receiver accepts.
    /// It is short, it is always present, it sits right next to `am`, and every instinct
    /// says "model". Reading it there fills the artifact with `"0,1,2"` in the model
    /// column for every AirPlay speaker on the network: plausible-looking, uniform, and
    /// completely wrong.
    ///
    /// On `_googlecast` it is the model, and a good one — `Chromecast Ultra`,
    /// `Google Nest Mini`. Forbidding it globally, as an earlier version did, dodged the
    /// `_raop` trap by throwing away the real model on every Chromecast, Nest and
    /// Android TV on the network. That is the same class of mistake as the trap itself:
    /// a rule applied one level too broadly, and silent either way.
    ///
    /// So the exclusion is scoped. The default is empty; only `_raop` forbids anything.
    public static func forbiddenModelKeys(for serviceType: String) -> Set<String> {
        normalizeServiceType(serviceType) == "_raop._tcp" ? ["md"] : []
    }

    /// The model string a TXT record carries, or nil.
    ///
    /// - Parameters:
    ///   - txt: the record's key/value pairs.
    ///   - serviceType: which service published it. REQUIRED, not optional, because
    ///     `md` cannot be interpreted without it — a signature that let a caller omit
    ///     the type would be an invitation to reintroduce the trap.
    ///
    /// Lookup is case-insensitive because publishers are inconsistent about it —
    /// `rpMd` and `rpmd` are both seen in the wild — and the forbidden set is checked
    /// case-insensitively too, so `MD` cannot slip past `md`.
    public static func model(fromTXT txt: [String: String], serviceType: String) -> String? {
        let forbidden = forbiddenModelKeys(for: serviceType)
        var folded: [String: String] = [:]
        folded.reserveCapacity(txt.count)
        for (key, value) in txt {
            let lowered = key.lowercased()
            guard !forbidden.contains(lowered) else { continue }
            // First writer wins, so two spellings of one key cannot make the result
            // depend on dictionary iteration order.
            if folded[lowered] == nil { folded[lowered] = value }
        }
        for key in modelKeys {
            guard let value = folded[key.lowercased()] else { continue }
            let trimmed = value.trimmed
            if !trimmed.isEmpty { return trimmed }
        }
        return nil
    }

    // ── Instance-name cleaning ───────────────────────────────────────────────────

    /// Turns an advertised instance name into something a person would recognise.
    ///
    /// Three rules, each from a real string on a real network, each applied once:
    ///
    ///   1. **`_raop` hardware prefix.** AirPlay receivers publish
    ///      `"AA0F330127A2@Mac Studio de Jose"` — twelve hex digits, an `@`, then the
    ///      name. The prefix is the device's hardware address and identifies nothing a
    ///      reader wants.
    ///   2. **`_sleep-proxy` owner prefix.** The proxy publishes on behalf of a
    ///      sleeping device as `"70-35-60-63.1 Sala de entretenimiento"` — four
    ///      hex-pair groups, a dot, a sequence number, a space, then the name.
    ///   3. **A trailing DNS-SD service suffix.** A browse reply's `serviceName` is the
    ///      bare instance label, but the same name reaches this function in fullname
    ///      form — `"AA0F330127A2@Mac Studio de Jose._raop._tcp.local."` — from a
    ///      resolve reply's `fullname`, from avahi's command-line output, and from every
    ///      captured fixture anyone will ever hand it. Leaving the suffix on turns a
    ///      device name into a protocol string in the device list.
    ///   4. **avahi `_workstation` suffix.** Linux hosts running avahi publish
    ///      `"host [aa:bb:cc:dd:ee:ff]"`, appending the MAC so two machines with the
    ///      same host name do not collide. Useful to avahi, noise to a reader.
    ///
    /// Applied in that order, and unconditionally rather than per service type: a
    /// device that publishes the `_raop` form under some other type still wants the
    /// prefix gone, and none of the three patterns can match an ordinary name by
    /// accident. Returns nil when nothing readable survives, which is a real case —
    /// an instance name that is ONLY a hardware prefix is not a name.
    public static func cleanInstanceName(_ raw: String) -> String? {
        var text = raw.trimmed
        text = strippingRAOPPrefix(text)
        text = strippingSleepProxyPrefix(text)
        text = strippingServiceSuffix(text)
        text = strippingTrailingMAC(text)
        let cleaned = text.trimmed
        return cleaned.isEmpty ? nil : cleaned
    }

    /// Cuts a `HEXMAC@` prefix — twelve hex digits then an at-sign.
    ///
    /// The length is checked exactly. A name that merely contains an `@` — an email
    /// address, or `user@host` — has to keep it, so a loose "everything before the
    /// first @" rule would truncate real names.
    static func strippingRAOPPrefix(_ text: String) -> String {
        guard let at = text.firstIndex(of: "@") else { return text }
        let prefix = text[text.startIndex..<at]
        guard prefix.count == 12, prefix.allSatisfy(\.isHexDigit) else { return text }
        return String(text[text.index(after: at)...])
    }

    /// Cuts a sleep-proxy `xx-xx-xx-xx.N ` prefix.
    ///
    /// Four hyphen-separated hex pairs, a dot, at least one digit, then a space. The
    /// leading group is the proxy's own metric and sequence rather than anything about
    /// the device, and the whole thing changes when the proxy restarts — so leaving it
    /// on would also make the name unstable across scans, not merely ugly.
    static func strippingSleepProxyPrefix(_ text: String) -> String {
        // The prefix may be followed by a name, or be the whole string — a sleep proxy
        // republishing a record whose name it never learned. The second case must clean
        // to NOTHING rather than to the prefix: `"70-35-60-63.1"` in a device list is a
        // proxy's internal bookkeeping presented as the device's identity.
        let space = text.firstIndex(of: " ")
        let head = space.map { text[text.startIndex..<$0] } ?? Substring(text)
        guard let dot = head.lastIndex(of: ".") else { return text }
        let groups = head[head.startIndex..<dot].split(separator: "-", omittingEmptySubsequences: false)
        let sequence = head[head.index(after: dot)...]
        guard groups.count == 4,
              groups.allSatisfy({ $0.count == 2 && $0.allSatisfy(\.isHexDigit) }),
              !sequence.isEmpty, sequence.allSatisfy(\.isNumber)
        else { return text }
        guard let space else { return "" }
        return String(text[text.index(after: space)...])
    }

    /// Cuts a trailing `._service._tcp.local.` suffix.
    ///
    /// Anchored on `._tcp.` or `._udp.` and then walked BACK to the start of the service
    /// label, because that label is what has to go too: cutting at `._tcp.` alone would
    /// leave `"Mac Studio de Jose._raop"`. Only a suffix is considered, so a name with a
    /// dot in it — and Bonjour instance names may contain dots — keeps everything before
    /// the service label.
    static func strippingServiceSuffix(_ text: String) -> String {
        // Searched case-insensitively IN `text` ITSELF, never in a lowercased copy.
        //
        // The copy version of this crashed, and the reason is worth stating because it
        // is not obvious and it is not rare. `lowercased()` DOES NOT PRESERVE LENGTH:
        // `İ` (U+0130) lowercases to two scalars, `K` (U+212A KELVIN SIGN) to one that
        // encodes shorter, `ẞ` to `ß`. A `Range<String.Index>` computed against the
        // lowered copy and then used to slice the original is an index into a different
        // string — so a device advertising `"İstanbul Ofis._smb._tcp.local."` produced
        // an index past the end of `text` and trapped, inside a task-group child, on
        // nothing worse than a device with a Turkish name. Staying in one string is what
        // every other function in this file already does.
        guard let marker = text.range(of: "._tcp.", options: .caseInsensitive)
                ?? text.range(of: "._udp.", options: .caseInsensitive)
                ?? text.range(of: "._tcp", options: .caseInsensitive)
                ?? text.range(of: "._udp", options: .caseInsensitive)
        else { return text }
        // Everything after the marker must be the domain — `local`, `local.`, or a
        // longer one — and nothing else. Otherwise this is a name that merely contains
        // the letters, not a fullname.
        let tail = text[marker.upperBound...]
        guard tail.isEmpty || tail.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" })
        else { return text }
        // Walk back to the dot that begins the service label — `._raop` — since the
        // label goes with the suffix.
        let head = text[text.startIndex..<marker.lowerBound]
        guard let labelStart = head.lastIndex(of: "."),
              head.index(after: labelStart) < head.endIndex,
              head[head.index(after: labelStart)] == "_"
        else { return text }
        return String(head[head.startIndex..<labelStart])
    }

    /// Cuts a trailing ` [aa:bb:cc:dd:ee:ff]`.
    ///
    /// Parsed with `MACAddress`, not with a shape check, so the bracket contents have
    /// to be a real hardware address before anything is removed. A name legitimately
    /// ending in a bracketed word — `"Printer [lobby]"` — is untouched.
    static func strippingTrailingMAC(_ text: String) -> String {
        guard text.hasSuffix("]"), let open = text.lastIndex(of: "[") else { return text }
        let inner = text[text.index(after: open)..<text.index(before: text.endIndex)]
        guard MACAddress(String(inner)) != nil else { return text }
        return String(text[text.startIndex..<open]).trimmed
    }

    // ── Sighting to candidate ────────────────────────────────────────────────────

    /// The name and model a sighting offers, or nil when it offers nothing usable.
    ///
    /// The name is the type's friendly TXT key where it has one — only `_googlecast`
    /// does, and for it the TXT value is by far the better name — and the cleaned
    /// instance name otherwise. The model comes from `model(fromTXT:)` regardless of
    /// which won, because a record can supply a model without supplying a better name.
    public static func candidate(from sighting: ServiceSighting) -> NameCandidate? {
        let type = serviceType(sighting.serviceType)
        let model = model(fromTXT: sighting.txt, serviceType: sighting.serviceType)
        let friendly = type?.friendlyNameKey
            .flatMap { key in sighting.txt.first { $0.key.lowercased() == key.lowercased() }?.value }
            .map(\.trimmed)
            .flatMap { $0.isEmpty ? nil : $0 }
        guard let value = friendly ?? cleanInstanceName(sighting.instanceName) else { return nil }
        return NameCandidate(
            value: value,
            source: .mdns,
            // THE TABLE DECIDES THE RANK, never the sighting's own `rank` field. That
            // field records what the browser believed and is informational; trusting it
            // here means an unknown service type — whose sighting carries the default
            // rank of 0 — outranks `_googlecast._tcp` and wins every tie on the network.
            // A browser that has never heard of a type must not thereby declare it the
            // cleanest one available.
            rank: rank(of: sighting.serviceType),
            model: model
        )
    }
}

extension String {
    /// Whitespace and newlines trimmed from both ends.
    ///
    /// `package` rather than `public`: the platform targets parse SSDP headers and XML
    /// and need exactly this, and adding a `String.trimmed` to core's PUBLIC surface
    /// would be a general-purpose utility escaping from a package whose API is supposed
    /// to be a scan report.
    ///
    /// A local helper so this file needs no Foundation import — core must build on
    /// Linux with no more than the standard library, and `trimmingCharacters(in:)`
    /// would drag Foundation into the definition package for four lines of work.
    package var trimmed: String {
        var view = Substring(self)
        while let first = view.first, first.isWhitespace { view.removeFirst() }
        while let last = view.last, last.isWhitespace { view.removeLast() }
        return String(view)
    }
}
