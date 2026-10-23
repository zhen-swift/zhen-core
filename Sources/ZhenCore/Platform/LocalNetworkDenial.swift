// LocalNetworkDenial.swift — inferring the permission that fails silently.
//
// On current macOS, ICMP to the local network, mDNS, SSDP multicast and NetBIOS all
// require the Local Network entitlement, and denial returns ZERO RESULTS RATHER THAN
// AN ERROR. There is no API to query the grant. A bare SPM executable has no bundle,
// so the grant attaches to the terminal and never appears under the tool's own name in
// System Settings, which means a user cannot even find it to fix it.
//
// So it has to be inferred, and the inference has a good control: the kernel's
// neighbour table is readable without the permission. A sweep that heard nothing while
// the ARP cache holds live entries is the signature — the machine has demonstrably
// been talking to those hosts, and our probes to them got nothing back.
//
// This lives in core because it is pure arithmetic over two numbers the platform
// already has, and because the platform target should not be where a user-facing
// string gets written.
//
// The heuristic is a heuristic and the string says so. Claiming certainty about a
// permission we cannot query is the kind of small lie that erodes trust in everything
// else the tool reports — and the alternative explanation, a genuinely empty network,
// is one a user can distinguish and we cannot.

/// Where the platform should point a user whose sweep heard nothing.
///
/// Core states the observation; the platform supplies the remedy. That split exists
/// because the remedy is the one genuinely OS-specific part of this, and core must run
/// on Linux — a package that unconditionally tells every user to open "Privacy &
/// Security › Local Network" is wrong on Linux, wrong on Windows later, and
/// embarrassing in a tool whose whole pitch is that it does not guess.
///
/// Extending this is how a new platform gets a remedy: a case here, a string below,
/// and no conditional compilation anywhere.
public enum ProbePermissionAdvice: Sendable, Hashable, CaseIterable {
    /// No platform-specific guidance. The degradation reports the observation only.
    /// This is the default, because a wrong instruction is worse than none.
    case unspecified
    /// Apple platforms: the Local Network privacy grant, which cannot be queried and
    /// returns zero results rather than an error when denied.
    case appleLocalNetwork
    /// Apple platforms, inside an app bundle: the same grant, without the sentence about
    /// command-line builds.
    ///
    /// `appleLocalNetwork` ends by warning that a command-line build has no bundle of its
    /// own, so the grant may be listed under the terminal. True for `zhen`, and wrong in an
    /// app — which has a bundle, and is listed under its own name. The app was deleting
    /// that sentence from this text at runtime, which is a consumer re-wording a finding;
    /// the right fix is for the finding to be worded for where it is read.
    case appleLocalNetworkInApp
    /// iPadOS: the same grant, which lives in Settings rather than System Settings and is
    /// always listed under the app, because on iPadOS everything that probes is one.
    case appleLocalNetworkOnIPad
    /// Linux: unprivileged ICMP datagram sockets are gated by a sysctl, and a user
    /// outside the permitted group range gets silence in much the same way.
    case linuxPingGroupRange

    /// The remedy sentence, or nil when there is nothing platform-specific to say.
    public var remedy: String? {
        switch self {
        case .unspecified:
            nil
        case .appleLocalNetwork:
            """
            On macOS this is usually the Local Network privacy permission, which cannot \
            be checked directly — grant it under Privacy & Security › Local Network. A \
            command-line build has no bundle of its own, so the grant may be listed \
            under the terminal application rather than under this tool.
            """
        case .appleLocalNetworkInApp:
            """
            On macOS this is usually the Local Network privacy permission, which cannot \
            be checked directly — grant it under Privacy & Security › Local Network, where \
            this app is listed under its own name.
            """
        case .appleLocalNetworkOnIPad:
            """
            On iPadOS this is usually the Local Network privacy permission, which cannot \
            be checked directly — turn it on under Settings › Privacy & Security › Local \
            Network, where this app is listed under its own name.
            """
        case .linuxPingGroupRange:
            """
            On Linux, unprivileged ICMP needs this user's group to fall within \
            net.ipv4.ping_group_range; check it with \
            `sysctl net.ipv4.ping_group_range`. A local firewall may also be dropping \
            the replies.
            """
        }
    }
}

/// Infers whether a silent sweep is explained by a denied probing permission.
public enum LocalNetworkDenialHeuristic {
    /// Decides whether to raise a degradation after a discovery stage.
    ///
    /// - Parameters:
    ///   - repliesSeen: replies the sweep received.
    ///   - probesSent: probes it sent. Zero probes means the stage never ran, which is
    ///     a different problem and not this one.
    ///   - neighborEntries: complete entries in the kernel's neighbour table for the
    ///     scanned network.
    ///   - advice: platform-specific remediation, supplied by the platform target.
    ///     Defaults to none, so core never asserts an OS it cannot see.
    /// - Returns: a degradation to attach to the run, or nil when there is nothing to
    ///   explain.
    public static func evaluate(
        repliesSeen: Int,
        probesSent: Int,
        neighborEntries: Int,
        advice: ProbePermissionAdvice = .unspecified
    ) -> Degradation? {
        guard probesSent > 0, repliesSeen == 0, neighborEntries > 0 else { return nil }
        // The observation, which is true on every platform and is the part we actually
        // measured. Note "likely cause" — the permission cannot be queried, and
        // claiming certainty about something deduced is the kind of small lie that
        // erodes trust in everything else the tool reports.
        var reason = """
            No host answered a probe, but the system's neighbour table lists \
            \(neighborEntries) device\(neighborEntries == 1 ? "" : "s") on this network. \
            Something is most likely blocking this tool from probing the local network; \
            that is a likely cause rather than a confirmed one.
            """
        if let remedy = advice.remedy {
            reason += " " + remedy
        }
        return Degradation(stage: .discovery, reason: reason, recoverable: false)
    }
}


/// What one name source did during a scan.
public struct NameSourceActivity: Sendable, Hashable {
    /// Which source this describes.
    public var source: NameSource
    /// How many answers it received. Zero is the interesting value.
    public var answered: Int
    /// Whether the source reported a failure of its own.
    ///
    /// The load-bearing field. A source that FAILED has already explained its own
    /// silence, and a second explanation blaming something else is not extra
    /// information — it is a contradiction the user has no way to resolve.
    public var failed: Bool

    /// Creates a value from its fields. Each one is documented on the property it sets.
    public init(source: NameSource, answered: Int, failed: Bool) {
        self.source = source
        self.answered = answered
        self.failed = failed
    }
}

/// Infers whether a silent naming stage is explained by a denied probing permission.
///
/// The naming-stage sibling of `LocalNetworkDenialHeuristic`, and it exists as its own
/// pure type for the same two reasons: the arithmetic is testable without a network, and
/// the user-facing string does not belong in a platform target.
///
/// It is also the place where this project came closest to lying to a user, so the
/// guards are worth stating plainly. An earlier version asserted, in confident prose,
/// that "no device answered Bonjour, UPnP or NetBIOS" and pointed at the Local Network
/// privacy setting. It did that:
///
///   * when SSDP and NetBIOS had been switched OFF and never asked anything, so
///     two-thirds of the sentence described sources that did not run; and
///   * when mDNSResponder had restarted mid-scan and killed every browse — which a VPN
///     connecting or a network-location change causes routinely — so the true cause was
///     a transient system failure and we sent the user to change a privacy setting that
///     was never the problem.
///
/// Both are worse than saying nothing. A degradation is read as a finding.
public enum NameSourceSilenceHeuristic {
    /// Decides whether to raise a degradation after the naming stage.
    ///
    /// - Parameters:
    ///   - activity: one entry per source that ACTUALLY RAN. A source that was disabled
    ///     must not appear, because the message is built from this list and naming a
    ///     source that was never asked is simply false.
    ///   - hostsProbed: how many hosts the stage was asked about. Zero means there was
    ///     nothing to name, which is not evidence of anything.
    ///   - advice: platform-specific remediation, supplied by the platform target.
    /// - Returns: a degradation, or nil when there is nothing to explain or nothing that
    ///   can honestly be said.
    public static func evaluate(
        _ activity: [NameSourceActivity],
        hostsProbed: Int,
        advice: ProbePermissionAdvice = .unspecified
    ) -> Degradation? {
        guard hostsProbed > 0, !activity.isEmpty else { return nil }
        // Somebody answered, so the sources are working and there is nothing to explain.
        guard activity.allSatisfy({ $0.answered == 0 }) else { return nil }
        // A source that failed has already said why it is silent. Blaming the permission
        // over the top of its own error message is the lie this guard exists to prevent.
        guard !activity.contains(where: \.failed) else { return nil }

        let names = activity.map(\.source.label).sorted()
        let list: String
        switch names.count {
        case 1: list = names[0]
        case 2: list = "\(names[0]) or \(names[1])"
        default: list = names.dropLast().joined(separator: ", ") + " or " + names[names.count - 1]
        }
        var reason = """
            No device answered \(list), so no names could be read this scan and every device \
            is reported by address alone.
            """
        if let remedy = advice.remedy {
            reason += " " + remedy
        }
        // Said out loud, because the alternative explanation — a network on which
        // genuinely nothing advertises a name — is one the user can distinguish and we
        // cannot.
        reason += """
             That is a likely cause rather than a confirmed one: a network on which \
            nothing advertises a name looks identical from here.
            """
        return Degradation(stage: .naming, reason: reason, recoverable: false)
    }
}
