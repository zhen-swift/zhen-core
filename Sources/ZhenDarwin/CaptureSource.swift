// CaptureSource.swift — where a capture device comes from, as far as an engine knows.
//
// ── The engines must not learn that a helper exists ────────────────────────────
//
// `BPFSweep`, `SYNScan` and `OSFingerprintProbe` each need a configured `/dev/bpf*`
// descriptor and have no business knowing how one was obtained. Under `sudo` it is an
// `open` in this process; with the helper installed it is an `open` in a root daemon and
// a descriptor passed back over XPC. The frames on the wire are identical either way,
// which is the entire claim the helper makes.
//
// So this is a closure in a box rather than an enum. An enum with a `.helper` case would
// put the word "helper" in three engines that should never be able to branch on it, and
// the first time somebody needed a third route they would branch on it. What an engine
// holds is a thing it can ask for a device, and there is nothing else it can do with it.
//
// ── Why the policy is chosen by the caller rather than discovered here ──────────
//
// The command line is a measured binary. Study 2 has a gate requiring its unprivileged
// discovery path to be behaviourally unchanged from the tag study 1 measured, and a
// helper probe on the startup path of every unprivileged scan is a behaviour change
// whether or not it finds anything. So the command line asks for `.directOnly` and gets
// precisely the composition it had before this file existed, while the app — which is
// the thing a helper is for — asks for `.helperThenDirect`.
// macOS only. iOS has no `/dev/bpf*` and its SDK no `<net/bpf.h>`, so on iPadOS this
// layer is absent and the scanner composes without it (see `DarwinScanner.make`).
#if os(macOS)

import CBPFShim
import Darwin
import ZhenPrivilege

/// A way to obtain a configured capture device.
public struct CaptureSource: Sendable {
    private let acquire: @Sendable (String, [bpf_insn], Duration) async -> Result<BPFDevice, BPFUnavailable>

    /// Internal rather than private so a test can build a source that records the bound
    /// it was handed, which is the only way to see which one `probe` passes without a
    /// helper to time.
    init(
        acquire: @escaping @Sendable (String, [bpf_insn], Duration) async -> Result<BPFDevice, BPFUnavailable>
    ) {
        self.acquire = acquire
    }

    /// Opens a device, or says why it could not.
    ///
    /// Internal, because `BPFDevice` is. Outside this module a `CaptureSource` is an
    /// opaque token you hand to an engine, which is all a caller should be able to do
    /// with one.
    ///
    /// - Parameter timeout: how long a helper may take to answer. The acquisition bound
    ///   unless the caller is only asking whether one is there; a direct open ignores it.
    func open(
        interface: String, filter: [bpf_insn],
        timeout: Duration = HelperClient.acquisitionTimeout
    ) async throws(BPFUnavailable) -> BPFDevice {
        switch await acquire(interface, filter, timeout) {
        case .success(let device): return device
        case .failure(let error): throw error
        }
    }

    /// `/dev/bpf*` in this process.
    public static let direct = CaptureSource { interface, filter, _ in
        do {
            return .success(try BPFDevice.open(interface: interface, filter: filter))
        } catch let error as BPFUnavailable {
            return .failure(error)
        } catch {
            return .failure(.configurationFailed("\(error)"))
        }
    }

    /// The privileged helper, and nothing else. Used once a direct open has been tried.
    public static let helper = CaptureSource { interface, filter, timeout in
        do {
            return .success(try await BPFDevice.openViaHelper(
                interface: interface, filter: filter, timeout: timeout))
        } catch let error as BPFUnavailable {
            return .failure(error)
        } catch {
            return .failure(.helperRefused("\(error)"))
        }
    }

    /// A direct open, falling back to the helper.
    ///
    /// The refusal reported on failure is the HELPER's, not the direct open's. Under an
    /// unprivileged app the direct open always fails with `.notPrivileged`, which is
    /// both true and useless — "you are not root" is not what a person who installed a
    /// helper needs to read. What went wrong with the helper is.
    public static let preferred = CaptureSource { interface, filter, timeout in
        if let device = try? BPFDevice.open(interface: interface, filter: filter) {
            return .success(device)
        }
        do {
            return .success(try await BPFDevice.openViaHelper(
                interface: interface, filter: filter, timeout: timeout))
        } catch let error as BPFUnavailable {
            return .failure(error)
        } catch {
            return .failure(.helperRefused("\(error)"))
        }
    }

    /// The source a policy selects.
    public static func source(for policy: CapturePolicy) -> CaptureSource {
        switch policy {
        case .directOnly: .direct
        case .helperThenDirect: .preferred
        }
    }

    /// Whether a device can be had right now, and why not when it cannot.
    ///
    /// The composition-time question: it decides whether the privileged engines are
    /// built at all. Opening and closing a device is a real attempt rather than a guess,
    /// which is the same argument that rejected `geteuid()` — and it now covers the
    /// helper too, because "is a helper installed and approved" has exactly as many
    /// wrong answers available to a check that does not try.
    ///
    /// The helper gets `HelperClient.probeTimeout` here, not the acquisition bound: this
    /// asks whether anybody is there, and a registration launchd cannot start never says
    /// no — it just never answers. See `probeTimeout` for the 3.2 s that cost.
    func probe(interface: String) async -> BPFUnavailable? {
        do {
            let device = try await open(
                interface: interface, filter: BPFFilter.arp(),
                timeout: HelperClient.probeTimeout)
            // Closed rather than kept: the composition root runs long before the sweep,
            // and holding an exclusive-open node across a naming stage would lock out
            // the very packet capture somebody is running to check this engine's work.
            await device.stop()
            return nil
        } catch {
            return error
        }
    }
}

#endif
