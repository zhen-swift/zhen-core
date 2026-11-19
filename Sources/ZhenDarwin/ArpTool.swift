// ArpTool.swift — the neighbour table through Apple's `arp`, when the kernel hands this process none.
//
// macOS 27 withholds the link-layer table from a binary that is not Apple's. The sysctl
// `DarwinNeighborCache` reads (`NET_RT_FLAGS` / `RTF_LLINFO`) sizes the dump at 0 bytes for
// zhen, and for a twenty-line C program making the same call, while `/usr/sbin/arp -an`,
// run beside them in the same session, lists every entry with its hardware address.
// Measured on macOS 27.2 and 27.2.1, 2026-11-19, from a terminal, from SSH and from a
// launchd job alike. `arp` carries no entitlement; what differs is whose signature it has.
//
// So when the sysctl comes back empty, the table is read by running `arp`. The cost is one
// process per read — a few milliseconds — and the snapshot says which source it came from,
// so an artifact never passes one off as the other.
#if os(macOS)

import Darwin
import ZhenCore

/// Reads the IPv4 neighbour table by running `/usr/sbin/arp -an`.
enum ArpTool {
    /// The tool. Absolute, so no `PATH` decides which `arp` runs.
    static let path = "/usr/sbin/arp"
    /// How a snapshot read this way names its source.
    static let source = "arp_tool"

    /// The entries `arp -an` lists, decoded as `DarwinNeighborCache.decode` decodes the kernel's.
    static func entries() throws(PlatformError) -> [NeighborEntry] {
        parse(try output())
    }

    /// Decodes `arp -an` output.
    ///
    /// One line per entry:
    ///
    ///     ? (192.168.64.2) at 52:55:55:ab:97:99 on bridge100 ifscope [bridge]
    ///     ? (192.168.64.3) at (incomplete) on bridge100 ifscope [bridge]
    ///     ? (192.168.64.1) at ca:80:6d:74:ed:64 on bridge100 ifscope permanent [bridge]
    ///
    /// The same rules as the kernel decoder: multicast addresses and multicast hardware
    /// addresses (which includes the broadcast entry) are link-layer plumbing and are
    /// dropped; an incomplete entry is kept and marked, as evidence of absence; the first
    /// entry for an address wins. `permanent` is how `arp` prints an entry with no expiry,
    /// which is what `RTF_STATIC` marks in the kernel's.
    static func parse(_ text: String) -> [NeighborEntry] {
        var seen: Set<IPv4Address> = []
        var entries: [NeighborEntry] = []
        for line in text.split(separator: "\n") {
            guard let open = line.firstIndex(of: "("), let close = line.firstIndex(of: ")"), open < close,
                  let ip = IPv4Address(String(line[line.index(after: open)..<close])), !ip.isMulticast
            else { continue }
            let words = line[line.index(after: close)...].split(separator: " ")
            guard words.count >= 2, words[0] == "at" else { continue }
            if words[1] == "(incomplete)" {
                if seen.insert(ip).inserted {
                    entries.append(NeighborEntry(ip: ip, mac: MACAddress(raw: 0),
                                                 isComplete: false, isPermanent: false))
                }
                continue
            }
            guard let mac = MACAddress(String(words[1])), !mac.isMulticast else { continue }
            guard seen.insert(ip).inserted else { continue }
            entries.append(NeighborEntry(ip: ip, mac: mac, isComplete: true,
                                         isPermanent: words.contains("permanent")))
        }
        return entries.sorted { $0.ip < $1.ip }
    }

    /// Runs `arp -an` and returns what it printed.
    ///
    /// `posix_spawn`, not Foundation's `Process`: this target does not import Foundation.
    /// The child inherits nothing but its three standard descriptors
    /// (`POSIX_SPAWN_CLOEXEC_DEFAULT`), so no socket of the scan leaks into it, and gets an
    /// empty environment.
    static func output() throws(PlatformError) -> String {
        var fds: [Int32] = [-1, -1]
        // SAFETY: `fds` holds the two descriptors pipe(2) writes.
        guard unsafe pipe(&fds) == 0 else { throw PlatformError.syscall("pipe for arp") }
        let (readEnd, writeEnd) = (fds[0], fds[1])

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        // SAFETY: initialised here, destroyed on every path out by the defer.
        unsafe posix_spawn_file_actions_init(&actions)
        unsafe posix_spawnattr_init(&attributes)
        defer {
            unsafe posix_spawn_file_actions_destroy(&actions)
            unsafe posix_spawnattr_destroy(&attributes)
        }
        unsafe posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))
        unsafe posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        unsafe posix_spawn_file_actions_adddup2(&actions, writeEnd, STDOUT_FILENO)
        unsafe posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)

        var pid: pid_t = 0
        // SAFETY: argv and envp are NULL-terminated arrays of C strings that outlive the
        // call (strdup'd, freed after it); posix_spawn copies them into the child.
        let argv: [UnsafeMutablePointer<CChar>?] = unsafe [strdup(path), strdup("-an"), nil]
        let envp: [UnsafeMutablePointer<CChar>?] = [nil]
        let spawned = unsafe posix_spawn(&pid, path, &actions, &attributes, argv, envp)
        for pointer in unsafe argv { unsafe free(pointer) }
        close(writeEnd)
        guard spawned == 0 else {
            close(readEnd)
            throw PlatformError.syscall("posix_spawn(\(path))")
        }

        var bytes: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 16_384)
        while true {
            // SAFETY: reads at most `chunk.count` bytes into `chunk`'s own storage.
            let count = unsafe chunk.withUnsafeMutableBytes { unsafe read(readEnd, $0.baseAddress, $0.count) }
            if count > 0 {
                bytes.append(contentsOf: chunk[0..<count])
            } else if count == 0 || errno != EINTR {
                break
            }
        }
        close(readEnd)

        var status: Int32 = 0
        // SAFETY: `status` is the out-parameter waitpid(2) writes.
        while unsafe waitpid(pid, &status, 0) == -1 && errno == EINTR {}
        // WIFEXITED / WEXITSTATUS are macros Swift does not import.
        guard status & 0x7F == 0, (status >> 8) & 0xFF == 0 else {
            throw PlatformError.unavailable("\(path) -an did not exit cleanly (status \(status)).")
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

#endif
