// Gate G0 of the 0.8.0 brief — the spike, kept so the answer can be re-measured.
//
// Question: does a PF_ROUTE socket on macOS 26 deliver a message when an ARP entry
// resolves (RTM_ADD / RTM_RESOLVE / RTM_CHANGE for an RTF_LLINFO route), to an
// UNPRIVILEGED process?
//
// Run, as an ordinary user, while something triggers ARP for a live address that is not
// in the cache (a ping is enough):
//
//     swift Docs/process/0.8.0-spike-route-socket.swift 6 > dump.txt &
//     ping -c1 -t1 <a live LAN address not in `arp -an`>
//
// The argument is how many seconds to listen. Every message is printed with its type,
// flags, destination and link-layer address, followed by its raw bytes in hex. The raw
// bytes are also appended to `route-socket.bin` in the working directory, so they can be
// committed as a parser fixture.
import Darwin
import Foundation

let seconds = CommandLine.arguments.count > 1 ? Int(CommandLine.arguments[1]) ?? 6 : 6
// Second argument: the socket's protocol filter. AF_INET (2, the default) or 0 (every family).
let family = CommandLine.arguments.count > 2 ? Int32(CommandLine.arguments[2]) ?? AF_INET : AF_INET
// Third argument, optional: an IPv4 address to send an RTM_GET for, which proves the socket
// is live — the kernel echoes a request back to its own sender whatever the privileges.
let probe = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : nil
let fd = socket(PF_ROUTE, SOCK_RAW, family)
guard fd >= 0 else {
  print("socket(PF_ROUTE) failed: errno \(errno) \(String(cString: strerror(errno)))")
  exit(1)
}
print("socket(PF_ROUTE, SOCK_RAW, \(family)) = \(fd), uid \(getuid()), euid \(geteuid())")
var timeout = timeval(tv_sec: 0, tv_usec: 200_000)
_ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

let names: [Int32: String] = [
  RTM_ADD: "RTM_ADD", RTM_DELETE: "RTM_DELETE", RTM_CHANGE: "RTM_CHANGE",
  RTM_GET: "RTM_GET", RTM_LOSING: "RTM_LOSING", RTM_REDIRECT: "RTM_REDIRECT",
  RTM_MISS: "RTM_MISS", RTM_LOCK: "RTM_LOCK", RTM_RESOLVE: "RTM_RESOLVE",
  RTM_NEWADDR: "RTM_NEWADDR", RTM_DELADDR: "RTM_DELADDR", RTM_IFINFO: "RTM_IFINFO",
  RTM_NEWMADDR: "RTM_NEWMADDR", RTM_DELMADDR: "RTM_DELMADDR", RTM_IFINFO2: "RTM_IFINFO2",
  RTM_NEWMADDR2: "RTM_NEWMADDR2", RTM_GET2: "RTM_GET2",
]
let flagNames: [(Int32, String)] = [
  (RTF_UP, "UP"), (RTF_GATEWAY, "GATEWAY"), (RTF_HOST, "HOST"), (RTF_REJECT, "REJECT"),
  (RTF_DYNAMIC, "DYNAMIC"), (RTF_DONE, "DONE"), (RTF_CLONING, "CLONING"),
  (RTF_LLINFO, "LLINFO"), (RTF_STATIC, "STATIC"), (RTF_WASCLONED, "WASCLONED"),
  (RTF_IFSCOPE, "IFSCOPE"), (RTF_ROUTER, "ROUTER"),
]

func u8(_ b: [UInt8], _ o: Int) -> Int { o < b.count ? Int(b[o]) : 0 }
func le16(_ b: [UInt8], _ o: Int) -> Int { u8(b, o) | u8(b, o + 1) << 8 }
func le32(_ b: [UInt8], _ o: Int) -> Int32 {
  Int32(bitPattern: UInt32(u8(b, o)) | UInt32(u8(b, o + 1)) << 8
    | UInt32(u8(b, o + 2)) << 16 | UInt32(u8(b, o + 3)) << 24)
}

let header = MemoryLayout<rt_msghdr>.size
if let probe {
  var request = [UInt8](repeating: 0, count: header + 16)
  var message = rt_msghdr()
  message.rtm_msglen = UInt16(request.count)
  message.rtm_version = UInt8(RTM_VERSION)
  message.rtm_type = UInt8(RTM_GET)
  message.rtm_addrs = RTA_DST
  message.rtm_seq = 1
  message.rtm_pid = getpid()
  withUnsafeBytes(of: &message) { raw in for i in 0..<header { request[i] = raw[i] } }
  var address = in_addr()
  inet_pton(AF_INET, probe, &address)
  request[header] = 16
  request[header + 1] = UInt8(AF_INET)
  withUnsafeBytes(of: &address) { raw in for i in 0..<4 { request[header + 4 + i] = raw[i] } }
  let written = request.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
  print("RTM_GET \(probe) written: \(written) (errno \(written < 0 ? errno : 0))")
}
let deadline = Date().addingTimeInterval(TimeInterval(seconds))
let out = FileManager.default.currentDirectoryPath + "/route-socket.bin"
FileManager.default.createFile(atPath: out, contents: nil)
let handle = FileHandle(forWritingAtPath: out)
var count = 0
var buffer = [UInt8](repeating: 0, count: 2048)
let start = Date()
while Date() < deadline {
  let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
  guard n > 0 else { continue }
  let bytes = Array(buffer[0..<n])
  handle?.write(Data(bytes))
  count += 1
  let type = Int32(u8(bytes, 3))
  let flags = le32(bytes, 8)
  let addrs = le32(bytes, 12)
  let flagText = flagNames.filter { flags & $0.0 != 0 }.map(\.1).joined(separator: "|")
  var cursor = header
  var dst = "-", lladdr = "-"
  for slot in [RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK, RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD] {
    guard addrs & slot != 0, cursor + 2 <= bytes.count else { continue }
    let len = u8(bytes, cursor), family = Int32(u8(bytes, cursor + 1))
    if slot == RTA_DST, family == AF_INET {
      dst = (4..<8).map { String(u8(bytes, cursor + $0)) }.joined(separator: ".")
    }
    if slot == RTA_GATEWAY, family == AF_LINK {
      let nlen = u8(bytes, cursor + 5), alen = u8(bytes, cursor + 6)
      lladdr = alen == 0 ? "(incomplete, alen 0)"
        : (0..<alen).map { String(format: "%02x", u8(bytes, cursor + 8 + nlen + $0)) }.joined(separator: ":")
    }
    cursor += len == 0 ? 4 : 1 + ((len - 1) | 3)
  }
  let t = String(format: "%7.3f", Date().timeIntervalSince(start))
  print("[\(t)s] #\(count) \(names[type] ?? "type \(type)") len \(le16(bytes, 0)) index \(le16(bytes, 4)) flags \(flagText) dst \(dst) lladdr \(lladdr)")
  print("    " + bytes.map { String(format: "%02x", $0) }.joined(separator: " "))
}
print("\(count) message(s) in \(seconds) s")
