# 14 · Root, but tiny: the privileged helper

![A tiny crowned tower, zhen-helper, opens the periscope once and passes the ticket to the app, which isn't root.](figures/14-hero.svg)

::: short
The short version

- Opening `/dev/bpf*` needs **root**. The Zhen app isn't root, and shouldn't be.
- So a tiny **launch daemon**, `zhen-helper`, runs as root. It does **one open plus the ten knobs** from chapter 11, then hands the **ticket** to the app.
- The ticket crosses between processes over **XPC**, which passes the file descriptor itself.
- Each side checks the other's **code signature**. Only Zhen, signed by its team, ever gets the ticket.
- "A root daemon should be small enough to read." (`BPFAcquisition.swift:9`)
:::

::: word
New word: launch daemon and XPC

A **launch daemon** is a background program that macOS's **launchd** starts as root, usually only when something calls it. **XPC** is how two processes on a Mac talk: one calls a method, and the other replies.
:::

## The pieces

![The helper and its launchd plist ship inside the app. SMAppService registers it, and you approve it in Login Items.](figures/14-pieces.svg)

- **`zhen-helper`** (`zhen-helper/main.swift`) is the daemon. It depends **only** on `ZhenPrivilege`, so a root process doing one `open` doesn't carry a TLS client and a port scanner around (`Package.swift:225-239`).
- **`ZhenPrivilege`** holds the open-and-configure code from chapter 11, the protocol and the app's side of the call. The app and the helper run **the same** acquisition code, because a second copy "would drift the first time one was corrected" (`BPFAcquisition.swift:11-14`).
- **The launchd plist**, `com.jctec.zhen.helper.plist`, sits in the app at `Contents/Library/LaunchDaemons/` (`zhen-app/Helper/com.jctec.zhen.helper.plist:17-29`):
  - `Label` and `MachServices`: the name the app calls.
  - `BundleProgram`: `Contents/MacOS/zhen-helper`.
  - `AssociatedBundleIdentifiers`: makes Login Items show "Zhen" with its icon instead of a bare label.
- **Registration** happens in the app, through `SMAppService.daemon(plistName:)` (`zhen-app/Zhen/Platform/LiveHelperService.swift:11-25`):
  - `register()` installs it and `unregister()` removes it.
  - `status` is `.notRegistered`, `.requiresApproval` (waiting for you in Login Items), `.enabled` or `.notFound`.
  - `SMAppService.openSystemSettingsLoginItems()` takes you straight to the switch.
- The Settings row asks the **running helper** for its version, because `status` "reports what was registered rather than what will answer" (`HelperClient.swift:143-147`).

## Three names, one spelling

![Label, Mach service and plist name must all be com.jctec.zhen.helper. One typo gives a misleading error 108.](figures/14-names.svg)

- The plist's **Label**, its **Mach service** name and the plist's **file name** must all be `com.jctec.zhen.helper` (`HelperProtocol.swift:40-58`).
- Get one wrong and `SMAppService` fails with **error 108, "unable to read plist"**, which "names the wrong thing and sends people to check their XML" (`HelperProtocol.swift:37-39`).
- So the name is written **once**, in `HelperIdentity`, and the app's tests check the built plist against it (`zhen-app/Helper/com.jctec.zhen.helper.plist:7-13`).

## Handing over the ticket

![The app asks; the helper checks, opens and configures; the ticket itself crosses over; the app dup()s it and adopts it.](figures/14-handoff.svg)

**The daemon** is a listener and nothing else:

- It starts an `NSXPCListener` on its Mach service and runs forever. launchd starts it **on demand** and may stop it at any time (`zhen-helper/main.swift:129-135`).
- It keeps **no state**: "a root process with no state cannot have its state corrupted" (`zhen-helper/main.swift:27-32`).

```swift
let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: HelperIdentity.label)
listener.delegate = delegate
listener.resume()
// Never returns. `launchd` starts this on demand and stops it when it is idle; there is
// no state to write out on the way down.
RunLoop.main.run()
```

[`zhen-helper/main.swift:129-135` @ 0.9.0]{.src}

**The protocol** is two methods on an `@objc` protocol (`HelperProtocol.swift:95-119`):

- `openCaptureDevice(interface:filter:reply:)`, whose reply is `(FileHandle?, Int, String?)`: the ticket, the granted buffer size, or a reason.
- `helperVersion(reply:)`, so a helper left over from an older install can say so.
- The filter travels as **8 bytes per instruction**, little-endian, written field by field. Decoding returns `nil` rather than cut it short, because a truncated filter "passes traffic the caller meant to exclude and does it silently" (`HelperProtocol.swift:121-169`).

**One request, step by step:**

1. The app calls `openCaptureDevice("en0", filter)`.
2. The helper re-checks the inputs: a name under 16 bytes made of letters, digits and dots, and a filter that decodes and isn't empty, because "an empty filter would capture the entire segment" (`zhen-helper/main.swift:60-79`).
3. It runs `BPFAcquisition.open`, the walk and the ten knobs from chapter 11 (`zhen-helper/main.swift:81-84`).
4. It replies with `FileHandle(fileDescriptor:closeOnDealloc: true)`. `NSXPCConnection` passes **the descriptor itself, not its bytes** (`HelperProtocol.swift:104-107`, `zhen-helper/main.swift:85-89`).
5. The app **`dup()`s** it, because the FileHandle closes its own copy as soon as the reply block returns (`HelperClient.swift:115-118`).
6. `BPFDevice.adopting` wraps it: "The seam the whole helper design rests on." The ARP sweep, the SYN scan and the fingerprint can't tell where the ticket came from (`BPFDevice.swift:131-143`).

```swift
// Duplicated, because the FileHandle the connection built owns its
// descriptor and closes it when it is deallocated — which happens as
// soon as this block returns. The dup is what outlives the reply.
let descriptor = dup(handle.fileDescriptor)
```

[`HelperClient.swift:115-118` @ 0.9.0]{.src}

## Checking badges both ways

![The app and the helper each check the other's signature. Any other app is turned away before it can ask for anything.](figures/14-signing.svg)

The rule is a **code-signing requirement**, one for each direction (`HelperProtocol.swift:67-88`):

```swift
public static let client = """
    identifier "\(HelperIdentity.applicationBundleIdentifier)" \
    and anchor apple generic \
    and certificate leaf[subject.OU] = "\(teamIdentifier)"
    """
```

[`HelperProtocol.swift:76-80` @ 0.9.0]{.src}

- In plain words: "this exact app, signed through Apple, by team `S8662L649U`".
- The **helper checks the app** on every connection, before reading any interface name. "The whole security argument, in one call." (`zhen-helper/main.swift:103-121`)
- macOS 12 and earlier don't have that call, so there the helper **refuses everyone** (`zhen-helper/main.swift:113-118`).
- The **app checks the helper** too. A ticket from anyone else is a view onto "traffic somebody else chose" (`HelperClient.swift:71-77`).

::: word
New word: code-signing requirement

A **code-signing requirement** is a small rule about who signed a program, such as "identifier X, Apple-issued certificate, team Y". macOS checks the other process against it before any message gets through.
:::

## Try each rung

![The zhen command opens BPF itself or goes unprivileged. The app tries a direct open, then the helper, then goes unprivileged.](figures/14-ladder.svg)

"Decided by attempting, never by asking who we are" (`DarwinScanner.swift:97-103`):

- Root with Wireshark holding every node has **no** capture ability.
- A Mac with a ChmodBPF-style daemon gives an ordinary user **root's** ability.

Two policies (`CapturePolicy.swift`, `CaptureSource.swift`):

- **`.directOnly`**, used by the `zhen` command: exactly what it did before the helper existed, because it's the binary the study measures (`CapturePolicy.swift:12-17`, `ScannerFactory.swift:83`).
- **`.helperThenDirect`**, used by the app. Despite its name, it tries a **direct open first**, then the helper, so a `sudo` run never depends on the daemon (`CapturePolicy.swift:19-26`, `CaptureSource.swift:92-104`).
- Whenever a rung fails, the scan steps down to the unprivileged engines. Nothing hard-fails.

**How the app asks** (`HelperClient.swift`):

- **A new connection per request**, with the `.privileged` option for reaching a launch daemon (`HelperClient.swift:65-67`). Removing the helper is a button in Settings, so a long-held connection would always need re-checking (`HelperClient.swift:13-18`).
- **Two stopwatches:** 3 s for a real request, 750 ms for "is anyone there?". A broken registration accepts the connection and **never answers**, and that once cost 3.2 s at every launch (`HelperClient.swift:33-51`).
- **Exactly one answer wins.** A reply, an error, an invalidation and the timeout can all fire. `Resumption` lets only the first through, because resuming twice is a crash (`HelperClient.swift:79-82`, `:216-240`).
- **Invalidated before any reply** means `helperAbsent`. That's the normal state for most people, so it isn't reported as a problem (`HelperClient.swift:84-87`).

## The weakness Zhen accepts

![FreeBSD can lock a handed-over periscope. Darwin can't, so only Zhen's signed app may ever receive one.](figures/14-bioclock.svg)

- FreeBSD can freeze a BPF ticket with `BIOCLOCK` before handing it over. **Darwin has no `BIOCLOCK`** (`HelperProtocol.swift:17-21`).
- So whoever holds the ticket can re-filter, or even turn on promiscuous mode. Handing it out is "granting full local packet capture, permanently, to whatever is on the other end of that connection" (`04-privileged-helper.md:149-153`).
- That's why the signing check is **mandatory, on every connection**. It's also why the app may send its own filter: it could change it afterwards anyway (`HelperProtocol.swift:23-30`).
- **Rejected:** running the sweeps inside the helper. The wall would be stronger, but the ARP sweep, the SYN scan and the fingerprint would move into root, "roughly tripling what runs as root" (`04-privileged-helper.md:163-168`).

**Measured on the wire** (`04-privileged-helper.md:32-44`):

| Run | ARP requests per address |
|---|---|
| App, sweep off | 1.01 |
| App, sweep through the helper | 3.17 |
| `sudo zhen`, for comparison | 3.96 |

The kernel ARPs each address once, and the sweep asks up to three times. An app running as an ordinary user now looks like `sudo` on the wire, "which is the claim the whole design rests on".

**How it ships:**

- **Unsandboxed, Developer ID**, not the Mac App Store. The App Sandbox has no entitlement that covers BPF (`SPEC.md:495-499`).
- **Not notarized yet.** `spctl` says "Unnotarized Developer ID", so on another Mac the first launch is blocked, and with it the button that installs the helper (`04-privileged-helper.md:52-63`).

::: honest
🔍 Honest note: `sudo zhen` stays root

`SPEC.md:506-520` says: run under `sudo`, open BPF at startup, then `setgid` and `setuid` to drop root for good, shrinking the root window to "a handful of startup syscalls".

- No code in `Sources/` calls `setuid`, `setgid` or `seteuid`.
- `PrivilegeBroker` says that mechanism "lives in the platform target" (`PlatformSeam.swift:464-470`). Nothing implements it, and the spec's `SudoPrivilegeBroker` and `DeniedPrivilegeBroker` (`SPEC.md:545-551`) don't exist.
- BPF isn't opened once at startup either. Each engine opens its own device when it runs.

So **`sudo zhen` runs as root for the whole scan**. The helper is the path that keeps root small.
:::

::: iphone
📱 On iPhone & iPad

- ❌ **No root, and no launch daemons for apps.** iOS has no third-party Mach services and no `SMAppService.daemon` (`HelperClient.swift:19-20`).
- ❌ **Nothing to open anyway.** There's no `/dev/bpf*` (chapter 11).
- ❌ `HelperClient` is macOS only (`HelperClient.swift:19-21`). The `zhen-helper` target still builds elsewhere, into a stub that explains itself and exits with **69**, `EX_UNAVAILABLE` (`zhen-helper/main.swift:137-155`).
- ✅ Nothing to install and nothing to approve: an iPad always runs the unprivileged scan.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Three names that disagree** give error 108, which blames the XML.
- **Forgetting `dup()`.** The FileHandle closes your ticket when the reply ends.
- **Resuming twice.** NSXPC can fire more than one handler, and a second resume crashes.
- **Waiting forever.** A broken registration accepts and never answers, so always use a timeout.
- **Trusting `SMAppService.status`.** It says what was registered, not what will answer.
- **Asking `geteuid()`.** It's wrong in both directions.
:::

::: remember
🧠 Remember

- Root does one job: open and configure `/dev/bpf`, then hand the ticket over XPC.
- Both sides check signatures on every connection, because a Darwin BPF ticket can't be locked.
- The app tries a direct open, then the helper, then unprivileged, and finds out **by trying**.
:::
