# 2 · Everything is a ticket

![The kernel keeps the real thing. You get a number.](figures/02-hero.svg)

::: short
The short version

- When your app asks the kernel for a socket, a file or a device, the kernel **keeps the real thing**.
- What you get back is a small whole number, a **file descriptor**. This book calls it a **ticket**.
- Every later request says "do this with ticket 3": `read(3…)`, `send(3…)`, `close(3)`.
- When a request fails, the answer is `-1`, and the reason is in a variable called **`errno`**.
- There's a limit to how many tickets one app can hold. Zhen asks for as many as it can get, and sizes its scans to fit.
:::

## Your app's wallet

![Every app starts with tickets 0, 1 and 2. Each socket Zhen opens gets the next free number.](figures/02-wallet.svg)

- **0, 1, 2** are there from birth: keyboard in, screen out, errors out.
- **3 and up** are whatever the app opens. In Zhen, that's mostly sockets:
  - **one** ICMP socket for the whole ping sweep (chapter 5)
  - **one per port** for a TCP knock (chapter 6), which can mean hundreds at once
- A ticket is **just a number**. It isn't the socket. If you lose the number, you can't reach the socket; if you keep a number after giving it back, it may now point at something else.

::: word
New word: system call

A **system call** (syscall) is a door in the castle wall: a request from your app to the kernel. `socket`, `close`, `read`, `getrlimit`: each is one door. Chapter 1 has the castle picture.
:::

## When the door says no

![A failed call returns -1. The reason is in errno.](figures/02-errno.svg)

1. Almost every door returns **`-1`** when it fails.
2. The reason is a number in **`errno`**, for example 13 = `EACCES`, "not allowed".
3. **Read `errno` straight away.** The very next call may overwrite it.

Zhen turns the most common reasons into three kinds of error:

| errno | meaning | Zhen calls it |
|---|---|---|
| `EPERM`, `EACCES` | not allowed | `.denied` |
| `ENOENT`, `ENXIO`, `ENODEV` | nothing there | `.notFound` |
| anything else | something else | `.systemError(code:)` |

```swift
static func syscall(_ api: String) -> PlatformError {
    // Read immediately after the failed call, before anything else can clobber it.
    let code = errno
    switch code {
    case EPERM, EACCES:
        return .denied("\(api) was refused (errno \(code))")
```

[`DarwinPlatform.swift:42-47` @ 0.9.0]{.src}

## The double-close trap

![Close a ticket twice and you can close someone else's connection.](figures/02-reuse.svg)

- `close(5)` gives ticket 5 **back**. The kernel can hand **5** to the very next `socket()`, from any part of the app.
- If old code calls `close(5)` **again**, it closes the **new** owner's socket. Nothing crashes; a connection somewhere just stops.
- That's why Zhen's rule is **exactly one owner closes each ticket**:
  - The ICMP socket keeps a flag, `sourceOwnsDescriptor`, so that only one of two places ever closes it (`ICMPSocket.swift:73`).
  - Sockets that wait for an answer are closed **only** inside their cancel handler (chapter 4).

```swift
public static func close(_ raw: Int32) {
    // … between two closes another thread can open a socket and be handed
    // the same number, and the second close then tears down an unrelated
    // connection.
    _ = Darwin.close(raw)
}
```

[`DarwinPlatform.swift:20-27` @ 0.9.0 (comment shortened)]{.src}

## How many tickets can I have?

![The rule says "nearly infinite". The kernel says 92,160. Zhen believes the kernel.](figures/02-limits.svg)

There are **two** limits, and they disagree:

1. **`RLIMIT_NOFILE`**, the app's own rule. Read it with `getrlimit` and raise it with `setrlimit`.
2. **`kern.maxfilesperproc`**, the kernel's real ceiling for one app. Read it with `sysctlbyname`.

On the Mac the code was written on, the rule claimed **9,223,372,036,854,775,807** and the kernel actually gave **92,160**.

So Zhen raises its limit like this:

1. Read the current rule (`getrlimit`).
2. Read the real ceiling (`sysctlbyname("kern.maxfilesperproc")`).
3. Ask for the **smaller** of the two (`setrlimit`).
4. If the kernel says no, **halve the request** and try again.
5. Report what was **actually granted**, never what was asked for.

```swift
guard unsafe getrlimit(RLIMIT_NOFILE, &limits) == 0 else { return 256 }
let ceiling = Self.perProcessCeiling()        // kern.maxfilesperproc
var wanted = min(Self.clamp(limits.rlim_max), ceiling)
while wanted > Self.clamp(limits.rlim_cur) {
    var attempt = limits
    attempt.rlim_cur = rlim_t(wanted)
    if unsafe setrlimit(RLIMIT_NOFILE, &attempt) == 0 { break }
    wanted /= 2
}
```

[`DarwinPlatform.swift:86-97` @ 0.9.0 (comments trimmed)]{.src}

**From tickets to speed.** The number granted becomes the scan's width: **probes in flight = min(512, tickets ÷ 4)** (`FanOut.swift:105-107`). These are the first syscalls of every scan (`DarwinScanner.swift:83-84`), on the Mac and on the iPhone alike.

::: word
New word: `unsafe`

The `unsafe` in the code above isn't a warning about the code. zhen-core turns on Swift's **strict memory safety**, so every place that hands a pointer to the kernel must be **marked** `unsafe`. That way, `grep unsafe` gives a short list of exactly where Swift meets C.
:::

::: iphone
📱 On iPhone & iPad

- ✅ Tickets, `errno`, `close`: identical. It's the same BSD layer of Darwin.
- ✅ `getrlimit` / `setrlimit` work, and Zhen runs the same raise-and-halve code.
- ⚪️ **How high** the limit goes on a real device hasn't been measured yet. The app's **Diagnostics** screen reads it for you (`zhen-ios/Zhen/Platform/CapabilityProbe.swift:49-63`). Anything below 256 counts as a surprise.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **Trusting `rlim_max`.** It can be "infinity", and converting that to `Int` traps. Zhen clamps it to 1,048,576 first (`DarwinPlatform.swift:125-127`).
- **Trusting the rule over the kernel.** The rule said ~9 quintillion; the kernel stopped at 92,160. Scans sized to the rule would have failed halfway with `EMFILE` ("too many open files").
- **Double close.** It's silent, it's random, and it hits someone else's socket.
:::

::: remember
🧠 Remember

- A file descriptor is a **ticket number**. The kernel keeps the real thing.
- `-1` means it failed; **`errno`** says why. Read it immediately.
- **One owner closes each ticket, exactly once.** Ask the kernel how many tickets you may hold, and believe the answer.
:::
