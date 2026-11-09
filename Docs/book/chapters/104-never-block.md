# 4 · Never block

![Never stand at a door. Let the bell call you.](figures/04-hero.svg)

::: short
The short version

- A normal `read` or `connect` **waits** until something happens. In Zhen, that waiting would freeze the whole scan.
- So every ticket is switched to **non-blocking** (`O_NONBLOCK`). A door that has nothing yet says `EAGAIN` or `EINPROGRESS` and returns at once.
- To learn when to try again, Zhen hangs a **bell**: a Dispatch source, which is the kernel's **kqueue** underneath. All bells ring on one dedicated queue.
- **Cancelling a bell takes time.** So a ticket is closed only **inside the bell's cancel handler**, never right after `cancel()`.
- The socket, a timer and cancellation all race. **The first one wins**, and the waiting task is resumed exactly once.
:::

## Why one stuck door stops everything

![Swift's pool has one worker per core. If every worker sits at a door, nothing else runs.](figures/04-deadlock.svg)

- Swift runs async tasks on a **cooperative pool**: a handful of threads, about **one per CPU core**.
- A task that calls a **blocking** `read` or `connect` keeps its thread asleep inside the kernel.
- A few stuck tasks and the pool is empty. Every other task waits, forever.
- **`Task.cancel()` can't help.** It only sets a flag that the task must check itself. A task asleep inside a syscall never checks it, and a task group "will not return until its child does" (`Readiness.swift:7-11`).
- The code's own verdict: a handful of blocked descriptors "does not slow the scanner down — it deadlocks it outright" (`DarwinPlatform.swift:133-137`).

::: word
New word: cooperative cancellation

In Swift, **cancelling a task** doesn't stop it. It sets a flag, and the task is expected to notice and stop by itself. That's **cooperative**: it only works if the task gets a chance to look.
:::

## Flip the switch: `O_NONBLOCK`

![With O_NONBLOCK, read says EAGAIN and connect says EINPROGRESS, and both return at once.](figures/04-nonblock.svg)

Every descriptor Zhen opens gets this, "with no exceptions" (`DarwinPlatform.swift:132`):

```swift
func setNonBlocking(_ fd: Int32) -> Bool {
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0 else { return false }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
}
```

[`DarwinPlatform.swift:139-143` @ 0.9.0]{.src}

Then the doors stop waiting:

- `read` with nothing to read returns `-1` with **`EAGAIN`**: "nothing yet, try later".
- `connect` returns `-1` with **`EINPROGRESS`**: "the knock is on its way". Any **other** error is a real answer; for a port scan, a refusal means "closed" (`TCPConnectScan.swift:206-214`).
- `sendto` with a full buffer returns **`EAGAIN`** too (chapter 5).

::: word
New word: non-blocking

A **non-blocking** ticket makes every door return immediately. If the answer isn't ready, you get `EAGAIN` (or `EINPROGRESS` for a connect) instead of a nap.
:::

## Bells: kqueue and Dispatch sources

![kqueue rings the read, write and timer bells. Their handlers all run on one serial queue.](figures/04-bell.svg)

"Try later" needs a "when". That's the bell:

1. **`makeReadSource`** rings when a ticket has something to read (`Readiness.swift:186`, and the ping socket's reader, `ICMPSocket.swift:140`).
2. **`makeWriteSource`** rings when a ticket can be written, which is also when a non-blocking `connect` has finished (`Readiness.swift:94`, `:154`).
3. **`makeTimerSource`** rings when the time budget runs out (`Readiness.swift:95`).

Underneath, a Dispatch source **is** kqueue, the kernel's readiness system (`Readiness.swift:3-5`). Every bell rings on one queue:

```swift
static let shared = DispatchQueue(
    label: "com.jctec.zhen.readiness",
    qos: .userInitiated,
    autoreleaseFrequency: .workItem
)
```

[`Readiness.swift:31-35` @ 0.9.0]{.src}

- **Dedicated**, not the shared pool, so a reply never waits behind report encoding or a screen redraw.
- **Serial**, because ordering the wake-ups "costs nothing".
- **High priority**, because a reply stuck in a queue "is measured as network latency and silently inflates every RTT in the report" (`Readiness.swift:27-30`).

::: word
New word: kqueue and Dispatch source

**kqueue** is the BSD kernel's way to say "tell me when any of these tickets is ready". A **Dispatch source** is Apple's friendlier wrapper: you give it a ticket, a queue and a handler, and the handler runs when kqueue fires.
:::

## Only the cancel handler closes the ticket

![Close right after cancel, and an old bell rings on a new socket. Close in the cancel handler, and it can't.](figures/04-cancel.svg)

The trap: **`DispatchSource.cancel()` is asynchronous**. It returns at once, and the kernel lets go of the ticket "some time later" (`Readiness.swift:42-45`).

An early version closed the ticket right after `cancel()`. Two things could happen:

- **Loud:** libdispatch spots it and crashes the app (`DISPATCH_CLIENT_CRASH`), somewhere in the middle of 25,000 probes.
- **Quiet, and worse:**
  1. The ticket number goes back to the kernel.
  2. The very next `socket()` gets the **same number**.
  3. The old write bell fires on the **new** connection.
  4. `getsockopt(SO_ERROR)` reads 0 from a socket nobody asked anything.
  5. "A filtered port is reported open, with a sub-millisecond round trip" (`Readiness.swift:50-55`).

So the close moves into the **cancel handler**, the one place the runtime promises the bell is finished:

```swift
source.setCancelHandler {
    timer.cancel()
    _ = Darwin.close(fd)
    continuation.resume(returning: box.take())
}
```

[`Readiness.swift:101-105` @ 0.9.0]{.src}

- The handler also **resumes the waiting task**, so no caller can run before the close (`Readiness.swift:57-59`).
- `SO_ERROR` (did the connect work?) is read in the **event** handler, while the ticket is still open and still ours (`Readiness.swift:88-89`, `:107-116`).
- Long-lived tickets that outlive one wait (the ping socket, a banner conversation) use the **borrowed** versions, which never close anything (`Readiness.swift:143-150`, `:176-181`).

## Three racers, one answer

![The socket, the timer and cancellation race. The first to write the box wins.](figures/04-race.svg)

Every wait has three possible endings, and they can happen at almost the same moment:

1. The **socket** is ready.
2. The **timer** runs out.
3. The **task is cancelled**.

How Zhen keeps that sane:

- Each racer writes its result into an **`OutcomeBox`**. Only the **first** write sticks (`Readiness.swift:316-331`).
- Each racer then calls `source.cancel()`. The cancel handler runs **once**, reads the box once, and resumes the task once.
- **`ResumeOnce`** handles a cancel that arrives *before* the bells are hung: it remembers it and fires it the moment the handler is installed (`Readiness.swift:371-383`, `:396-404`).
- One more check after arming: if the task was cancelled in between, cancel now. Otherwise the probe "would run its full budget" (`Readiness.swift:130-136`).

::: honest
🔍 Honest note: the descriptor wrapper nobody uses

Two comments say the TCP knock's ticket is an **`OwnedDescriptor`**, a wrapper that makes a second `close` a compile error (`DarwinPlatform.swift:30-38`, `TCPConnectScan.swift:170-174`). The code underneath uses a plain `Int32` (`TCPConnectScan.swift:176`), and no file in `Sources/` creates an `OwnedDescriptor`. The single-close rule still holds, but by the cancel-handler discipline in this chapter, not by the type.
:::

::: iphone
📱 On iPhone & iPad

- ✅ `fcntl`, `O_NONBLOCK`, kqueue and Dispatch are all part of the shared BSD layer and Apple's frameworks.
- ✅ The same `Readiness.swift` is compiled for iPadOS, and the engine's tests run on an iPad simulator in CI (`Package.swift:71-73`).
- ⚪️ The simulator runs on the Mac's kernel (`Docs/IPADOS.md:63`). How the readiness queue's timing holds up on a real device hasn't been measured.
:::

::: gotcha
⚠️ Gotchas the code remembers

- **A blocking call on the pool.** Not slow: stopped (`Readiness.swift:9-11`).
- **Closing after `cancel()`.** A crash if you're lucky, a filtered port reported open if you're not.
- **Reading `SO_ERROR` too late.** It means something only on the ticket it belongs to, so it's read before the close (`Readiness.swift:88-89`).
- **A cancel that lands before the bells are armed.** Without the extra `Task.isCancelled` check, that probe waits out its whole budget (`Readiness.swift:130-136`).
:::

::: remember
🧠 Remember

- Every ticket is **`O_NONBLOCK`**. Doors answer `EAGAIN` or `EINPROGRESS` instead of waiting.
- A **Dispatch source** (kqueue) rings when it's time; all bells ring on **one dedicated, serial queue**.
- `cancel()` is asynchronous, so **only the cancel handler closes the ticket**. First racer wins; resume exactly once.
:::
