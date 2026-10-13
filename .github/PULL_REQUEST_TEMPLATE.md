## What this changes, and why

<!-- The reasoning matters more than the diff. If it changes timing, say what it
     trades and against which case. -->

## Checks

- [ ] `swift test` passes in every package touched
- [ ] `./Scripts/verify-linux.sh` passes if `ZhenCore` changed — inspection is
      not proof, Swift does not type-check inactive `#if` branches
- [ ] `python3 Scripts/generate-xcodeproj.py` produces no diff if the project changed
- [ ] Anything that could regress has a test that fails without the fix

## The rules this repository does not bend

- [ ] No subprocesses. No `Foundation.Process`, no `posix_spawn`, anywhere
- [ ] No blocking call on a socket descriptor — non-blocking, readiness through a
      `DispatchSource`, and any source owning a descriptor closes it in its cancel handler
- [ ] `ZhenCore` has no `import Darwin` and no `#if os(...)` in its public API
- [ ] A probe failure is a `Degradation` in the artifact, never a swallowed error and
      never only a log line

## What you could not verify

<!-- Say it plainly. An untested path named here is worth more than a checkbox
     ticked on trust. -->
