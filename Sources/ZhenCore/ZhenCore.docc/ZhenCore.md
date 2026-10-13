# ``ZhenCore``

The definition layer for zhen: the wire model, the time and concurrency
primitives, and the protocol surface that describes probing.

## Overview

This package contains no user interface, no command parsing and no application
lifecycle. **It opens no sockets and parses no packets.** It declares *what a probe
result is*, not how to obtain one — the engines that obtain them live in platform
targets and are injected through the protocols declared here.

Both consumers depend on it and neither may define a type the other would also need.
If both want it, it belongs here.

Core depends on nothing but the standard library and Foundation, and **its public API
must compile on Linux.** Darwin-only machinery — `dns_sd`, kqueue, BPF, the route
socket — is reachable only through the protocols in <doc:#Platform>. There is no
`#if canImport(Darwin)` anywhere in this package, and there must never be one: a
conditional inside a public type is a design failure, a protocol with two conformances
is not.

## Four rules that everything here follows

**Two clocks, never mixed.** ``MonotonicInstant`` measures; ``Timestamp`` displays.
The separation is structural rather than conventional — ``MonotonicInstant`` is not
`Codable`, so it cannot reach a model type, and ``Timestamp`` has no subtraction, so a
duration cannot be computed from wall-clock stamps across an NTP step.

**Optionality means *not observed*, never zero.** A host with no round-trip
measurement has `rtt == nil`, never a sample of `0`, which would read as the fastest
device on the network. The unidentified device — no name, no vendor, no model, a
randomized MAC — is the normal case on a home network and the acceptance case for the
whole product.

**A deadline expiring is a normal return.** ``Outcome/deadlineExpired`` is a success
value carrying partial results. Nothing on the path that produces it throws, and the
CLI exits zero on it. Whether a run was complete is a field in the artifact, not a
status code — and ``PoolTermination`` is how core's own fan-out primitive reports
which of the three endings happened, because a short result cannot say: silent probes
are dropped, so "fewer results than items" is the normal shape of a successful sweep.

**Nothing reports success for work it did not do.** A network too wide to enumerate
refuses with a ``Degradation`` from ``ScanTarget/resolution`` rather than resolving to
an empty address list — zero probes and an outcome of `.complete` would tell a user
with a /8 that their network is empty.

**Failures are values.** Every probe failure travels back to the surface as a
``Degradation``. Explaining *why* a device is unidentified is the product's main
feature, and a silent `catch {}` destroys it.

## Two confidences, and they are not the same number

``Device`` carries both, computed from different inputs, answering different questions.

``Identification`` — how well do we know *what this thing is*. Fused from name, model,
vendor and OS-hint evidence, and from how many independent sources agree. This is what
the device list shows and the only one an everyday user sees.

``Stability`` — how likely this *record* is to fragment or merge wrongly. Derived from
the weight of the strongest ``HostIdentifier``: a universal MAC outranks an mDNS
instance, which outranks a rotating private MAC, which outranks an address lease. It
belongs one level in — the detail view's identity card, and the CLI's JSON.

They routinely disagree, which is the proof they are distinct. A MacBook advertising a
clean Bonjour name over a rotating MAC is `.identified` and only `.moderate`. A gateway
with a burned-in MAC and no friendly name is `.partial` and `.strong`. Collapsing them
loses one of those two facts every time.

## Topics

### The artifact

- ``ScanReport``
- ``ScanRun``
- ``Outcome``
- ``EngineDescriptor``
- ``SchemaError``

### Devices and identity

- ``Device``
- ``HostFacts``
- ``Identification``
- ``IdentificationEvidence``
- ``Stability``
- ``HostIdentifier``
- ``HostIdentifierKind``
- ``OSHint``

### Names

- ``NameSource``
- ``NameCandidate``

### Ports and services

- ``PortObservation``
- ``PortState``
- ``TransportProtocol``
- ``ServiceIdentity``
- ``ServiceEvidence``

### Addresses

- ``MACAddress``
- ``IPv4Address``
- ``IPv4Network``
- ``NetworkInterface``

### Time and measurement

- ``MonotonicInstant``
- ``Timestamp``
- ``Stopwatch``
- ``Deadline``
- ``RTTSample``
- ``RTTEstimator``
- ``Timing``
- ``StageTiming``

### Concurrency

- ``boundedPool(over:concurrency:deadline:onProgress:work:)``
- ``BoundedPoolRun``
- ``PoolTermination``
- ``ProbeOutcome``
- ``discardingFanOut(over:concurrency:deadline:work:)``
- ``ConcurrencyBudget``
- ``ProbeCounters``
- ``ProbeCounterSnapshot``
- ``ProbeStream``
- ``StreamBuffering``
- ``ProbeEvent``
- ``ProgressSink``

### Engines

- ``HostDiscovery``
- ``PortScanning``
- ``ScanTarget``
- ``TargetResolution``
- ``DiscoveryResult``
- ``PortScanResult``
- ``EngineKind``
- ``EngineCapabilities``
- ``PortSpec``

### Events

- ``ScanEvent``
- ``ScanEventKind``
- ``EventSeverity``
- ``deriveEvents(previous:current:at:run:network:)``

### Degradations

- ``Degradation``
- ``Stage``
- ``LocalNetworkDenialHeuristic``
- ``ProbePermissionAdvice``

### Platform

- ``PlatformError``
- ``InterfaceProvider``
- ``NeighborCache``
- ``NeighborEntry``
- ``ServiceBrowser``
- ``ServiceSighting``
- ``ReverseNameResolver``
- ``PrivilegeBroker``
- ``ResourceLimits``
- ``OwnedDescriptor``
- ``DescriptorPolicy``

### Wire bytes

- ``InternetChecksum``
- ``WireDecodable``

### Legibility

- ``Contrast``
- ``SRGBColor``
