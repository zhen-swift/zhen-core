# Security

## Reporting a vulnerability

Open a **private** security advisory on the repository rather than a public issue.
If that is not available to you, open an issue titled "security contact request" with
no detail in it and wait to be contacted.

Please include what you did, what happened, and what you expected. A proof of concept
is welcome; a working exploit is not required and never necessary to be taken
seriously.

There is no bounty. There is a commitment to reply, to say plainly whether something
is a bug, and to credit you unless you would rather not be.

## Use it on networks you are responsible for

This is a network scanner. It sends ICMP echo requests, multicast service discovery
queries and — with `--deep` — TCP connections to every address in a range you give it.

That is unremarkable traffic on a network you run and can be unwelcome on one you do
not. Scanning a network without the owner's permission is, depending on where you are,
somewhere between rude and illegal. The tool will not stop you; nothing about it is a
safeguard against pointing it somewhere you should not.

Scan your own network. Scan a client's network with their written agreement. Do not
scan a network because you can reach it.

## What the scanner does and does not do

Worth stating plainly, because a scanner people cannot reason about is a scanner people
should not run:

- **No subprocesses, ever.** No shelling out, no bundled interpreters, no external
  binaries. There is a test that fails if `Foundation.Process` or `posix_spawn` appears
  in the built modules.
- **No elevated privileges.** The unprivileged path is the only path in this build.
  Unprivileged ICMP datagram sockets and the kernel's neighbour table are enough, which
  is why the tool never asks for a password.
- **Nothing leaves the machine.** No telemetry, no crash reporting, no update check, no
  network requests other than the scan itself.
- **Nothing is written outside the app.** History is in memory for the session; there is
  no database on disk yet.

## Controls worth knowing about

Two are deliberate and worth naming, because they are the places where a scanner can be
turned against the person running it.

**The UPnP description fetch is validated.** `LOCATION` in an SSDP response is an
attacker-controlled string arriving in an unauthenticated UDP datagram, and the parser
deliberately accepts unsolicited `NOTIFY` as well as replies. Handing that to an HTTP
client unvalidated turns the scanner into a confused deputy that will fetch anything the
sender names — `http://127.0.0.1:PORT/` to reach a service bound to loopback, a router's
admin endpoint that trusts the LAN, or `file:///…/.ssh/id_rsa`. So: `http` only, a
numeric IPv4 host, and that address must equal the source of the datagram. A device may
describe itself and nothing else. Redirects are refused, because a `302` is the same
forgery one hop later.

**Responses are bounded.** The description fetch stops at 256 KB during the transfer, not
after it — the byte count on the other end is chosen by whoever sent the datagram.

**NetBIOS replies are matched.** NBSTAT has no authentication and no handshake, so a
reply is accepted only from an address the scan actually asked and only carrying the
transaction ID it was asked with. Without both, one forged datagram could attach a chosen
name to a real device *and* mark it resolved, so the genuine reply would never be used.

## Multicast and VPNs

The SSDP socket binds to the selected interface's address and sets `IP_MULTICAST_IF`. An
unbound multicast send leaves through whichever interface the kernel's multicast route
names, which on a laptop with a VPN up is routinely the tunnel — so the search would
reach a network you did not mean to scan and the results would describe somebody else's
devices. If you are on a VPN and the interface looks wrong, check `--iface`.

## What is not hardened

Said out loud, because "we did not get to it" is more useful than silence:

- **No sandbox.** A network scanner cannot be sandboxed — the App Sandbox has no
  entitlement covering raw sockets, and sandboxed multicast needs a managed entitlement.
  This is a decision, not an oversight, and it is why the app is not an App Store app.
- **Ad-hoc signing.** Distribution needs a Developer ID certificate, hardened runtime and
  notarization. The local build signs ad-hoc, which is enough for a stable identity
  across launches and not enough for anyone else to trust the binary.
- **The privileged helper does not exist in this build.** When it does, it will verify
  its caller's code signature from the connection audit token — a Mach service is
  reachable by anything running as the user, and without that check a privileged helper
  is a privilege-escalation gadget with our name on it.
