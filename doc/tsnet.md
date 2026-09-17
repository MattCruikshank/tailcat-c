# How much of tsnet is this?

`tsnet` is the other library that embeds a Tailscale node in a process.
tailcat and tailcat-c are often described as "like tsnet", so it is worth
saying exactly how much of it is here, measured rather than felt.

Short version: **about 13% of tsnet by line, about 25–30% by feature, and
about half by difficulty** — because the parts that are done are the parts
with the worst difficulty-per-line, and the parts that are missing are mostly
bulk.

## Lineage: tailcat is not a fork of tsnet

It is easy to assume tailcat was forked from `tsnet` and cut down. It was not,
in the source-control sense, but the resemblance is real and worth being
precise about.

`upstream-tailcat/tailcat.go` never imports `tailscale.com/tsnet`. Both
packages sit on the *same* substrate — `wgengine.NewUserspaceEngine`,
`netstack.Create`, `wgengine/filter`, `wgcfg`, and `magicsock` underneath all
of it. What tsnet puts on top is `ipnlocal.LocalBackend` driving
`controlclient`. What tailcat puts on top is a hand-rolled `locoBackend` that
synthesises a netmap out of nothing, with the comment at
`upstream-tailcat/tailcat.go:331` saying so directly: *"but there's no
controlclient involved, because there's…"*.

The listener layer, on the other hand, looks lifted and then simplified.
`upstream-tailcat/listen.go:129` and `tsnet/tsnet.go:2296` both define a
`listener` with `s`, a `chan net.Conn`, a `closedc chan struct{}` and a
`closed bool` guarded by the server mutex, and both implement `handle`,
`Accept`, `Addr`, `Close` and `closeLocked` with the same `select` bodies.
tailcat's differs by dropping funnel keys, the gonet listener and the
multi-key listen set, and by adding a packet-filter rebuild on close.

So the accurate statement is:

> **tsnet ≈ tailcat + the entire Tailscale control plane + the node feature
> set.**

tailcat is tsnet with the coordination server amputated and a bearer-token
address (`tc…`, plus the meow bootstrap) grafted on where the netmap used to
be. tailcat-c is a C reimplementation of tailcat, so it inherits that shape:
it is a *data plane* project, and the whole control half of tsnet is not
merely unimplemented but deliberately absent.

## Method

The denominator comes from `tsnet/depaware.txt`, which is the real closure
rather than the import list at the top of `tsnet.go`:

| | count |
|---|---:|
| packages in tsnet's closure | 363 |
| of those, `tailscale.com/*` | 207 |
| of those, `gvisor.dev/gvisor/pkg/tcpip/*` | 41 |
| of those, `github.com/tailscale/wireguard-go/*` | 11 |

Non-test Go lines were counted for all 207 first-party packages out of git
objects: **172,866 lines**. `tsnet.go` itself is 2,395 of them, which is the
same trick tailcat plays — 8,884 lines of Go standing on a data plane it does
not own.

The numerator is tailcat-c: **26,829 lines of C and 5,721 of headers**, with
20,286 lines of tests alongside.

## By feature

| tsnet capability | tailcat-c |
|---|---|
| **Data plane** | |
| WireGuard tunnel (wireguard-go `device`) | ✅ `src/wg/noise.c`, `src/wg/peer.c` |
| DERP relay client (`derp` + `derphttp`) | ✅ `src/derp/` |
| DERP map fetch, region chosen by latency | ✅ `derpmap.c`, `netcheck.c` |
| STUN | ✅ `src/net/stun.c` |
| netcheck | ⚠️ no hairpin probe, no port-mapping probe |
| disco path discovery / NAT traversal | ⚠️ `0x01`–`0x03` only |
| UDP relay endpoint allocation (disco `0x04`+) | ❌ |
| Port mapping (UPnP / NAT-PMP / PCP) | ❌ |
| Path MTU discovery | ❌ |
| Link-change monitoring and rebind (`net/netmon`) | ❌ |
| Userspace TCP/IP stack (gvisor netstack) | ✅ **our own**, `net/tcp.c` + `tcpmux.c` + `udp*.c` |
| ACL packet filter (`wgengine/filter`) | ⚠️ `--allow` by client node key only |
| Exit node / subnet routing, as the server | ✅ `serve exit-node`, `src/net/proxy.c` |
| TUN device mode (`Server.Tun`) | ❌ |
| pcap capture (`CapturePcap`) | ❌ |
| **Control plane** | |
| ts2021 Noise control transport (`controlbase`, `controlhttp`) | ❌ |
| Register and map poll (`controlclient`) | ❌ |
| The `LocalBackend` state machine (`ipnlocal`) | ❌ |
| Auth keys, OAuth client secrets, workload identity | ❌ |
| Interactive login URL | ❌ (nothing to log in to) |
| State store, prefs, profiles | ⚠️ saved keypairs (`genkey`), not `ipn` state |
| Tailnet lock (`tka`) | ❌ |
| Netmap, peers, `WhoIs`, LocalAPI, `local.Client` | ❌ |
| logtail upload, health tracker, hostinfo, clientmetrics | ❌ |
| **Node features** | |
| MagicDNS resolver and split DNS | ❌ |
| HTTPS certificates, ACME, `CertDomains`, `ListenTLS` | ❌ |
| Funnel (`ListenFunnel`) | ❌ |
| Tailscale Services (`ListenService`) | ❌ |
| Tailscale SSH server (`ListenSSH` → `tailssh`) | ⚠️ our own SSH+SFTP subset, unrelated code |
| Web client (`RunWebClient`) | ❌ |
| Loopback SOCKS5 + localapi (`Loopback`) | ⚠️ SOCKS5 yes, including UDP ASSOCIATE; localapi no |
| Taildrive, Taildrop | ❌ (`recv` is tailcat's own idea, not this) |

Roughly **9 full, 6 partial, 22 absent**: **25–30% by feature count**.

## By lines of code

| Bucket | Go lines | tailcat-c |
|---|---:|---|
| Covered `tailscale.com` packages | **~23,500** | ~11,400 C |
| Not covered `tailscale.com` packages | ~149,400 | — |
| wireguard-go `device` and friends | ~10,000 | ~1,450 C |
| gvisor `tcpip` subset (41 packages) | ~100,000 | ~2,400 C |

The covered column, package by package:

| package | Go lines | ours |
|---|---:|---|
| `wgengine/magicsock` | 11,291 | `path.c` 646, `udpmux.c` 638, `disco.c` 249, `endpoint.c` 214 |
| `wgengine/netstack` (+ gvisor) | 3,043 | `tcp.c` 1,195, `tcpmux.c` 553, `udpmux.c`, `udp.c` 283 |
| `derp` + `derp/derphttp` | 2,488 | `derp/client.c` 515, `derp/frame.c` 203 |
| `net/netcheck` | 1,896 | `netcheck.c` 423 |
| `types/key` | 1,663 | `crypto/`, `addr.c` 476 |
| `net/socks5` | 749 | `socks.c` + the server loop in the CLI |
| `disco` | 702 | `disco.c` 249 |
| `net/stun` | 314 | `stun.c` 237 |
| `net/tsaddr`, `wgengine/wgcfg`, the `tailcfg` DERPMap slice | ~1,340 | `nat64.c` 52, `derpmap.c` 443 |

And the largest of what is not covered:

| package | Go lines |
|---|---:|
| `ipn/ipnlocal` | 20,349 |
| `tailcfg` | 7,826 |
| `net/dns` + `net/dns/resolver` | 9,568 |
| `control/controlclient` + `controlbase` + `controlhttp` | 6,331 |
| `ipn` | 4,536 |
| `tka` | 4,280 |
| `net/netmon` | 3,934 |
| `ipn/localapi` | 3,726 |
| `net/portmapper` | 2,813 |
| `tempfork/acme` + `feature/acme` | 4,491 |
| `net/tstun` | 2,591 |
| `client/local` | 2,544 |
| `health`, `logtail`, `hostinfo`, `client/web`, … | the rest |

So:

- **13.6%** of tsnet's first-party Go (23,486 of 172,866), across **13 of its
  207 packages**.
- **~47%** if gvisor and wireguard-go go in the denominator too (133k of
  283k) — but that figure is an artefact of gvisor being enormous and generic
  where `tcp.c` is 1,195 lines and does exactly what one peer needs. It is
  not a claim about craftsmanship in either direction.

**13–15% is the honest line figure.**

## By difficulty

This is where the picture inverts, and it is the number worth quoting.

Rank tsnet's parts by how likely a competent engineer is to get them wrong:

1. **Noise IKpsk2, AEAD, rekeying, cookie reply** — done ✅
2. **Userspace TCP**: retransmission, windows, orderly teardown — done ✅
3. **NAT traversal**: disco, STUN, netcheck, the endpoint set, upgrade and
   fallback — done ✅, less the relay-allocation tail
4. **DERP framing and TLS to the relay** — done ✅ (TLS 1.2; 1.3 is blocked on
   Ed25519, see the README)
5. **ts2021 control transport, map poll, applying a netmap** — ❌, but
   well-specified and mechanical, and another Noise handshake built from
   primitives that are already here
6. **DNS**: MagicDNS, split DNS, and the OS integration under it — ❌, and
   genuinely nasty, mostly per-platform
7. **portmapper**: UPnP, NAT-PMP, PCP — ❌, medium, three unrelated protocols
8. **`ipnlocal`, 20,000 lines** — ❌, bulky rather than deep: prefs, serve
   config, profiles, policy
9. **ACME, funnel, services, web client, localapi, logtail** — ❌, bulky and
   shallow

The four hardest things on that list are done. The remaining 85% of the lines
is roughly half the work, and it is the easier half — with the exception of
DNS and the netmon/rebind layer, which are unpleasant in a way no line count
shows.

**By difficulty-weighted effort: 45–55% of tsnet.**

## The asymmetry

The comparison does not run only one way. tailcat-c contains a large amount of
code that maps to *nothing* in tsnet's closure: an SSH client and server, an
SFTP client and server, the address codec, the meow bootstrap, and the CLI —
`src/ssh/` and `src/cli/` alone are 9,899 lines, about 37% of the project.
tsnet's `ListenSSH` delegates to `tailssh`, which is not even linked into its
default build.

So the two questions have different answers:

- *How much of tsnet is implemented here?* ~13% by line, ~25–30% by feature,
  ~half by difficulty.
- *How much of tailcat-c is tsnet-shaped work?* About 11,400 of 26,829 lines,
  or roughly 43% — with another 37% in SSH, SFTP and the CLI that tsnet has no
  counterpart for at all.

## If parity were the goal

It is not, but the ordered gap is worth writing down:

1. **ts2021 + `controlclient` + applying a netmap.** The step that turns this
   from a pipe into a node. Perhaps 4,000–6,000 lines of C, and the single
   largest addition the project would ever have taken — and the one that
   changes what the project *is*, since the premise so far has been that there
   is no control plane.
2. **netmon and rebinding**, without which a node that changes networks stays
   broken.
3. **portmapper**, three protocols, each self-contained.
4. **DNS**, which is where the per-platform work lives.
5. Everything else: localapi, prefs, certs, funnel, services, the web client.
   Bulk, not depth.
