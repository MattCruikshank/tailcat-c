# Plan: closing the gap with tailcat

What tailcat-c would need to reach feature parity with upstream
[tailcat](https://github.com/tailscale/tailcat), roughly in the order worth
doing it.

Today tailcat-c has the **core data path** — address codec, DERP relay,
WireGuard tunnel, userspace TCP — working in both roles and verified against
the real Go implementation. Everything below is built on top of that, or
makes it more robust.

Sizes are rough C line counts for the new code, excluding tests, which have
run about 1:1 with implementation on this project. "Risk" is about how likely
the thing is to be subtly wrong in a way tests do not catch — the Noise
transcript and the TCP sequence arithmetic were both in that category.

---

## Phase 1 — make the tool self-sufficient  ✅ DONE

Right now a user needs the Go `tailcat` binary to resolve an address before
ours can use it, and `serve` needs a relay hostname typed in by hand. This
phase removes that.

### 1.1 HTTP client ✅ · 330 lines

A minimal HTTP/1.1 GET over the existing TLS transport: request, status line,
headers, and a body delivered either by `Content-Length` or `chunked`
transfer encoding. Bounded response size, no redirects beyond one hop, no
cookies, no keep-alive.

The DERP client already does a hand-rolled HTTP upgrade, so some of this is
consolidation rather than new work.

### 1.2 JSON parser ✅ · 470 lines

Strict, allocation-free, non-recursive, in the same shape as `src/cbor.c` —
that file is a good template and the same bounds-checking discipline applies.
The document is small and regular:

```
{"Regions": {"301": {"RegionID":…, "RegionCode":…, "RegionName":…,
                     "Latitude":…, "Longitude":…,
                     "Nodes":[{"Name":…, "RegionID":…, "HostName":…,
                               "IPv4":…, "IPv6":…, "CanPort80":…}]}}}
```

Only six region fields and six node fields, all of which map onto the
existing `tc_derp_region` / `tc_derp_node` structs. Needs the same UTF-8
validation and depth/size limits the CBOR reader has, since this is fetched
from the network.

**Worth fuzzing** on arrival, like the address parser.

### 1.3 DERP map fetch and cache ✅ · 300 lines

`GET https://tailcat.dev/derpmap.json` (overridable, as upstream's
`--derpmap-url` is), parsed into the existing structs, cached in memory for
an hour the way upstream does. Unlocks:

- short addresses (`RegionID` with no embedded region) working directly
- `serve` without `--relay`

### 1.4 Region selection ✅ · 60 lines

Upstream picks a region with `netcheck`, which sends STUN probes and measures
per-region RTT. That is a large dependency for one decision.

A much smaller approach: open a DERP connection to two or three candidate
regions concurrently, measure the handshake round trip, keep the fastest and
drop the rest. **This is not equivalent to netcheck** — it measures TCP+TLS
to the relay rather than UDP path quality, and it will pick differently in
some networks. Worth doing the cheap version and saying so, then revisiting
if Phase 4 brings STUN anyway.

### 1.5 `resolve` and `ping` subcommands ✅ · 170 lines

Both fall out of the above. `resolve` is parse → fetch → embed → re-encode,
and every piece exists. `ping` is the meow round trip we already do, with a
timer around it and the result printed.

**Phase 1 done: ~1,330 lines**, against an estimate of ~1,100. tailcat-c now
needs nothing else installed: short addresses work directly, and `serve`
picks its own relay.

Verified against the Go implementation: `tailcat-c resolve` on a short
address produces a **byte-identical** result to `tailcat resolve`, which
exercises the whole chain -- HTTPS, JSON, the DERP map, and address
re-encoding -- in one comparison.

Region selection came in far under estimate because it reuses the DERP client
rather than implementing probing of its own. It remains the deliberate
approximation described above.

---

## Phase 2 — make the existing data path robust  ✅ DONE

These are the things that make the difference between a demo and something
you would leave running. Several are already recorded as limitations in the
README.

### 2.1 Connection demultiplexer ✅ · 400 lines

**The key structural change in the whole plan**, and it is done. `src/net/
tcpmux.c` holds a table keyed by (local port, remote port), dispatches
inbound IPv6 packets, accepts repeatedly on a listener set, and allocates
ephemeral ports. The TCP state machine did not change.

Two decisions that were not in the estimate:

- A packet for a port pair nobody owns draws a **reset** rather than a drop,
  so dialling a closed port fails at once instead of retransmitting for a
  minute. `tc_tcp_reject` builds the reply from the offending segment alone.
- A bare SYN for a pair held in **TIME_WAIT is accepted**, per RFC 1122
  4.2.2.13. The straggler TIME_WAIT guards against carries an ACK; a bare SYN
  is the peer reopening. The usual objection does not apply here, because
  everything reaching this stack was authenticated by the WireGuard session
  that carried it.

The CLI routes through the mux even though a pipe uses one connection, so
dispatch is exercised by every live run. `scripts/live-serve.sh` is new and
covers the passive open against a real Go client -- the direction nothing
automated reached before.

### 2.2 Rekeying and session lifetime ✅ · 420 lines

`src/wg/peer.c` holds the previous/current/next keypair triple, the handshake
timers, passive keepalives and expiry. The CLI is rewired onto it.

The risk was real and it landed where expected. Retrying a handshake by
resending the *identical* initiation looks thrifty and is wrong: the peer's
own replay protection rejects a repeated timestamp, so one lost packet
stranded the tunnel for ninety seconds. Only a two-hour simulation with loss
found it.

`make live-rekey` holds a session open for 280 seconds against the real Go
server. It takes six minutes and there is no shortcut to proving this one.

### 2.3 Cookie reply / DoS mitigation ✅ · 290 lines

XChaCha20-Poly1305 (HChaCha20 plus the existing ChaCha20-Poly1305), the
cookie reply message, and mac2 on both sides.

Demanding cookies is **off by default**: the exchange costs an extra round
trip on every handshake, and this is a netcat rather than a relay. Consuming
a reply is unconditional, so a peer that demands one from us always gets an
answer.

Two things the estimate did not anticipate. The sender identifier is the
peer's node key rather than an IP, because over a relay there is no address
to bind a cookie to — which turns out not to affect interoperability at all,
since the cookie is opaque to the initiator. And the mac2 check has to run
before `tc_wg_handshake_init`, not merely before consuming the message: that
call does an X25519 of its own, so checking after it would still pay the
expensive cost for every forged initiation.

### 2.4 Initiation replay protection ✅ · 20 lines

Done as part of 2.2, because the thing it needs -- the last timestamp seen
from a peer -- only exists once something tracks a peer over time.

### 2.5 Reconnection and liveness ✅ · 260 lines

`FRAME_RESTARTING` ends the connection instead of being discarded, every
frame records liveness, `tc_derp_reconnect` redials under the same identity,
and the CLI backs off and re-meows. Write timeouts via `SO_SNDTIMEO`, and
documented as unrecoverable unlike read timeouts — a half-written frame
leaves the stream unparseable.

Nothing above DERP is disturbed by a reconnection: the WireGuard session is
keyed to the peers rather than to the path, so a tunnel resumes rather than
rehandshaking.

This is also where the **Makefile turned out to have no header dependency
tracking**. Adding one member to `tc_stream` left `http.c` compiled against
the old layout and crashed three call frames away. Fixed with `-MMD -MP`.

**Phase 2 done: ~1,390 lines**, against an estimate of ~1,150. The data path
is now robust rather than merely working: sessions renew, relays can restart
under it, replays and floods are refused, and no call can block forever.

---

## Phase 3 — the commands people actually use

All of these depend on 2.1, which is in place, so none of them is blocked.
3.2 and 3.3 also reuse `src/net/proxy.c` from 3.1, which is most of their
bulk already written.

### 3.1 `serve` with ports ✅ · 690 lines

`serve 8080,8443`, `serve all`, port ranges, and as many clients at once as
the table holds.

Three pieces rather than one: `src/portset.c` for the spec syntax,
`src/net/proxy.c` for the splice (which 3.2 and 3.3 reuse, so it is in the
library with its own tests), and an accept filter on the mux, since neither
`all` nor "any port" fits an array of sixteen listeners.

**Multi-client was folded in here** rather than left for later. Each client is
a separate WireGuard session, tunnel address and demultiplexer; nothing is
shared but the relay connection and the socket pool. Doing it now meant the
proxy and the accept filter were designed against the real shape of the
problem instead of being retrofitted.

Half close is most of the work: the tunnel FIN becomes `shutdown(SHUT_WR)` on
the socket, and the socket EOF becomes a tunnel FIN once everything read has
been acknowledged. A proxy without it passes every request-response test and
hangs on anything that signals completion with an EOF.

### 3.2 `forward` ✅ · 230 lines

`forward <addr> 8080 18080:8080 0:443`. Listeners bind before the tunnel is
dialled, so a port already in use fails immediately rather than after a
handshake with a relay, and an OS-chosen port is read back with `getsockname`
so the number printed is the one that was actually used.

The `local:host:port` form needs an exit node and is refused by name.

### 3.3 `socks` ✅ · 180 lines

A SOCKS5 server that dials through the tunnel: no authentication, CONNECT
only, proper reply codes for refusals.

The destination **host** is read and discarded. There is exactly one place
this proxy can go -- the server at the far end of the tunnel -- so only the
port means anything. Upstream routes by hostname because it can hold several
servers at once; with one, doing so would be a fiction.

### 3.4 `ssh` and `cp` clients ✅ · 350 lines

As predicted, the system ssh and scp do the protocol and we are the
`ProxyCommand`. What the estimate missed is that "argument construction" is
the security-sensitive half: the command line goes to a *shell*, and includes
a path this program did not choose.

`src/shquote.c` has its own tests for that -- close-escape-reopen for embedded
single quotes, doubled percent signs for OpenSSH's own token expansion, and a
refusal rather than a mangling for the cmd.exe characters that cannot survive
both cmd.exe and the argv parser behind it.

`tc_ssh_dest_host` gives ssh a short stable hash instead of the address,
because ssh expands the destination into `ControlPath` and an AF_UNIX path
cannot hold a full tailcat address.

`make live-ssh` runs the real ssh and scp against upstream's own SSH server
through our tunnel.

### 3.5 `recv` (file drop box) — **moved to Phase 5**

**This estimate was wrong, and the way it was wrong is worth recording.** It
assumed `recv` would need "a small framing format". It does not: `tailcat
recv` is exactly `serve --files <dir>:wo files`, and the `files` service is
**SFTP over SSH**. There is no tailcat-specific file protocol to implement.

So the server half needs an SSH server and an SFTP server — 5.4 and 5.5, some
5,500 lines, the largest items in the whole plan — not 300 lines. Building a
bespoke protocol instead would produce a `recv` that no real `tailcat cp`
could talk to, which is worse than not having one.

**The client half already works**, and did before anyone wrote a line for it:
`cp` execs the system scp with tailcat-c as the ProxyCommand, scp speaks SFTP
over SSH, and upstream's `recv` serves that. `make live-recv` delivers a file
into a real drop box and checks the two properties flat mode promises — the
server chooses the stored name, and an existing file is untouched.

The security concern the original entry raised is real and still applies, but
it applies to 5.5: it is the SFTP server that would write attacker-named
files.

### 3.6 `genkey`, `printpub` ✅ · 520 lines

Saved identities, in upstream's own `*.private.json` format, read and written
byte for byte compatibly. Plus `--key` on every command that needs one.

Not "mostly plumbing": the format is an interop surface, so it was determined
by generating real keys with `tailcat genkey` and reading the bytes, and the
tests round-trip those exact files. The derived fields (public key, disco key)
are recomputed and compared rather than trusted, since a file naming different
ones would produce an address nobody can reach.

**`browse` is deliberately not done.** It is `forward 0:80` plus opening a
URL, which is the only part of upstream's command set that does nothing a user
cannot do in one line.

This is also where `serve` was found to be advertising the wrong address form
-- embedding the relay where upstream names a region by number -- so the same
saved key produced different addresses on the two sides. `--full-address` now
opts into the embedded form.

**Phase 3 done: ~1,970 lines**, against an estimate of ~1,400 that did not
include multi-client serving. 3.5 moved to Phase 5 and `browse` was judged not
worth writing; everything else is finished.

What remains of upstream's command set -- `recv`, `ls`, `serve ssh`,
`serve files` -- is gated entirely on having an SSH server.

---

## Phase 4 — direct peer-to-peer paths

The big one, and the thing that makes tailcat *tailcat* rather than a relay
client. This is the other half of the original scope question.

### 4.1 UDP transport and endpoint enumeration · ~300 lines · medium risk

A UDP socket alongside the DERP connection, local address enumeration, and
sending WireGuard packets to a peer address rather than through the relay.

### 4.2 STUN client · ~250 lines · low risk

RFC 5389 binding requests to the relays' STUN ports to learn our public
address. Small and well specified; upstream's is 450 lines of Go.

### 4.3 disco protocol · ~400 lines · medium risk

`"TS💬"` magic, a type byte, a version byte, then a NaCl box — **and we
already have NaCl box from M3**. For basic traversal only three of the nine
message types matter: `Ping` (0x01), `Pong` (0x02) and `CallMeMaybe` (0x03).
The rest are UDP-relay endpoint allocation and can wait.

### 4.4 Path discovery and upgrade · ~600 lines · **high risk**

The actual hard part, and the reason the original scope excluded it. Probing
candidate paths, scoring them, switching a live session from DERP to direct
without dropping packets, detecting a dead direct path and falling back, and
handling both peers doing this at once. This is the heart of what
`magicsock` spends 11,000 lines on.

Testable the same way the TCP stack was — a simulated network with
configurable NAT behaviour — but the failure modes are timing-dependent and
the interop surface is large.

### 4.5 netcheck · ~400 lines · medium risk

Proper per-region latency and NAT-type probing, replacing the cheap 1.4
heuristic.

**Phase 4 total: ~1,950 lines.** Realistically the longest phase in calendar
time regardless of line count.

---

## Phase 5 — the long tail

### 5.1 UDP through the tunnel · ~200 lines · low risk
Datagram forwarding, plus `DialUDP`. The tunnel carries IP, so this is a UDP
header and a demux entry.

### 5.2 NAT64 for IPv4 · ~100 lines · low risk
Map IPv4 destinations into the NAT64 prefix, as upstream does, so IPv4
targets work over the IPv6-only tunnel.

### 5.3 TLS 1.3 · ~50 lines config · low risk
Enable `MBEDTLS_SSL_PROTO_TLS1_3`, which needs the PSA crypto layer
(`MBEDTLS_PSA_CRYPTO_C`) — a large amount of additional Mbed TLS code for a
modest gain. It would also unlock upstream's meta-certificate "fast start",
which skips the HTTP upgrade.

### 5.4 SSH server · ~4,000+ lines · **high risk**
The largest single item. Transport, key exchange, userauth, channels, PTY
handling. Realistically: vendor an existing implementation rather than write
one. Needed for `ls` (SFTP) and for being an SSH target.

### 5.5 SFTP server · ~1,500 lines · medium risk
Needed by `ls`, by the server side of `cp`, and by **`recv`**, which moved
here from 3.5. Depends on 5.4.

This is where the "writes attacker-named files" hazard lives. Upstream's flat
write-only mode is the design to copy rather than improve on: the server
chooses every stored name, so a sender can neither overwrite anything nor
learn what is already in the directory. The recursive mode (`:wo+`,
`--accept-dirs`) trades exactly that away, and upstream documents the
trade-off rather than hiding it.

No SFTP *client* is needed: `cp` and `ls` can keep execing the system scp and
sftp, as `cp` already does.

### 5.6 WebAssembly build · unknown · high risk
Upstream compiles to WASM for the browser demo. Cosmopolitan does **not**
target WASM, so this would mean a second toolchain and a second build of the
whole stack — arguably out of scope for a project whose premise is one fat
APE.

---

## Cross-cutting, and worth doing before Phase 3

These are already in the README's TODO list and do not depend on any feature.

- ~~**CI**~~: done differently. `make diag5/3/1` and a pre-push hook run the
  checks locally in three tiers; see the README. Hosted CI was rejected
  deliberately -- the live tests dial Tailscale's production relays, and that
  is not something to automate on every push.
- **Test on macOS, the BSDs, and aarch64.** Two of six target operating
  systems are covered, both x86_64. The aarch64 half of every binary is built
  and linked but **has never been executed**. This is the largest untested
  claim remaining.
- **Extend fuzzing** to the DERP frame codec, the JSON parser and the TCP
  input path.
- **Constant-time audit** with actual timing measurements, rather than the
  current "written in a data-independent style".
- **Thread-safety**: either make `tc_derp_client` safe for concurrent use or
  state plainly that callers must serialise it.

---

## Totals and honest expectations

| Phase | New C | Risk |
|---|---:|---|
| 1 — self-sufficient | ~1,330 ✅ | done |
| 2 — robust | ~1,390 ✅ | done |
| 3 — commands | ~1,970 ✅ | done |
| 4 — direct paths | ~1,950 | **high** |
| 5 — long tail (excl. SSH/WASM) | ~350 | low |
| 5 — SSH + SFTP (incl. `recv`) | ~5,500 | high |

Roughly **7,000 lines** for everything except SSH, SFTP and WASM, on top of
the ~7,500 that exist — so a little under double the current size. Add SSH and
SFTP and it roughly doubles again.

Phases 1 and 3 are mostly mechanical. Phase 2 and Phase 4 are where the real
difficulty is, and both have failure modes that only appear under load or
over time rather than in a unit test. The pattern from M1–M7 holds: the
dangerous work is where a plausible-looking implementation is subtly wrong,
and the defence is differential testing against the Go implementation plus a
second, stricter toolchain.

**Phases 1, 2 and 3 are done.** Everything that made the tunnel unreliable is
closed, and every command that moves bytes is implemented.

The next thing is **Phase 3**, which is now unblocked and mostly mechanical:
`serve` with ports, `forward`, `socks` and the `ssh`/`cp` wrappers all wanted
the demultiplexer and a session that lasts, and now have both. 3.5 (`recv`)
is the one to write carefully, since it writes attacker-named files.

The cross-cutting item worth doing alongside it is **running the aarch64
half**, which is now the largest untested claim in the project: the
diagnostics cover x86_64 on two operating systems, and the other half of every
binary has never been executed at all.
