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

## Phase 2 — make the existing data path robust

These are the things that make the difference between a demo and something
you would leave running. Several are already recorded as limitations in the
README.

### 2.1 Connection demultiplexer · ~350 lines · medium risk

**The key structural change in the whole plan.** Today one `tc_tcp_conn` is
one connection, with no dispatcher. Almost everything in Phase 3 needs many
at once.

Needs a table keyed by (local port, remote port), dispatch of inbound IPv6
packets to the right connection, a listener that can accept repeatedly, and
port allocation. The TCP state machine itself does not change.

### 2.2 Rekeying and session lifetime · ~250 lines · high risk

WireGuard renews a session after two minutes or a message-count threshold,
and refuses to use one past `REJECT_AFTER_TIME`. We currently derive one
session and use it until the counter limit, which is fine for a short pipe
and wrong for anything long-lived.

Needs the handshake timers (`REKEY_AFTER_TIME`, `REKEY_AFTER_MESSAGES`,
`REJECT_AFTER_TIME`, `KEEPALIVE_TIMEOUT`), a previous/current/next keypair
triple so packets in flight during a rekey still decrypt, and passive
keepalives.

High risk because the failure mode is a tunnel that works for two minutes in
testing and then silently stops.

### 2.3 Cookie reply / DoS mitigation · ~200 lines · medium risk

`mac2` is currently written as zero and never checked; `tests/test_noise.c`
asserts that tolerance so it stays visible. A peer under load that demands a
cookie will reject us today.

Needs the cookie reply message (type 3), XChaCha20-Poly1305 — which means
extending `salsa20.c`'s neighbours or adding XChaCha — and the mac2
computation on both sides.

### 2.4 Initiation replay protection · ~80 lines · low risk

`tc_wg_consume_initiation` already reports the TAI64N timestamp; nothing
remembers it. Store the last one per peer and reject anything not strictly
newer.

### 2.5 Reconnection and liveness · ~250 lines · medium risk

Act on `FRAME_RESTARTING` instead of ignoring it, track keep-alives to notice
a dead relay, reconnect with backoff, and re-meow after reconnecting. Also
write timeouts, which reads have and writes do not.

**Phase 2 total: ~1,150 lines.**

---

## Phase 3 — the commands people actually use

All of these depend on 2.1.

### 3.1 `serve` with ports · ~200 lines · low risk

`serve 8080,8443` and `serve all`: accept connections inside the tunnel and
proxy them to localhost ports. Needs 2.1 plus an outbound connector using the
host stack (`tc_net_tcp_connect`, which exists).

### 3.2 `forward` · ~250 lines · low risk

The inverse: listen on local TCP ports with the host stack, and proxy each
accepted connection through the tunnel. Needs 2.1 and a poll loop over many
descriptors rather than two.

### 3.3 `socks` · ~300 lines · low risk

A SOCKS5 server on localhost that dials through the tunnel. The protocol is
small and well specified. Needs 2.1.

### 3.4 `ssh` and `cp` clients · ~150 lines · low risk

**Cheaper than it looks.** Upstream shells out to the *system* ssh and scp,
with tailcat acting as a `ProxyCommand` that pipes stdio to port 22 — which
is what our pipe mode already does. This is mostly argument construction and
process spawning.

### 3.5 `recv` (file drop box) · ~300 lines · low risk

Serve a directory write-only over the tunnel. Needs a small framing format
and careful path handling — **the one security-sensitive part of Phase 3**,
since it writes attacker-named files. Path traversal is the obvious hazard.

### 3.6 `genkey`, `printpub`, `browse` · ~200 lines · low risk

Persistent keys on disk (with sane permissions), printing a public key, and
opening a browser. Mostly plumbing.

**Phase 3 total: ~1,400 lines.**

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

### 5.5 SFTP client and server · ~1,500 lines · medium risk
Needed by `ls` and the server side of `cp`. Depends on 5.4.

### 5.6 WebAssembly build · unknown · high risk
Upstream compiles to WASM for the browser demo. Cosmopolitan does **not**
target WASM, so this would mean a second toolchain and a second build of the
whole stack — arguably out of scope for a project whose premise is one fat
APE.

---

## Cross-cutting, and worth doing before Phase 3

These are already in the README's TODO list and do not depend on any feature.

- **CI**: build both toolchains, run tests, interop and fuzzing. Everything so
  far has been run by hand on one machine.
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
| 1 — self-sufficient | ~1,100 | low |
| 2 — robust | ~1,150 | medium/high |
| 3 — commands | ~1,400 | low |
| 4 — direct paths | ~1,950 | **high** |
| 5 — long tail (excl. SSH/WASM) | ~350 | low |
| 5 — SSH + SFTP | ~5,500 | high |

Roughly **7,000 lines** for everything except SSH, SFTP and WASM, on top of
the ~7,500 that exist — so a little under double the current size. Add SSH and
SFTP and it roughly doubles again.

Phases 1 and 3 are mostly mechanical. Phase 2 and Phase 4 are where the real
difficulty is, and both have failure modes that only appear under load or
over time rather than in a unit test. The pattern from M1–M7 holds: the
dangerous work is where a plausible-looking implementation is subtly wrong,
and the defence is differential testing against the Go implementation plus a
second, stricter toolchain.

**Start with Phase 1.** It is self-contained, low risk, removes the last
external dependency on the Go binary, and 1.2's JSON parser gets reused by
anything later that touches a control document.
