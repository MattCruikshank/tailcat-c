# Plan: closing the gap with tailcat

What tailcat-c would need to reach feature parity with upstream
[tailcat](https://github.com/tailscale/tailcat), roughly in the order worth
doing it.

Today tailcat-c has the **whole data path** — address codec, DERP relay,
WireGuard tunnel, userspace TCP and UDP, and direct peer-to-peer paths with
NAT traversal — plus the SSH and SFTP subset that `recv` and `ls` sit on,
working in both roles and verified against the real Go implementation and
against a real OpenSSH.

**Phases 1–5 are done**, apart from two things that are blocked on something
other than effort: WebAssembly, on a toolchain that does not exist for
Cosmopolitan, and TLS 1.3, on an Ed25519 certificate Mbed TLS cannot parse.

What is left of upstream's surface is deliberate rather than pending:
`serve ssh` as a general shell server, and the read-write and recursive file
modes. Both are recorded in 5.5 with the reasoning, because a drop box that
can run commands or let a sender choose names is not the thing this
implements.

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

**`browse` was deliberately not done here**, and was done later as 5.10. The
reasoning below -- that it is `forward 0:80` plus opening a URL, and so does
nothing a user cannot do in one line -- was right about the forwarding and
wrong about the other half. See 5.10 for what "opening a URL" turned out to
cost, and why.

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

### 4.1 UDP transport and endpoint enumeration ✅ · 545 lines

A UDP socket alongside the DERP connection, local address enumeration, and
sending WireGuard packets to a peer address rather than through the relay.

### 4.2 STUN client ✅ · 314 lines

RFC 5389 binding requests to the relays' STUN ports to learn our public
address. Small and well specified; upstream's is 450 lines of Go.

### 4.3 disco protocol ✅ · 368 lines

`"TS💬"` magic, a sender disco key, a nonce, then a NaCl box from M3.
Three of the nine message types cover basic traversal: `Ping` (0x01), `Pong`
(0x02) and `CallMeMaybe` (0x03); the rest are UDP-relay endpoint allocation
and parse as unknown, which is what an older peer does anyway.

Two decisions worth writing down. `tc_disco_open` takes the key it *expects*
and requires the packet's own sender field to match it — opening with
whatever key the packet names would let anyone seal a valid disco message to
us, which is the one thing sealing is for. And a ping padded past 32 bytes is
not read as a node key: the sender omits that field when it has none, so
zeros there can only be MTU filler, and reading them would invent a peer
identity out of padding.

Verified against `tailscale.com/disco` in both directions — our messages
against theirs, and their bytes through our parser — using inner payloads as
vectors, since the outer nonce is random and cannot be compared.

### 4.4 Path discovery and upgrade ✅ · 954 lines

The hard one, and the reason the original scope excluded it.

**The rule everything rests on:** a path is usable only when a Ping we sent
along it has been answered. Not when we have an address for it, not when a
packet arrived from it, not when it looks plausible. Only a Pong proves the
path carries traffic *inbound*, through whatever NAT is in the way. Every
other signal can be produced by an attacker or by a NAT that will drop the
next packet, and acting on one means sending a live session into a hole.

Switching is only a change to where the next packet is addressed. Nothing is
renegotiated and no state moves, because the WireGuard session is the same
session either way; the new path is proven before it is used and the old one
keeps working while the new one is probed, so there is no moment at which a
packet can be lost. Coming back is the dangerous direction and gets the
conservative treatment: a direct path that goes quiet is abandoned after
`TC_PATH_TRUST_MS` and the relay, which never stopped working, takes over.

Both peers doing this at once needs no leader and no agreement. Each side
decides where its own packets go, so the two directions can differ for a
while — A direct, B still relayed. That asymmetry is correct and closes on
its own.

Tested against a simulated network where the NAT behaviour, the loss, the
delay and the clock are all arguments: two public hosts, two ordinary NATs
punching through, a symmetric NAT that can never work, symmetric-to-public
(which works, but only via the inbound probe), a path dying under a live
session, a path recovering, 40% loss, 100% loss, and a peer flooding the
candidate table. A minute of protocol time costs no wall clock.

Ten mutations of the decision logic were applied. Six survived the first
pass, which is the whole reason for doing it — in particular *nothing* was
testing the one rule above, because no scenario had one-way reachability.
After adding that scenario and four others, nine of ten are caught and the
tenth is an equivalent mutant.

Not implemented, deliberately: relay-to-relay discovery, UDP relay allocation
(disco 0x04 and up), path MTU discovery, and any interface preference beyond
the round trip it produces. Upstream's `magicsock` spends about eleven
thousand lines on all of it.

### 4.5 netcheck ✅ · 620 lines

Per-region latency and NAT-type probing over UDP, replacing the 1.4
heuristic. Every probe goes out at once, so the timeout is a ceiling on the
whole check rather than a per-region cost; 1.4 probed four regions in
sequence and a slow network cost four timeouts.

The scheduling and accounting are separated from the socket, which is the
design decision worth recording. A netcheck whose logic only runs against
live servers can only be *tested* against live servers, and this project does
not put load on Tailscale's infrastructure to check its own arithmetic.
Driven by hand with the clock as an argument, the core is fully exercised
offline -- latency ordering, retransmit rounds, answers arriving after the
deadline, a response bearing a transaction ID we never sent, a response from
the wrong address -- and a whole three-second check runs in microseconds.
`tc_netcheck_run` is the thin loop that wires it to a tc_udp, tested against
STUN responders on loopback.

Seven mutations of the accounting were applied to confirm the tests bite;
all seven were caught.

The mapped address belongs to the socket the probes went out on, so
`tc_netcheck_run` takes the caller's tc_udp rather than opening its own. The
CLI's region selection uses a throwaway socket and keeps only the latencies;
4.4 will run a netcheck on the socket that carries the session.

Not implemented, deliberately: hairpinning, UPnP/PMP/PCP, captive portal
detection. Each is a separate mechanism rather than a reading of these
probes.

**Phase 4 done: 2,801 lines.** The longest phase, as expected.

---

## Phase 5 — the long tail

### 5.1 UDP through the tunnel · the mux ✅ · 466 lines

**Done: `udpmux`**, the layer itself. Building and parsing IPv6+UDP through
the tunnel, listeners, NAT-style bindings for replies, and a bounded receive
queue.

The wire format is checked against packets built by **gopacket**, in both
directions, because the checksum is the part that cannot be checked any other
way. It covers an IPv6 pseudo-header, so a wrong one is completely invisible
to a loopback test — our sender and our receiver would agree perfectly and
nothing else in the world would accept a single packet. That is the same
shape as the IPv6 formatter bug (16), so this time the anchor came first.

Two rules worth stating, both easy to get wrong:

- Over IPv6 the UDP checksum is **mandatory** (RFC 8200 §8.1), because IPv6
  has no header checksum of its own. A zero checksum is malformed, not
  unprotected — applying IPv4's rule here would accept unverified datagrams.
- A checksum that *computes* to zero must be sent as `0xFFFF`, equal in
  ones-complement arithmetic, so zero keeps its meaning of "absent". Getting
  this wrong yields a datagram that is correct 65535 times in 65536. The test
  searches for a payload that lands on it rather than assuming the branch is
  unreachable.

Bindings expire after two minutes idle, per RFC 4787 REQ-5; shorter breaks
request-response protocols that wait longer than that between packets.

Eleven mutations were applied and all eleven are caught — though two of them
had to be rewritten first. One was a false catch (it failed to compile), and
one modelled the wrong bug: removing the zero-checksum rejection merely falls
through to verification, which fails anyway. The hazard is IPv4's rule on
IPv6, where zero means "skip verification"; written that way it is caught. A
mutation that survives is a gap in the tests, but a mutation that is *caught*
is only useful if it was the right mutation.

`udpmux` also gained exit-node mode, symmetric with tcpmux's. Because UDP has
no connection to hang a destination on, it travels with each datagram and
`tc_udp_mux_recv_addrs` reports it. The exposure is slightly worse than TCP's
and the header says so: there is no handshake, so one forged datagram is a
complete request, and plenty of UDP services act on a single one.

**SOCKS5 UDP ASSOCIATE** (RFC 1928 §7) closes this. `socks` now opens a
relay socket per association, carries each datagram to whatever it names, and
brings the answer back with a header saying where it came from — which is
what lets one association talk to several destinations at once and tell the
replies apart.

The association is owned by its TCP control connection, as the RFC requires:
when that closes the relay socket goes. A UDP forwarder left running on a
user's machine for whoever finds the port is not a thing to leave behind.

Getting there needed one more change to `udpmux`, and it was the same lesson
`tcpmux` taught in 5.2: the binding key had to grow to the full tuple. A
reply forwarded by an exit node arrives *from the destination*, not from the
peer, and without the remote address in the key there was no way to tell a
genuine answer from anything the peer cared to invent. `tc_udp_mux_send_as`
is the other half — the server speaking as the destination it contacted.

### 5.2 NAT64 and exit nodes ✅ · 830 lines

These turned out to be one feature. Upstream's `serve <ports>` is TCP only;
UDP and arbitrary destinations both reach a tailcat server through exit-node
mode, and NAT64 is how an IPv4 destination gets there over a tunnel that
carries nothing but IPv6.

`nat64` implements the RFC 6052 well-known prefix `64:ff9b::/96` —
deliberately *not* `::ffff:0:0/96`, which already means "this IPv4 address
written as sixteen bytes" here and is unmapped on sight, so an address
translated into it would come back out as IPv4 at a layer that had no idea
translation was happening. Anchored against RFC 6052 §2.4's published
example and against `inet_pton`, which will do the embedding itself.

`tcpmux` gained exit-node mode, off unless asked for. The change that
mattered was the connection key: once a destination beyond the peer is
possible, the port pair stops being unique, because every exit-node flow goes
to port 443 of somewhere different. Two would collide, and the symptom is not
an error — it is one connection quietly receiving the other's bytes.

`serve exit-node` and `forward <local>:<host>:<port>` expose it, with
`live-exitnode` checking both that a client reaches a third address *and*
that a server which was not asked to forward refuses. The second half is the
one worth having: a default that quietly allowed forwarding would be the most
dangerous kind of bug here, one that only shows up as a feature.

### 5.3 TLS 1.3 ❌ tried, reverted · blocked on Mbed TLS's X.509 parser

Enabling it is easy and it does not work.

The config side is about what was estimated: `MBEDTLS_SSL_PROTO_TLS1_3`, the
PSA crypto layer it requires (`MBEDTLS_PSA_CRYPTO_C` plus HKDF — and *not*
`MBEDTLS_PSA_CRYPTO_CONFIG`, whose defaults drag in ARIA, Camellia, CCM and
DES), about twenty extra Mbed TLS sources, and a `psa_crypto_init()` before
the first context. It builds, links, and costs 232 KB, about 11%.

It also cannot reach a single relay.

DERP servers append a self-signed **meta certificate** to the chain, encoding
the server's public key in its CommonName so a client can skip a round trip.
They send it only on TLS 1.3, because 1.3 encrypts the certificate chain and
1.2 does not. That certificate is **Ed25519**, and Mbed TLS 3.6 cannot parse
an Ed25519 certificate at all — the chain is rejected whole, before any
verification, with `X509 - Signature algorithm (oid) is unsupported`.

The irony is exact: the thing 1.3 would have unlocked is "fast start", which
reads the DERP key out of that meta certificate; and the meta certificate is
what makes 1.3 unusable. Making it work means teaching a vendored TLS library
to skip certificates it cannot parse, in the middle of chain validation,
which is not a change to make for an optimisation we do not implement.

Kept from the attempt: `tc_tls_last_version()`, so the negotiated version is
observable rather than assumed, and a Makefile fix — Mbed TLS objects now
depend on `mbedtls_config.h` explicitly, because `-MMD` stops at the
`-isystem` header that includes it and editing the config rebuilt nothing.

### 5.4 SSH server · ~2,500 lines · **high risk** · **decided: write the subset**

The largest single item. The licence question that gated it has been
answered -- write the subset, with TinySSH as reference rather than
dependency -- so what follows is now a work plan rather than a decision.

**The layers, bottom up.** Each is finished and verified before the next
starts, because a bug in a lower one surfaces in a higher one as "the hash
does not match" and nothing more specific.

- [x] **5.4.1 wire format** · 415 lines, plus 532 of tests · `tc/sshwire.h`.
      RFC 4251 section 5: byte, boolean, uint32, uint64, string, mpint,
      name-list. Anchored byte-for-byte against `golang.org/x/crypto/ssh` by
      `tools/genssh`, including the `ssh-ed25519` key and signature blobs.
      Eight mutations applied, eight caught -- one of them by ASan rather
      than by an assertion, which is how the `max` argument to
      `tc_ssh_get_string` turned out to be the only thing standing between a
      hostile length field and a stack buffer in `tc_ssh_get_cstring`.

      The design decision worth carrying upward is the **sticky error**: the
      reader latches a failure and every later call becomes a no-op, so a
      caller parses a whole packet and asks once at the end. Returning a
      status per call is a design where exactly one call site eventually goes
      unchecked, and there are a dozen per packet.
- [x] **5.4.2 binary packet protocol** · 373 lines, plus 458 of tests.
      Version exchange, packet framing with padding, sequence numbers, and
      `chacha20-poly1305@openssh.com` -- which is not the RFC 8439 AEAD but
      OpenSSH's own construction: two keys, the length field encrypted
      separately so it can be read before the payload is authenticated, and
      the Poly1305 key taken from block zero of the payload keystream.
      Getting the length-field key wrong yields a connection that works
      until a packet crosses a 4KB boundary.
- [x] **5.4.3 key exchange** · 300 lines.
      KEXINIT and negotiation, `curve25519-sha256`, the exchange hash,
      `ssh-ed25519` host key signing, key derivation. Our preference order
      decides, not the peer's, and a wrong first-packet guess is discarded --
      both checked, and the second only catches with a peer whose favourite
      is an algorithm we support but rank lower.
- [x] **5.4.4 userauth** · 250 lines · publickey only. One function rather
      than two, deliberately: there is no way to verify a signature without
      also checking the key is authorized, because the version of this that
      has a bug has exactly that shape.
- [x] **5.4.5 connection layer** · 330 lines · one channel, flow control,
      `subsystem` and `exec`, everything else refused *and answered*.
- [x] **5.4.6 the server** · 640 lines · the transport state machine over a
      pair of callbacks rather than a socket, so the same code serves over
      the tunnel later. `make live-sshd` puts a real OpenSSH 9.6 client
      against it.

      That test found the bug offline testing structurally could not: the
      padding rule differs between the two ciphers, and the "none" cipher in
      force before NEWKEYS uses RFC 4253's plain rule where the length field
      *is* counted. Every vector we had was encrypted, so every handshake
      packet was four bytes out of alignment and OpenSSH rejected all of
      them. See bug 22.
- [x] **5.4.7 rekeying** · 135 lines · as a responder. A peer may start a
      key exchange at any point and we complete it; we never start one.

      Handled in `recv_packet` rather than in each caller, for the same
      reason SSH_MSG_IGNORE is: a peer may rekey at any moment, and a state
      machine that only tolerates one where it expects one works against one
      implementation and hangs against the next. `do_kex` and the rekey path
      now share one `kex_exchange`, differing in exactly two places -- who
      sent KEXINIT first, and whether the session id is set.

      Three details that are each a silent corruption if wrong, and all
      three are caught by mutation:
      - The **session id does not change**. It is H from the first exchange
        and the derivation folds it into every later key, which is what
        binds new keys to the identity proven at the start.
      - The **sequence number does not reset** (RFC 4253 6.4). It is also
        the cipher nonce, so resetting it would repeat a nonce under the new
        key on the very first packet after the rekey.
      - **NEWKEYS is not symmetric.** Our send key goes in immediately after
        our NEWKEYS goes out; their receive key can only go in *after* their
        NEWKEYS has been read, because that message is the last one still
        under the old key.

      What remains bounded is the sequence number wrapping at 2^32 packets,
      which a peer that rekeys on any sane schedule never approaches.
      Initiating ourselves would remove even that, at the cost of buffering
      channel data between our KEXINIT and the peer's reply -- RFC 4253 7.1
      requires us to keep accepting it. Not worth it for a drop box.

The decision and its alternatives remain recorded below, because a decision
whose reasoning is thrown away is one that gets relitigated. Full detail is in the README under
[Vendoring an SSH server](README.md#vendoring-an-ssh-server); the summary:

| | Licence | Verdict |
|---|---|---|
| TinySSH | public domain | usable; a port, not a drop-in (Unix-only, own NaCl) |
| Dropbear | MIT | usable, but ~30k lines and a second crypto stack |
| OpenSSH portable | BSD-ish | reference implementation, deeply Unix-specific |
| libssh | LGPL-2.1 | obliges us to ship relinkable objects |
| wolfSSH | GPLv3 / commercial | would relicense this project |
| libssh2 | BSD-3 | **client only** — cannot do this |

**Recommendation: write the subset.** We do not need an SSH server; we need
`sftp` over SSH with publickey auth, which is transport and key exchange
(`curve25519-sha256` — X25519 and SHA-256, both already here),
`chacha20-poly1305@openssh.com` (already here), publickey userauth, and a
single channel with only the `subsystem` request. No PTY, no port
forwarding, no agent forwarding, no shell — which is most of what makes a
general `sshd` large, and all of which a drop box should not have.

The one real gap **was Ed25519**, and it is now done: `tc/ed25519.h`, 877
lines, checked against RFC 8032's published vectors and byte-for-byte against
Go's `crypto/ed25519`. So `ssh-ed25519` keys need no `ecdsa-sha2-nistp256`
fallback.

The estimate drops from ~4,000 lines to ~2,500 precisely because the scope
is the subset rather than a general server.

### 5.5 SFTP server ✅ · 944 lines, plus 789 of tests · **done**

Serves the server side of `cp` and **`recv`**, which moved here from 3.5. The
`ls` client is still a choice, and the reasoning for it is kept below.

Two files, deliberately apart. `tc/sftp.h` is the version 3 wire format and
has no opinions; `tc/dropbox.h` has nothing but opinions. Keeping them
separate means a change to parsing cannot quietly become a change to
permissions.

**The guarantee is one sentence: a sender cannot choose the stored
filename.** Everything else follows from it or guards it -- only the final
path component is considered, which defeats every traversal at once; the
result is sanitised and made unique; a collision picks a different name
rather than overwriting, and the chosen name is never sent back, because
returning it would leak the directory contents the rule protects.

The sanitiser refuses more than a Unix server would need to, because this
binary runs on Windows: the reserved device names (`nul`, `con`, `com1` and
the rest, with or without an extension), a trailing dot or space -- which
Windows strips before opening, so `evil. ` and `evil` are one file there and
two names here -- and the characters Windows forbids outright. One name means
one thing on every platform we ship to.

Ten mutations, ten caught. Six live checks with a real `scp` and `sftp`, and
the live test is the one that matters: a policy that is right against
requests we constructed can still have a gap a real client walks through.
Two of the ten mutations are caught by the live test as well, and one --
refusing a read-open -- is not, because `sftp` gives up at the stat and never
reaches the open. Two independent barriers, one tested at each level, and
that is recorded in the script rather than left to look like a gap.

**Still flat only.** No directories, so no recursive upload. Upstream offers
that as `:wo+` and documents that it trades the guarantee away -- once a
sender can create directories it can choose names again. If it is added it
should be a separate mode with the trade stated, not a relaxation of this
one.

This is where the "writes attacker-named files" hazard lives. Upstream's flat
write-only mode is the design to copy rather than improve on: the server
chooses every stored name, so a sender can neither overwrite anything nor
learn what is already in the directory. The recursive mode (`:wo+`,
`--accept-dirs`) trades exactly that away, and upstream documents the
trade-off rather than hiding it.

**How upstream does these three is not uniform**, and it is worth being
precise about because it decides how much we would have to write:

| | upstream | ours |
|---|---|---|
| `ssh` | execs the system `ssh` (`exec.LookPath("ssh")`) | same |
| `cp` | execs the system `scp` (`exec.LookPath("scp")`) | same |
| `ls` | **in-process**: `golang.org/x/crypto/ssh` + `github.com/pkg/sftp`, dialling port 22 through its own tunnel | not implemented |

So for `ssh` and `cp` we already match upstream exactly. `ls` is the odd one
out: upstream does not shell out to the system `sftp` binary, it links an SSH
client and an SFTP client and drives them itself, which is where a good part
of that ~20,000 lines of Go dependency goes.

**Decided: write the SFTP client** (`tc/sshclient.h` plus the client half of
`tc/sftp.h`, 1,100 lines). `ls` now does what upstream does -- no `sftp`
binary involved, output that matches, and nothing to be missing on Windows.
`make live-ls` lists a directory served by a real Go tailcat.

The alternatives, and why they lost:

- **Exec the system `sftp`** (`sftp -b`). Consistent with how we already do
  `cp`, and needs no SFTP client at all. The cost is that the output is
  whatever the local `sftp` prints, so `tailcat-c ls` and `tailcat ls` would
  not agree on formatting, and it needs an `sftp` binary present — which on
  Windows is not a given.
- **Write an SFTP client** (~400 lines for the handful of packets `ls`
  needs: `SSH_FXP_STAT`, `SSH_FXP_OPENDIR`, `SSH_FXP_READDIR`). Matches
  upstream's output, needs no external binary — but needs an SSH *client*
  too, and we have neither.

Worth noting the ordering: an SFTP client is only cheap **after** 5.4 exists,
because it needs an SSH transport to run over. Before then, execing is the
only option that works at all.

Upstream's `ls` also disables host key checking, for the same reason our
`ssh` wrapper does: "The WireGuard tunnel already authenticated the server by
its node key in the tailcat address, so the SSH host key adds nothing." Good
to know we reached the same conclusion independently.

### 5.6 WebAssembly build · blocked on the toolchain

Upstream compiles to WASM for the browser demo. Cosmopolitan does **not**
target WASM: cosmocc is GCC for x86_64 and aarch64, and there is no clang,
emscripten or wasi-sdk in this environment to fall back on. This would mean a
second toolchain and a second build of the whole stack.

It is also the item most in tension with the premise. The selling point of
this project is *one file that runs everywhere*; a WASM build is by
definition a second artifact that runs somewhere else. Worth doing only if
the browser demo is the point, rather than as parity for its own sake.

Two things would need solving beyond the toolchain: there are no raw sockets
in a browser, so DERP would have to run over WebSocket as upstream's demo
does, and the direct-path work from Phase 4 has nothing to stand on — a
browser cannot open a UDP socket at all, so a WASM build is relay-only by
construction.

### 5.7 the allow list ✅ · ~300 lines

`--allow` restricts a server to named client node keys, matching upstream's
flag. Small, and worth a note for one decision inside it: `tc_allow_permits`
refuses the all-zero key **before** it checks whether a list exists at all.

The ordering is the whole point. The natural shape is "no list configured, so
permit everything", with the sanity check on the key somewhere after it — and
that admits the all-zero key in exactly the permissive configuration where
nobody is watching for it. A refusal that only applies once you have already
opted into restriction is not a refusal.

Without `--allow`, and especially with `serve exit-node`, anyone holding the
address can reach anything the serving machine can, including loopback
services and cloud metadata endpoints. It is off by default because that is
upstream's default, not because it is the safe one.

### 5.8 TCP hardening ✅ · ~120 lines

Not planned; found. Making `tests/fuzz_tcp.c` assert its own reach turned up
two ways a single authenticated peer could permanently exhaust the 64-entry
connection table — a corrupt SYN leaving an unreapable connection in
`LISTEN`, and a vanished peer leaving one in `ESTABLISHED` with no timer
watching it. The second is fixed with keepalive probes, which detect a peer
that does not *answer* rather than one that is merely quiet.

The README has the detail as bugs 20 and 21, including the third bug the fix
contained (a deadline the tick declined to act on, so a caller sleeping until
it would spin) and the fourth it revealed (a zero-length keepalive probe, of
the kind a Linux kernel sends, drew no acknowledgement at all).

What it says about method is the reusable part: the fuzzer had been reporting
the same 64 accepted connections at 20,000 iterations and at 200,000, and
nothing was watching that number. Every harness now fails if it stops
reaching the code it exists to exercise.

### 5.9 `readme` ✅ · ~175 lines, mostly prose

Skipped once as "not worth writing", which was half right and half a wrong
reason. The command is four lines -- upstream is a `//go:embed README.md` and
a write to stdout -- so effort was never the objection. What was missing was
the *document*. Upstream's README.md is 30 KB of user documentation, so
embedding it answers the question a user is asking. Ours is 83 KB of
engineering log, and printing 1,400 lines about mutation testing to someone
who typed `readme` would answer a question nobody asked, for four per cent of
a binary whose size is a selling point.

So `doc/usage.md` was written to be the thing worth embedding: examples,
flags, and the three things a user can get wrong here -- that the address is a
bearer credential, that `serve exit-node` reaches loopback, and that `ssh`
turns off host key checking. `scripts/gen-usage.py` turns it into
`src/usage_text.c`, the way `gen-ca-bundle.py` does for the certificate list.

Two decisions inside it are worth keeping:

- The generated file is committed, so a build needs no Python, but it is
  **not** a prerequisite of the object file in the Makefile. A checkout sets
  mtimes in whatever order it likes, and a build graph that can decide to
  shell out to `python3` is one that breaks on a machine without it.
  `make usage-text` regenerates by hand and level 1 fails if the two have
  drifted, which is the same shape as the crypto and SSH vector checks.
- The generator **refuses non-ASCII**. `doc/usage.md` was written with em
  dashes, which is right for a Markdown file and wrong for something printed
  to a terminal on six operating systems that do not agree about encoding.
  Every other byte this program emits is ASCII; the check makes that true by
  construction rather than by remembering.

### 5.10 `browse` ✅ · ~700 lines, half of them tests

The last command, and the one PLAN had called "the only part of upstream's
command set that does nothing a user cannot do in one line". That was true of
the *forwarding*, which is `forward 0:80`, and it quietly assumed the other
half -- pointing a browser at the result -- was a call to `system()`. It is
not, for three reasons, and the reasons are the content of `src/browser.c`:

- **There is no shell.** The conventional Windows incantation is
  `cmd /c start <url>`, which hands a URL to a command interpreter; the Go
  package upstream uses carries an `&` -> `^&` escape that exists only
  because of it. `rundll32 url.dll,FileProtocolHandler` takes an argv, so it
  is tried first. Every opener is exec'd from an argv array, and the URL is
  built in one function out of four numbers and a port, which refuses
  anything that is not a dotted quad rather than guessing.
- **The opener depends on the operating system, which a fat APE does not
  know until it runs.** `#ifdef __APPLE__` is a question about the compiler,
  and the same binary starts on six systems. `tc_host_os` asks Cosmopolitan
  at runtime through `IsWindows()` and friends, and falls back to
  compile-time detection under a host compiler, where the question really is
  settled at build time. (`config_dir` in the CLI still has the compile-time
  form, and is wrong on macOS for exactly this reason -- noted under
  Cross-cutting.)
- **Not every machine should be asked.** A headless Linux box and an ssh
  session both have no screen to put a window on. Upstream's package checks
  `$DISPLAY`; this also accepts `$WAYLAND_DISPLAY`, because the question is
  about screens rather than about X11. `$BROWSER` overrides all of it, which
  is the one deliberate difference from upstream: someone who has named a
  text browser on a headless machine has already answered.

`forward` gained `--open-browser`, as upstream's has, and it is refused with
more than one mapping because there is one browser.

The browser is opened **after** the tunnel is up rather than when the
listener binds, which is where upstream does it. Opening a window on
someone's desktop is a visible act, and the file already had the same rule
for the child process `socks -- cmd` starts: do it once there is something
behind the address.

Twenty-five mutations, all killed -- but only after the tests stopped
borrowing the environment. See the README: three of them survived because
`xdg-open` implements the same `$BROWSER` convention we do, so a build that
ignored ours still ran the recorder by a longer route.

## Phase 6 — reading the documentation as a user would

### 6.1 Walking upstream's README ✅ · ~450 lines, most of them tests

Every instruction in upstream's README, typed at our binary, with the result
written down in [doc/upstream-readme.md](doc/upstream-readme.md). The feature
table already said what was implemented; this asked what a person *following
the documentation* actually sees, which turns out to be a different question
with a worse answer.

Five things were wrong. Two were found by reading the argument parser while
planning the walk, before running anything:

- **`--flag=value` was not accepted anywhere.** Upstream's README is written
  almost entirely in that spelling, so nearly every flag example produced
  `unknown flag`.
- **`parse` printed a table where upstream prints JSON**, so every `| jq`
  in circulation worked against the real thing and not against ours. Now
  byte-identical, pinned by `make parse-interop` over 500 generated
  addresses.

Three more came out of the walk itself, and are README bugs 32 and 33. The
one worth carrying forward is that `ssh <addr> ls -l` *worked* while quietly
dropping the `-l`, because our own `ls -l` flag was parsed before the
subcommand was known. An error message is a bad outcome a user can see. A
changed command is a bad outcome they cannot.

What the walk confirms: the data plane, `serve` in every form, all the
`forward` mapping shapes, `browse`, `socks`, exit nodes, the whole key
workflow including the magic `default` key, and `parse`/`resolve` producing
upstream's bytes exactly. Region names resolve to upstream's own numbers.

One near-miss worth recording as method. Upstream's `ping` appeared to fail
against our server -- `context deadline exceeded` -- which would have been a
serious interop finding. It was the test's fault: a `serve` with no ports and
the default ten-second timeout. Given ports and thirty seconds, upstream
pings us in 5.61ms over a direct path. The rule that saved it is the same one
bugs 7 and 8 taught: when an interop test fails, suspect the scaffolding
first.

### 6.2 What the walk showed is missing ⏸ · not started

None of these is hard. They are listed because the walk is the only thing
that found them: each is a feature the table called done, or did not mention
at all, and a user following upstream's documentation meets them immediately.
In rough order of what they cost:

1. ~~**`socks <addr> <cmd>` without `--`**~~: done. The argument after the
   address is a port if it reads as one and the start of a command if it
   does not, and `--` still works for the one ambiguous case, a command
   whose name is a number. It needed the same pass-through `ssh` and `cp`
   got in bug 32 -- `socks <addr> python3 x.py --from-env 18082` had
   `--from-env` read as ours -- which is the third subcommand to want it and
   an argument for making that the rule rather than the exception.
2. **`ping --until-direct`.** Bigger than this list first said, and the
   correction is the useful part: it claimed "path discovery already reports
   which path a reply arrived on, so this is a loop and an exit code". That
   is false. `ping` here is relay-only -- it opens a DERP connection, sends a
   meow ping, waits for the reply -- and never attempts a direct path, so
   there is nothing to loop on and the flag could only ever fail.

   Doing it properly means rebuilding `ping` on the client stack the pipe
   uses: `client_up` for the tunnel, `path_bring_up` for discovery, a pump
   loop to drive them, and `tc_path_best` to ask which way the last reply
   came. Every piece exists; none of them is currently wired into `ping`,
   and the pump is the fiddliest code in the project. Call it a day's work
   touching the part with the worst failure modes, not an hour.

   It would also close the cosmetic gap in the walkthrough: upstream's ping
   names the direct path it used, and ours can only ever name a relay
   because a relay is all it has.
3. **Reaching a third address from the pipe form and `ssh -p ip:port`.**
   `forward` parses `local:ip:port` and `serve exit-node` serves it, so both
   ends exist; what is missing is accepting the syntax in two more places and
   routing through `tc_nat64_wrap` as `forward` does. Both refuse it by name
   today rather than connecting somewhere else -- see bug 34 for why that
   sentence had to be written.
4. **`genkey --fixed-region` and `genkey --region=<relay-hostname>`.**
   `--relay` already pins a relay for one `serve`. What is missing is baking
   the choice into a *saved key*, which is what lets a published address
   survive a restart. The key file format would gain a field.
5. **`socks` recognising a tailcat address as a URL hostname**, which is what
   makes its address argument optional. Our SOCKS server already ignores the
   requested hostname except for `server.tailcat`; this means parsing it as
   an address instead and dialling it.
6. **Addresses in DNS TXT records.** The largest of these, and the only one
   that adds a dependency: a resolver, and with it upstream's safety check,
   which probes a DNS-named server as a stranger would and refuses to connect
   if that login succeeds. Publishing an address makes it public, so the
   server has to authenticate clients by something other than knowing it --
   which is exactly what `--allow` is for, and that is already here. Without
   the check, this feature would quietly encourage the mistake it exists to
   prevent, so the two land together or not at all.

Not on this list, and deliberately: the `ssh`, `no-auth-ssh`, `exec` and
`files` services (5.4 and 5.5 say why), and bare `tailcat` starting a server,
which is a one-line change this project declines because printing usage for
a bare invocation is better behaviour and the explicit `serve` is right
there.

---

## Cross-cutting

These are already in the README's TODO list and do not depend on any feature.

- ~~**CI**~~: done differently. `make diag5/3/1` and a pre-push hook run the
  checks locally in three tiers; see the README. Hosted CI was rejected
  deliberately -- the live tests dial Tailscale's production relays, and that
  is not something to automate on every push.
- ~~**aarch64**~~: done. `make test-aarch64` runs all 36 test binaries on
  real aarch64 instructions under qemu-user, and they pass -- 9,979
  assertions, first attempt. Both halves of every fat binary now execute
  their own instructions, where for most of this project's life one half had
  been compiled and never invoked. `make test-unsigned-char` remains as the
  cheap check that needs no emulator. Above this: qemu-system, which would
  exercise Cosmopolitan's own aarch64 runtime rather than only our code
  (qemu-user translates syscalls to the host kernel), and then hardware.
- **Test on macOS and the BSDs.** Two of six target operating systems are
  covered. With aarch64 executing, what is left is the operating systems,
  and that is now the largest untested claim -- and the one an emulator and
  a package cannot close.
- **Extend fuzzing** to the DERP frame codec, which is the last of the three
  originally listed here — the JSON parser and the TCP input path both have
  harnesses now. The frame codec parses attacker-influenced lengths straight
  off a socket, which is the shape that produced bugs 20 and 21.
- **Extend mutation testing** beyond path discovery, the UDP mux, TCP, the
  SSH subset and the browser opener, which are the only modules it has been
  applied to. It found gaps in every one of them, at a rate that suggests the
  rest have them too.
- **`config_dir` is decided at compile time and should not be.** It picks
  `~/Library/Application Support` under `#ifdef __APPLE__` and `~/.config`
  otherwise, which is a question about the compiler. cosmocc does not define
  `__APPLE__`, so the shipped binary takes the `~/.config` branch *on macOS*
  -- and the comment above it says it exists precisely so that a key saved by
  upstream's Go tailcat is found by ours. It is not, on a Mac. `tc_host_os`
  (added for `browse`, PLAN 5.10) answers the question at runtime and is the
  fix; it is small, and it needs a Mac to verify, which is the same thing
  blocking the line above.
- **Constant-time audit** with actual timing measurements, rather than the
  current "written in a data-independent style".
- **Thread-safety**: either make `tc_derp_client` safe for concurrent use or
  state plainly that callers must serialise it.

---

## Totals and honest expectations

| Phase | New C | Status |
|---|---:|---|
| 1 — self-sufficient | ~1,330 | ✅ done |
| 2 — robust | ~1,390 | ✅ done |
| 3 — commands | ~1,970 | ✅ done |
| 4 — direct paths | 2,801 | ✅ done |
| 5.1 — datagrams, and SOCKS5 UDP ASSOCIATE | ~870 | ✅ done |
| 5.2 — NAT64 and exit nodes | ~830 | ✅ done |
| 5.3 — TLS 1.3 | — | ❌ blocked on Mbed TLS’s X.509 parser |
| 5.4 — the SSH subset, server and rekey | 2,648 | ✅ done |
| 5.5 — SFTP, the drop box, and `recv` | 1,194 | ✅ done |
| 5.5 — `ls`, with SSH and SFTP clients | 1,100 | ✅ done |
| 5.6 — WebAssembly | ? | ⏸ no toolchain |
| 5.7 — `--allow` list | ~300 | ✅ done |
| 5.8 — TCP hardening (bugs 20, 21) | ~120 | ✅ done |
| 5.9 — `readme` and `doc/usage.md` | ~175 | ✅ done |
| 5.10 — `browse` and `--open-browser` | ~700 | ✅ done |
| 6.1 — walking upstream’s README | ~450 | ✅ done |
| 6.2 — the gaps it found | ? | ⏸ not started |
| — Ed25519 (RFC 8032) | 877 | ✅ done |

The estimates held up better than expected in aggregate and badly in
particulars. Phase 4 came in at 2,801 against ~1,950 estimated — the extra is
almost entirely test scaffolding for the simulated networks, which was the
right place to spend it. Phase 5.4 went the other way, from ~4,000 to ~2,500,
because the scope turned out to be "sftp over ssh" rather than "an ssh
server". The one that was simply wrong was 3.5 (`recv`), estimated at ~300
lines and actually a subset of 5.5.

Source today is **26,629 lines** under `src/` plus 5,721 of headers, against
**20,286** of tests and another 3,427 of shell for the live ones. (189 of
that `src/` figure are generated: `doc/usage.md` as a C string literal.)
Counting the live scripts as tests, which is what they are, that is roughly
23,000 of checking against 26,000 of implementation. The 1:1 ratio predicted
at the start has held to within about ten per cent for the whole project,
and the ratio has been the useful number rather than either total.

Phase 2 and Phase 4 were where the real difficulty was, and both had the
failure modes predicted for them: things that only appear under load or over
time. Phase 2's rekey bug took a two-hour simulated run with 5% loss to
surface; Phase 4's worst bug was invisible to every unit test and showed up
on the first end-to-end run. The defence held — differential testing against
the Go implementation, a second stricter toolchain, and simulated networks
where the clock is an argument — with one addition worth carrying forward:
**mutation testing**, which found that six of ten assertions about path
discovery were not actually being made.

### What to do next

1. **Run the aarch64 half**, which is now half done. `make
   test-unsigned-char` passes: `char` really is signed on cosmo x86_64 and
   unsigned on cosmo aarch64, and all 35 test binaries pass under the other
   signedness. `make test-aarch64` runs the real aarch64 instructions under
   qemu-user and is written and waiting on `qemu-user-static` being
   installed. cosmocc emits a plain `.aarch64.elf` beside each binary, so no
   APE assimilation is needed. After that: qemu-system, then hardware.

   This is now the largest untested claim in the project by some way: four
   of six target operating systems and half of every binary.
2. **Upstream's other file modes**, if they are wanted: `:rw` and the
   recursive write-only `:wo+`. The second trades away the drop box
   guarantee by design and should be a separate mode with the trade stated,
   not a relaxation of the flat one.
3. **Bound `FIN_WAIT_2`.** Keepalive and idle timeout are done (bug 21), and
   they cover the peer that vanishes. They do not cover the peer that is
   alive, answers every probe, and simply never sends its FIN: nothing bounds
   that state, exactly as on any stack that has not added a
   `tcp_fin_timeout`. Small, and the table it protects holds sixty-four
   entries.
4. **Fuzz the DERP frame codec, and mutate the modules that have never been
   mutated.** Both are listed under Cross-cutting, and both are cheap next to
   what they have historically returned: every module mutated so far gave up
   at least one assertion that was not actually being made, and the TCP
   fuzzer found two table-exhaustion bugs within minutes of being made honest
   about its own reach.
5. **Make reaping automatic, or say plainly that it is not.**
   `tc_tcp_mux_reap` has to be called or closed connections hold their slots.
   That is now less dangerous than it was — bugs 20 and 21 removed the two
   ways connections got stuck *unreapable* — but it is still a caller
   obligation documented in one header and easy to miss.

WebAssembly is last on purpose, and possibly never: it is a second artifact
for a project whose premise is one file, and a browser cannot open a UDP
socket, so a WASM build would be relay-only by construction — throwing away
the whole of Phase 4.
