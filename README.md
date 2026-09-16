# tailcat-c

A rewrite of [tailcat](https://github.com/tailscale/tailcat) in C11, built
with the [Cosmopolitan](https://github.com/jart/cosmopolitan) C compiler into
a single **fat Actually Portable Executable** — one binary that runs on
Linux, macOS, Windows, FreeBSD, OpenBSD and NetBSD, on both x86_64 and
aarch64.

**Status: the agreed scope works, on two operating systems.** `tailcat-c`
both serves and connects, interoperates with the real Go tailcat in both
roles, and the *same fat binary* does it on Linux and on Windows:

```console
$ echo 'the quick brown fox' | tailcat-c -v tcpGFwWCDMihnYWAeovm...
# relay tc301a.ipn.dev
# meowed: the server has added us as a peer
# tunnel up
# connected
```

and the Go server prints `the quick brown fox` on its own stdout.

It works the other way round too: `tailcat-c serve` mints an address that the
**real Go client** accepts, answers its WireGuard handshake as the responder,
and writes what it receives to stdout.

`scripts/live-cross.sh` runs one binary against itself across both operating
systems, in both directions, through a real relay:

```
one binary, 1759283 bytes, run by both operating systems

== A: Windows transmits -> Linux receives ==
  the Linux server received: hello from Windows
== B: Linux transmits -> Windows receives ==
  the Windows server received: hello from Linux
```

Everything is a single fat Actually Portable Executable with no dependencies
beyond a vendored Mbed TLS. See [Limitations](#limitations) for what this
deliberately does not do, and [Known TODOs](#known-todos) for the loose
ends.

## Why this is a big job

tailcat's own source is ~8,900 lines of Go, which undersells it badly: it is
a thin shell over a very large data plane it does not own. A working rewrite
has to reimplement, at minimum:

| Component | Go LOC | Needed for |
|---|---:|---|
| tailcat itself | 8,884 | everything |
| `wgengine/magicsock` | 11,243 | DERP muxing, NAT traversal |
| `derp` (client half) | ~2,500 | relay transport |
| `netcheck`, `stun`, `disco`, `types/key` | 4,683 | relay selection, path discovery |
| `wireguard-go` | ~10,000 | the actual encryption |
| `gvisor` netstack | 100,000+ | userspace TCP, since tailcat touches no routing tables |
| `gliderssh` + `x/crypto/ssh` + `sftp` | ~20,000 | only the SSH/SFTP features |

## Scope

This implementation targets the **DERP-relay-only interop core**: fully wire
compatible with real tailcat, but relaying through DERP rather than
establishing direct peer-to-peer paths — exactly what tailcat's own
WebAssembly web demo does today. That drops `magicsock`'s hardest parts
(disco, netcheck, endpoint scoring, path upgrade) while still talking to the
real thing, and it is a strict subset of the full data plane, so direct
paths can be added later without redesign.

Out of scope for now: direct P2P/NAT traversal, the SSH server, SFTP, the
SOCKS proxy, and the browser/WASM build.

## How it compares

### Size

Both columns are release builds: upstream with its own `-s -w` and 75
`ts_omit_*` tags from `.goreleaser.yaml`, ours stripped by cosmocc.

| | tailcat-c | tailcat (Go) |
|---|---:|---:|
| binary | **1.75 MB** | 17.67 MB |
| gzipped | **0.86 MB** | 6.77 MB |
| files needed for 6 OSes × 2 arches | **1** | 12 |

The ratio is about 10×, and **most of it is the feature gap below, not
craftsmanship**. A Go binary also carries a runtime, a garbage collector and
reflection metadata that a C program does not, which accounts for a good part
of the rest. The interesting number is not 1.75 MB, it is that one file covers
every target: our own protocol code is only ~40 KB of it, and the single
largest thing we add is the 181 KB CA bundle.

### Features

| | tailcat-c | tailcat |
|---|:--:|:--:|
| **Data plane** | | |
| WireGuard tunnel (Noise IKpsk2) | ✅ | ✅ |
| Pre-shared key layer | ✅ | ✅ |
| DERP relay transport | ✅ | ✅ |
| Bring your own relay | ✅ | ✅ |
| Direct peer-to-peer path (NAT traversal, disco, STUN, netcheck) | ❌ | ✅ |
| Rekeying / session renewal | ✅ | ✅ |
| Cookie reply (DoS mitigation) | ✅ | ✅ |
| DERP map fetch | ✅ | ✅ |
| Region choice by latency | approximate | ✅ (netcheck) |
| Multiple concurrent connections | ✅ | ✅ |
| UDP forwarding | ❌ | ✅ |
| IPv4 into the tunnel via NAT64 | ❌ | ✅ |
| TLS to the relay | 1.2 | 1.2 + 1.3 |
| **Commands** | | |
| pipe stdin/stdout to a server | ✅ | ✅ |
| `serve` | ports, ranges, `all`; many clients | full |
| `parse` | ✅ | ✅ (JSON) |
| `version` | ✅ | ✅ |
| `ping` | ✅ | ✅ |
| `resolve` | ✅ | ✅ |
| Multiple concurrent clients | ✅ (8) | ✅ |
| `forward` (local TCP port forwarding) | ✅ | ✅ |
| `socks` (SOCKS5 proxy) | ✅ (one server) | ✅ (many) |
| `socks -- <cmd>` with `all_proxy` | ✅ | ✅ |
| `ssh` / `cp` (via the system ssh and scp) | ✅ | ✅ |
| `ls` (SFTP remote listing) | ❌ | ✅ |
| SSH *server* (`serve ssh`) | ❌ | ✅ |
| `recv` (file drop box, receiving) | ❌ (needs SSH+SFTP) | ✅ |
| `cp` *into* a `tailcat recv` drop box | ✅ | ✅ |
| `genkey`, `printpub` (saved identities) | ✅ | ✅ |
| `browse`, `readme` | ❌ (not worth writing) | ✅ |
| **Platforms** | | |
| Linux, Windows | ✅ tested | ✅ |
| macOS, FreeBSD, OpenBSD, NetBSD | built, untested | ✅ (macOS) |
| aarch64 | built, never executed | ✅ |
| Browser (WebAssembly) | ❌ | ✅ |
| Persistent keys on disk | ❌ | ✅ |

So: tailcat-c does the **core data path** — address, relay, tunnel, TCP — in
both roles and interoperably. Everything built *on top* of that data path is
upstream's, and that is most of what a user actually reaches for.

## Build

Requires the [cosmocc](https://github.com/jart/cosmopolitan) toolchain:

```sh
mkdir -p ~/cosmocc && cd ~/cosmocc
curl -fsSL -o cosmocc.zip https://cosmo.zip/pub/cosmocc/cosmocc.zip
unzip -o cosmocc.zip
```

Then:

```sh
git clone --recurse-submodules https://github.com/MattCruikshank/tailcat-c
make            # build
make test       # unit tests; also asserts every binary is a fat APE
make fuzz       # fuzz/property tests under ASan + UBSan (host gcc)
make interop    # cross-check against the real Go tailcat library
make live       # connect to a real DERP relay and relay a packet (needs network)
make live-wg    # handshake against a real wireguard-go device
make live-tailcat  # full tunnel with a real tailcat server (needs network)
make live-cli      # drive the CLI end to end against a real server
```

And, from Git Bash on Windows rather than from inside WSL, since it drives
both sides:

```sh
sh scripts/live-cross.sh   # one binary, two operating systems, both ways
```

### Checking it

Local, tiered, numbered like Starfleet diagnostics -- **1 is the one where you
take the panels off**, 5 is the quick sweep:

```console
$ make diag5     # ~5s    did I just break the build
$ make diag3     # ~30s   both toolchains, sanitizers, fuzzing, crosscheck
$ make diag1     # long   the above from a clean tree, plus every live test
```

Level 3 runs before every push. Install the hook once:

```console
$ git config core.hooksPath scripts/githooks
```

`TC_DIAG=5 git push` drops to the quick sweep and `TC_DIAG=0 git push` skips
it, for when you know better.

Levels 4 and 2 are deliberately undefined rather than missing: three tiers is
what the work divides into, and two more would be distinctions nobody would
remember.

The split is about more than duration. **Level 1 is the only level that
touches the network**, because the live tests dial Tailscale's production
relays and run a real `tailcat` -- which is a thing to do deliberately before
a release, not on every push. It is also the only level that starts from
`rm -rf build`, which is what rules out the stale-object class of bug that
went unnoticed here for the whole project.

Every stage times itself, so the cost of each level stays a measured fact
rather than an estimate in a comment.

Then:

```console
$ tailcat-c serve                          # listen; prints an address
$ echo hello | tailcat-c <tc-address>      # pipe to a server
$ tailcat-c serve 22,80,8000-8999          # proxy local ports
$ tailcat-c forward <tc-addr> 18080:80     # reach its port 80 on ours
$ tailcat-c socks <tc-addr> 1080           # or via a SOCKS5 proxy
$ tailcat-c genkey --key default --region 301  # a stable address
$ tailcat-c ssh <tc-addr> uptime           # via the system ssh
$ tailcat-c ping <tc-address>              # time the round trip
$ tailcat-c resolve <tc-address>           # embed the relay, for offline use
$ tailcat-c parse <tc-address>             # describe an address
```

The address must be self-contained; run `tailcat resolve` on a short one,
since fetching the DERP map is not implemented.

Mbed TLS is a pinned submodule, so `--recurse-submodules` matters; an
existing clone needs `git submodule update --init`.

`make CC=gcc test` builds with the host compiler instead, which is useful
under sanitizers.

### Building on Windows

The toolchain runs under WSL. `scripts/wslmake.sh` wraps it and handles a
WSL-specific problem: WSL registers a `binfmt_misc` handler for anything
starting with `MZ`, which swallows Actually Portable Executables and hands
them to Windows — and cosmocc runs APE tools during its own build, so it
fails outright. The wrapper disables that handler and registers
Cosmopolitan's loader instead, in the same invocation as the build, because
`binfmt_misc` is per-WSL-instance state and WSL tears the instance down as
soon as its last process exits.

```sh
scripts/wslmake.sh 'make test'
```

## Verification

The address layer is checked three ways:

1. **Golden vectors ported from upstream.** `tests/test_addr.c` uses the
   exact addresses and malformed-input cases from tailcat's own
   `tailcat_test.go` (`TestAddr`, `TestParseAddrMalformed*`,
   `TestParseAddrNullInArrays`).
2. **Differential testing against the real Go library.** `make interop` has
   `tools/genaddrs` generate thousands of random addresses using the actual
   `github.com/tailscale/tailcat` package, then requires the C code to parse
   each one and re-encode it *byte for byte identically*. That single check
   pins field order, the `omitempty` rules, shortest-form CBOR integers and
   the elide/restore transforms all at once. 2,000 addresses currently pass.
3. **Fuzzing.** `make fuzz` mutates a seed corpus under ASan and UBSan,
   asserting no crashes and that any address that parses survives an
   encode/parse round trip unchanged.

The crypto layer is checked the same way. `tools/genvectors` derives
`tests/crypto_vectors.h` from `golang.org/x/crypto/{blake2s,chacha20poly1305,
curve25519}` and wireguard-go's own exported `KDF1`/`KDF2`/`KDF3` — the exact
implementations tailcat interoperates with — rather than transcribing hex by
hand, which is where crypto test suites quietly go wrong. Two vectors
(`rfc7693-abc` and `rfc7748-1`) are the published RFC values, so the
generator is anchored to something outside Go as well.

`tests/fuzz_crypto.c` property-tests the parts that guard the tunnel: random
ciphertext never authenticates, a single flipped bit anywhere in ciphertext,
tag, associated data or counter always fails, BLAKE2s fed in arbitrary chunk
sizes equals the one-shot digest, and X25519 is commutative and refuses
small-order points.

## Design notes

**No dynamic allocation in the parsers.** Addresses arrive from untrusted
places — a pasted string, a `tailcat=` TXT record — so `tc_addr_parse` writes
into a caller-provided fixed-size `tc_conn_info` and rejects anything that
exceeds its limits with `TC_ERR_TOOMANY` rather than truncating. There is no
`malloc` on the parse path at all.

**The CBOR reader is deliberately narrow.** It refuses indefinite-length
items, tags, floats, unassigned simple values and the reserved
additional-info values, and validates UTF-8 on text strings (matching
fxamacker's `UTF8RejectInvalid`). Container element counts are bounds-checked
against the bytes remaining, which both rejects absurd counts up front and
keeps them from overflowing later arithmetic. Nothing in it recurses, so
nesting depth cannot exhaust the stack.

**Bug-compatible where it matters.** `tc_base64url_decode` skips `\r` and
`\n` and does not reject a final quantum with non-zero unused bits, because
Go's decoder does both — being stricter would mean refusing addresses real
tailcat emits. Both deviations are documented at the declaration.

### What the toolchain taught us

- **Stack protection is unavailable in a fat build.** aarch64 has no
  `__stack_chk_guard` at all, so any `-fstack-protector-*` flag fails to link
  the aarch64 half. Supplying the symbol by hand makes it link, but the
  x86_64 binary then segfaults, because Cosmopolitan only defines the guard
  in its `-mtiny` runtime. Measured against cosmocc 14.1.0. The flag is
  therefore enabled only for host builds, which is where the sanitizer and
  fuzz targets run. `make test` runs `scripts/check-fat.sh` on every binary
  so this tradeoff cannot silently become "we quietly dropped aarch64".
- **cosmocc does not expose mbedTLS** to user programs; it bundles only
  GCC/Clang, Cosmopolitan Libc, libcxx, compiler-rt and OpenMP. DERP needs
  HTTPS, so a TLS library has to be vendored. See below.
- **Never use `-moptlinux` or `-mtinylinux`** — both produce Linux-only
  binaries.
- **`-std=gnu11`, not `-std=c11`.** Strict ISO mode makes glibc hide the POSIX
  networking declarations the DERP transport needs. `-Wpedantic` stays on, so
  our own code is still held to ISO C. Cosmopolitan is more permissive than
  glibc here, which is exactly why the project also builds with host gcc: that
  build caught `src/net/tls.c` using `calloc` with no `<stdlib.h>`, which
  cosmo's headers had been supplying transitively.
- **cosmocc keeps the aarch64 object in a sibling `.aarch64/` directory** next
  to the x86_64 one, and resolves the pair automatically at link time. Worth
  knowing before concluding a symbol is missing: `nm` on the obvious path only
  shows you half the build.
- **Mbed TLS's public headers do not survive our warning set** (redundant
  redeclarations, `#if` on undefined macros), so they are included with
  `-isystem`. That suppresses their warnings without weakening ours.
- **ISO C only guarantees 4095-byte string literals**, which `-Wpedantic`
  enforces, and the CA bundle is 181KB. The generated file suppresses
  `-Woverlength-strings` locally rather than emitting a far larger and less
  readable hex byte array.

### Working with WSL

Both are about WSL rather than Cosmopolitan, but both cost real time:

- **A WSL instance is torn down as soon as its last process exits**, taking
  `binfmt_misc` registrations and `/tmp` with it. Anything that must persist
  across steps has to happen inside a single `wsl.exe` invocation, or live on
  a mounted Windows path. `scripts/wslmake.sh` exists for exactly this.
- **`WSLInterop` claims every file starting with `MZ`** and hands it to
  Windows, which swallows Actually Portable Executables — including the APE
  tools cosmocc runs during its own build, so it fails before producing
  anything.

### On trusting DERP

A DERP relay is untrusted by design. It only ever sees WireGuard-encrypted
packets, so tailcat's confidentiality does not rest on the relay behaving, and
tailcat needs no account with whoever runs it.

That is not a reason to verify its certificate loosely, though — a relay that
can be impersonated can still deny service or fingerprint who is talking to
whom — so TLS verification is required by default and `insecure_skip_verify`
has to be asked for explicitly. Because an Actually Portable Executable cannot
rely on the host having a trust store at a known path, Mozilla's roots are
compiled in; regenerate them with `scripts/gen-ca-bundle.py`.

Opening the server's `FRAME_SERVER_INFO` box is also a real check rather than
a formality: it proves the relay holds the private key matching the public key
it greeted us with.

The tailcat layer is checked the same way again: `tools/genaddrs -vectors`
emits `tests/meow_vectors.h` using upstream's own `EncodeMeowPing`,
`EncodeMeowed` and `DiscoPublicForNode`, so the encoded packets and the
derived disco keys are pinned against the real implementation rather than
against our reading of it.

`make live-tailcat` is the end-to-end check: it builds the upstream Go
binary, starts a real server, resolves the address it prints, and requires
the C side to parse it, reach the relay, be meowed, and complete a
handshake. Every milestone at once, against the thing we have to
interoperate with.

## Bugs this verification has actually caught

Kept as a record, because each one says something about where the risk in this
project really is. All were found by tooling rather than by reading the code.

**1. NaCl secretbox started the keystream in the wrong place.** *(M3, found by
generated vectors.)* NaCl takes the one-time Poly1305 key from the first 32
bytes of the keystream and then encrypts the message from byte **32** — the
second half of block 0 — not from block 1. I had written it as a block
counter, which silently skipped 32 bytes of keystream. The tell was that empty
plaintexts passed (the tag only covers the key derivation) and every non-empty
one failed. Nothing but a differential vector would have found this quickly.

**2. X25519 did not clamp the scalar.** *(M2, found by RFC 7748 vectors.)*
`decodeScalar25519` clamps as part of X25519, so the RFC's own test vectors
supply *unclamped* scalars and expect the implementation to do it. Mbed TLS
also rejects an unclamped scalar outright, so this failed loudly rather than
quietly — but only because the vectors used the RFC's inputs verbatim.

**3. `mbedtls_ecp_mul` rejects a NULL RNG.** *(M2.)* It returns
`MBEDTLS_ERR_ECP_BAD_INPUT_DATA`; it wants the RNG to randomise projective
coordinates as a side-channel countermeasure. I had written a comment
confidently asserting NULL was fine. The comment was wrong, and the code
matched the comment.

**4. `tls.c` used `calloc`/`free` with no `<stdlib.h>`.** *(M3, found by the
host gcc build.)* Cosmopolitan's headers supply it transitively, so cosmocc
never complained. An implicitly declared `calloc` is genuine undefined
behaviour.

**5. `-std=c11` hides `struct addrinfo` under glibc.** *(M3, host gcc build.)*
Strict ISO mode suppresses the POSIX networking declarations. Cosmopolitan is
more permissive, so again only the second toolchain noticed.

**6. The build silently used the wrong compiler.** *(M1.)* `CC` is a GNU make
builtin with a default of `cc`, so `CC ?= $(COSMOCC)` is a no-op. The first
"passing" build was host `cc`, not cosmocc — the entire point of the project,
quietly not happening. Fixed with `ifeq ($(origin CC),default)`, and `make
test` now asserts every binary is a fat APE so it cannot regress unnoticed.

**7. The interop harness mis-parsed hex.** *(M4.)* `sscanf("%2x")` did not
honour the field width reliably, turning `0f` into `f9` in one byte of a key.
The protocol code was correct; the scaffolding feeding it was not. It
surfaced as `Received packet with invalid mac1` from wireguard-go, which
points at the protocol and not at the test. Localising it needed a probe with
the known-good bytes hard-coded, to prove BLAKE2s was innocent before hunting
for the real cause.

**8. The interop harness watched the wrong channel.** *(M4.)* wireguard-go's
test TUN names its channels from the device's point of view, so packets the
device receives arrive on `Inbound`; the harness waited on `Outbound` and saw
nothing. Again the implementation was right and the test was wrong.

**9. TCP sent uninitialised memory when the send buffer was shorter than the
sequence space.** *(M6, found by a 40,000-byte transfer arriving as 54,087.)*
SYN and FIN each consume a sequence number without occupying the buffer, so
`snd_len - in_flight()` underflowed a `size_t` and `try_send` transmitted a
full segment of whatever was in the buffer. The size mismatch was the only
symptom; nothing crashed.

**10. The JSON reader negated `INT64_MIN`.** *(Phase 2.1, found by
UndefinedBehaviorSanitizer -- eventually.)* `-(int64_t)mag` is undefined for
the one magnitude only the negative side can hold. UBSan had been reporting it
for as long as the code existed, but **its diagnostics are non-fatal by
default**: it printed a line and the suite still said `ok json 264 checks`, so
several runs were reported as clean that were not. `SANITIZE=1` now passes
`-fno-sanitize-recover=all`, and a finding fails the run. The lesson is not
about the bug, which was trivial; it is that a checker whose output does not
fail anything is a checker nobody reads.

**11. A connection reset before it was accepted left a freed pointer in the
accept queue.** *(Phase 2.1, found by mutation testing.)* This is the only
entry found by deliberately breaking working code to see whether the tests
noticed. Removing the accept-queue cleanup from the mux's drop path made no
test fail -- a real gap, since the sequence (SYN queued, peer resets, loop
reaps, application accepts) is ordinary. Notably ASan did not catch it either,
because the freed pointer was returned and compared rather than dereferenced.
A test for that exact sequence now exists, and the mutation fails it.

**12. Handshake retries resent the identical initiation.** *(Phase 2.2, found
by a two-hour simulation with 5% loss.)* Resending the same bytes looks like
the thrifty choice: a fresh initiation carries a new ephemeral key and makes
the peer repeat the expensive half. It is also exactly what initiation replay
protection rejects, so one lost handshake packet stranded the tunnel until the
attempt was abandoned ninety seconds later. wireguard-go builds a new
initiation on every send for this reason. Nothing shorter than hours of
simulated time would have found it: it needs a lost handshake message, on a
session old enough to expire before the retries give up.

**13. The test for bug 12 did not test bug 12.** *(Phase 2.2, found by
mutation.)* `live-rekey.sh` held a session open for 280 seconds and required
every line to arrive. With our rekey timer disabled entirely it still passed
15 of 15 -- because WireGuard is deliberately redundant: the Go server renews
at its own threshold if we do not. A delivery-only check proves the responder
path and nothing about our own timer. The script now reads a summary the CLI
emits and requires that *this* side initiated the rotations. Worth separating
from the rest: the code was already correct, and the test was the thing that
was wrong.

**14. The Makefile had no header dependency tracking.** *(Phase 2.5, found by
AddressSanitizer.)* Adding one member to `tc_stream` grew it from 56 bytes to
64. Nothing rebuilt the objects that include the header, so `http.c` kept a
stack frame laid out for the old struct while `tls.c` wrote into the new one,
and `serve` crashed in `tc_net_tcp_connect` — three call frames from anything
that had changed. This is not a link error: it is a program whose files
disagree about where the fields are, and it had been latent since the first
commit, invisible until the first change to a widely-included struct. Fixed
with `-MMD -MP` and `-include`. ASan named the overflowing variable, its
frame and the byte offset, which turned a mystifying crash into an obvious
struct mismatch in about a minute.

**15. The proxy killed its own process with SIGPIPE.** *(Phase 3.1, found by
the first run of test_proxy.)* Writing to a socket whose peer has gone raises
SIGPIPE, whose default disposition terminates the process -- and for a proxy,
a local service exiting mid-stream is ordinary rather than exceptional. The
test did not report a failure; it died with exit 141 and printed nothing.
Fixed with `MSG_NOSIGNAL` per call rather than by changing the signal
disposition of whatever program links the library, which is not a library's
decision to make.

The pattern is hard to miss: **four of the first six came from running the
same code through a second, stricter environment**, and the two crypto bugs
came from comparing against a reference implementation rather than against my
own expectations. Neither unit tests nor code review would have found most of
them.

Bugs 7 and 8 are worth separating out, because they are the opposite failure:
**the implementation was correct and the test harness was broken**, in both
cases with a symptom that pointed squarely at the implementation. When an
interop test fails, the scaffolding deserves as much suspicion as the code
under test.

Multi-client serving repeated that lesson three times in one sitting, and all
three looked like the server hanging: a bare `wait` that also waited on the
server and the local service, which never exit; a background job inheriting
stdout and holding the pipe open after the test had finished; and a
`pkill -f tailcat-c` that matched the shell whose own command line contained
that string, so the cleanup killed the thing running it. The feature under
test worked first time. The harness cost more than the feature.

Bugs 10 and 13 are the uncomfortable ones, and they are the same failure in
two shapes: a check that cannot fail is not a check. One was a sanitizer whose
findings did not stop the run; the other was a live test that passed with the
feature it existed to test switched off. Both were caught by asking what would
have to break for this to go red -- which is now the habit: **11 and 13 came
from deliberately breaking working code to see whether anything noticed, and
12 from a simulation long enough for the bug to have room to appear.**

## Limitations

Current, and deliberate unless noted.

### Protocol scope

- **Relay-only.** No direct peer-to-peer path, so no NAT traversal, no disco,
  no STUN, no netcheck, no endpoint scoring. Every packet goes through DERP.
  This is the agreed scope, and it is a strict subset of the full data plane,
  but it means higher latency than real tailcat once that would have gone
  direct.
- **One pipe at a time.** The data path is real — WireGuard, userspace TCP,
  and interop with the Go binary in both directions — but a session carries a
  single stream of bytes. The port-based commands all wait on the
  demultiplexer (PLAN.md 2.1).
- **No SSH or SFTP *server*, and no WASM build.** `ssh` and `cp` work as
  clients, because they exec the system ssh and scp with us as a
  `ProxyCommand`; serving SSH would mean implementing it.
- **`ssh` turns off host key checking**, because the destination it gives ssh
  is a hash of the address rather than a host anyone holds a key for, and the
  address already authenticates the server: reaching it required the
  pre-shared key and the server's public key. A `known_hosts` entry keyed on a
  synthetic name would add a prompt and no security.
- **`socks` reaches one server**, the one in its address, and ignores the
  destination host in each CONNECT request -- only the port is used. Upstream
  routes by hostname across several servers at once. Ours would be inventing
  a destination it cannot reach.
- **Region selection is an approximation.** A relay is chosen by timing a
  DERP connection (TCP, TLS and the key exchange), not by STUN probes as
  upstream's netcheck does. It measures the path a relayed session actually
  uses, but will choose differently where TCP and UDP diverge.
- **`serve` with no ports handles one client and one connection**, then
  exits -- it writes to one stdout, so a second client would have nowhere to
  go. That is upstream's behaviour too. `serve <ports>` has no such limit and
  takes up to 8 clients and 64 connections at once.
- **No `--allow` list.** Anyone holding the address can connect. Upstream can
  restrict by client public key; we cannot, so the address is the only
  credential.

### TLS

- **TLS 1.2 only.** TLS 1.3 in Mbed TLS 3.6 requires the PSA crypto layer,
  which is a large amount of additional code. Tailscale's relays accept 1.2,
  and ECDHE with AEAD suites is not a weak configuration — but it does mean
  upstream's "fast start" optimisation is unavailable, since reading the
  relay's key from a meta certificate requires 1.3.
- **The CA bundle is a point-in-time snapshot** of Mozilla's roots, compiled
  in and refreshed only by re-running `scripts/gen-ca-bundle.py`. A root
  distrusted upstream stays trusted here until someone regenerates it.
- **No revocation checking.** No OCSP, no CRLs. Mbed TLS supports neither well
  in this configuration.
- **The cipher suite list is trimmed** to what the config enables. A relay
  demanding something we did not compile in will fail the handshake rather
  than negotiate down.

### WireGuard

- **No persistent keepalive.** The passive keepalive is implemented -- a data
  packet is answered with an empty one if nothing else goes back within ten
  seconds -- but there is no configurable interval for holding a NAT binding
  open, which is moot while every path goes through a relay.
- **Demanding cookies is off by default.** The exchange is implemented in
  both directions, but `tc_wg_peer_set_under_load` has to be turned on before
  we ask a peer for one. It costs an extra round trip on every handshake, and
  the traffic reaching a tool like this is already bounded by the relay.
  Answering a peer that demands one is unconditional.
- **No handshake rate limit.** Initiation replay is rejected, but a peer that
  floods us with *fresh* initiations will make us do the expensive half of a
  handshake each time. wireguard-go caps this at one per 20 ms. Nothing here
  does, which matters more once 2.3 brings cookies.
- **No index table.** Handshake indices are random 32-bit values with no
  check for collision, which is fine for one peer and would not be for many.

### TCP

- **No SACK, timestamps or window scaling.** Throughput over a long fat pipe
  will be poor; over a relay with a 64KB window it is adequate.
- **No fast recovery**, only fast retransmit: after three duplicate ACKs the
  window is halved and one segment resent, then slow start resumes.
- **The MSS is fixed at 1140** and derived from tailcat's 1232-byte maximum
  UDP payload. There is no path MTU discovery, and nothing fragments, so a
  smaller path would black-hole rather than degrade.
- **`tc_wg_timestamp_force_offset_ms` and `tc_tcp_force_next_iss` exist for
  tests only.** The first moves the TAI64N clock, which is precisely what an
  attacker replaying an initiation would want; the second makes the initial
  sequence number predictable, which is what makes blind stream injection
  practical. Both are documented as such at their definitions.

### Implementation

- **Writes have no timeout.** Reads are bounded by
  `tc_derp_set_read_timeout`, and a timed-out read is recoverable rather than
  fatal -- the TLS record layer keeps what it had, so a later read resumes
  mid-record. Writes can still block indefinitely on a stalled relay.
- **No reconnection.** `FRAME_RESTARTING` is parsed and ignored; a dropped
  connection is simply an error to the caller.
- **A `tc_derp_client` is not safe for concurrent use.** Send and receive both
  touch the same stream with no lock, and both use thread-local scratch
  buffers of about 64KB each.
- **Address parser limits are compile-time**: at most
  `TC_ADDR_MAX_REGIONS` (2) regions and `TC_ADDR_MAX_NODES` (8) nodes. Real
  addresses carry one region with one or two nodes, so this is ample, but a
  hand-built address with more is rejected rather than truncated.
- **The CBOR reader is stricter than Go's** in two ways that could in
  principle reject something upstream accepts: it refuses indefinite-length
  items and tags. tailcat's encoder emits neither, so this has never fired,
  but it is a deviation rather than a pure subset.
- **`tc_conn_info` is several kilobytes.** Callers should heap-allocate it
  rather than put it on a small thread stack.

### Security posture

- **No stack protection in the shipped binary.** See the Cosmopolitan notes
  above; this is forced by the fat build, not chosen. The sanitizer and fuzz
  builds do have it.
- **Fuzzing is a homegrown mutation fuzzer**, not coverage-guided. It runs
  under ASan and UBSan and checks real invariants, but it is not libFuzzer and
  cosmocc ships no libFuzzer or ASan runtime to make it one.
- **No constant-time audit has been done** beyond writing the primitives in a
  data-independent style and using Mbed TLS for the hard parts. No timing
  measurements have been taken.
- **Key zeroization is best-effort.** Key material is wiped with an explicit
  memset-through-a-volatile-pointer, but nothing prevents the compiler or the
  OS from having copied it elsewhere first.
- **No CI.** Everything here was run by hand on one machine, on Linux under
  WSL. The binaries are fat and should run on macOS, Windows and the BSDs —
  but that has not been tested on any of them.

## Known TODOs

Roughly in the order they should be picked up.

- [ ] **No TCP keepalive or idle timeout**; a silent peer is never noticed.
- [ ] **Reaping is caller-driven.** `tc_tcp_mux_reap` has to be called or
      closed connections hold their table slots; nothing does it on a timer.
- [x] **Tiered local diagnostics** (`make diag5/3/1`) with a pre-push hook.
      Deliberately not hosted CI: the live tests dial Tailscale's production
      relays, and pointing a robot at someone else's infrastructure on every
      push is not a reasonable default.
- [ ] **Run the aarch64 half.** `check-fat` proves it compiles, links and is
      present in every binary. Nothing has ever *executed* it, which makes it
      the largest untested claim in this README. The plan, cheapest first:
      - [ ] **Build x86_64 with `-funsigned-char`** and run the whole suite.
            No emulator, no new infrastructure. Plain `char` is signed on
            x86-64 and unsigned on aarch64, so `if (c < 0)` on a `char`
            silently changes meaning between them — and `json.c`, `cbor.c`,
            `base64url.c` and `http.c` are full of character handling that
            *mostly* uses `uint8_t`. "Mostly" is the word that hides this.
            Check first whether cosmocc already forces a signedness for both
            targets; if it does, the concern evaporates and that is worth
            knowing too.
      - [ ] **qemu-user** (`qemu-aarch64` plus binfmt). Whether it runs an APE
            unmodified needs finding out rather than assuming: Cosmopolitan
            issues raw syscalls and brings its own loader, and qemu-user
            translates syscalls to the host kernel instead of emulating one.
            It may need `assimilate` to flatten the APE into a plain aarch64
            ELF first. This catches miscompilation and arch-dependent logic.
      - [ ] **qemu-system** with a real aarch64 Linux: slow, but the only
            option that exercises Cosmopolitan's own aarch64 runtime rather
            than just our instructions.
      - [ ] **Real hardware** beats all of the above if any is to hand.
- [ ] **Test on macOS and the BSDs, and on aarch64.** Linux and Windows are
      covered; the other four targets and the entire aarch64 half are not.
- [ ] **Thread-safety review** of `tc_derp_client`, or an explicit statement
      that callers must serialise it.
- [ ] Revisit **TLS 1.3** once the PSA dependency is worth paying for.
- [ ] Refresh the **CA bundle** and decide on a cadence for it.
- [ ] Consider making the address-parser limits runtime-configurable.
- [ ] **Replace the region heuristic with netcheck** once Phase 4 brings STUN;
      until then a relay is chosen by DERP handshake time, not path quality.
- [ ] **Refresh the DERP map cache in the background** rather than only on a
      miss, so a long-lived process does not pay a fetch mid-session.

## Roadmap

- [x] **M1 — Addresses.** base64url, strict CBOR, the `Addr` codec, golden
      vectors, differential testing against Go, fuzzing.
- [x] **M2 — Crypto.** X25519, ChaCha20-Poly1305 and the CSPRNG from a pinned
      Mbed TLS 3.6.7; BLAKE2s, HMAC-BLAKE2s and WireGuard's KDF1/2/3
      implemented here, because Mbed TLS has no BLAKE2s and Noise needs it.
      Vectors are generated from the same Go libraries WireGuard uses, with
      RFC 7693 and RFC 7748 values as external anchors.
- [x] **M3 — DERP client.** TCP, TLS 1.2 with certificate verification
      against 121 compiled-in roots, the HTTP upgrade, the frame codec, the
      NaCl-box key exchange and the send/receive loop. Verified end to end
      against a production Tailscale relay by `make live`.
- [x] **M4 — WireGuard.** The Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
      handshake, transport encryption and the 2048-bit sliding replay window.
      Verified against real wireguard-go by `make live-wg`, which completes a
      handshake and gets an encrypted IPv4 packet delivered to its TUN.
      Rekeying and the cookie/DoS exchange are not implemented; see
      Limitations.
- [x] **M5 — meow bootstrap.** The introduction exchange, the disco key
      derivation a peer must advertise, and tunnel addressing. Verified
      end to end by `make live-tailcat`: a real tailcat server accepts our
      meow, adds us as a peer, and completes a WireGuard handshake through
      the relay.
- [x] **M6 — Minimal TCP.** A two-peer userspace TCP over IPv6: the state
      machine, cumulative ACKs with a bounded reassembly queue, RTO with
      Jacobson/Karels and Karn's algorithm, fast retransmit, slow start and
      congestion avoidance, window updates and half close. Roughly 900 lines
      in place of gvisor's netstack. Tested against a simulated link with
      loss, duplication and reordering, and end to end against a real
      tailcat server.
- [x] **M7 — CLI.** `tailcat-c <addr> [port]` pipes stdin and stdout through
      the tunnel, plus `parse` and `version`. A single-threaded event loop
      over the relay socket and stdin drives the TCP stack and the WireGuard
      session, so there are no locks. Verified by `make live-cli` against the
      upstream Go server.
- [x] **Phase 1 — self-sufficiency.** A strict JSON reader, an HTTPS GET, the
      DERP map fetched and cached for an hour, a relay chosen by measured
      handshake time, and the `resolve` and `ping` subcommands. Short
      addresses now work directly and `serve` needs no `--relay`, so nothing
      else has to be installed alongside the binary. `tailcat-c resolve`
      produces a byte-identical result to `tailcat resolve`.

- [x] **Phase 2.1 — the demultiplexer.** Many TCP connections over one tunnel:
      a table keyed by the port pair, a listener set, ephemeral port
      allocation, and a reset for anything addressed to a port nobody owns.
      The CLI routes through it, so dispatch is exercised by every live run.
      `make live-serve` covers the passive open against a real Go client.

- [x] **Phase 2.2 — session lifetime.** The previous/current/next keypair
      triple, WireGuard's rekey and expiry timers, passive keepalives, and
      initiation replay protection. A session now renews itself instead of
      dying after two minutes. `make live-rekey` holds one open for 280
      seconds against a real tailcat server, across rotations this side
      initiated; it takes six minutes, which is the shortest honest way to
      test it.

- [x] **Phase 2.3 — cookies.** XChaCha20-Poly1305, the cookie reply, and mac2
      on both sides, so a peer under load can be answered rather than lost.
      Verified against wireguard-go's own `CookieChecker` end to end.
- [x] **Phase 2.5 — reconnection and liveness.** `FRAME_RESTARTING` acted on,
      keep-alives tracked, redial under the same identity with backoff, and
      write timeouts. A tunnel now survives its relay restarting, because
      WireGuard is keyed to the peers rather than to the path.

- [x] **Phase 3.1 — `serve <ports>`.** Port specs with ranges and `all`, a
      reusable splice that carries half closes in both directions, and many
      clients at once, each with its own WireGuard session and demultiplexer.
      `make live-serve-ports` proves a real Go client reaching a real local
      service; `make live-multi` proves four of them at once seeing only
      their own traffic.

- [x] **Phase 3.2 and 3.3 — `forward` and `socks`.** Both listen locally and
      dial through the tunnel, sharing one loop and the splice from 3.1.
      `make live-forward` runs each against a real Go `tailcat serve`, which
      is the mirror of `live-serve-ports`: between them, both ends of the
      proxy have now been driven by something that is not ours.

- [x] **Phase 3.4 — `ssh` and `cp`.** The system ssh and scp, with tailcat-c
      as their `ProxyCommand`. `make live-ssh` is the longest chain anything
      here has been tested through, and only the middle of it is ours:
      `ssh -> tailcat-c -> DERP -> WireGuard -> the Go tailcat's sshd`.

- [x] **Phase 3.6 — saved identities.** `genkey`, `printpub` and `--key`, in
      upstream's own `*.private.json` format. Without one, a server's address
      changed on every restart, which made it useless in a script.
      `make live-genkey` runs a key through both implementations in both
      directions and requires the addresses they derive to be identical
      strings — which is how it caught `serve` advertising the embedded
      address form where upstream names a region by number.

**Phases 1, 2 and 3 are done.** `recv` turned out not to belong to Phase 3 at
all: it is `serve --files <dir>:wo files`, and the `files` service is SFTP
over SSH, so the *server* half needs PLAN.md's 5.4 and 5.5 rather than the
~300 lines that entry estimated. The *client* half already works — `make
live-recv` delivers a file into a real `tailcat recv` drop box — because `cp`
execs the system scp, which speaks exactly that protocol.

Beyond here, see [PLAN.md](PLAN.md): Phase 4 is direct peer-to-peer paths, and
everything left of upstream's command set (`recv`, `ls`, `serve ssh`) needs an
SSH server first.

## Licence

BSD-3-Clause, matching upstream tailcat. Portions are ports of
Tailscale-authored code; see `upstream-tailcat/LICENSE`.
