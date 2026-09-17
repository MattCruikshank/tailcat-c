# tailcat-c

A rewrite of [tailcat](https://github.com/tailscale/tailcat) in C11, built
with the [Cosmopolitan](https://github.com/jart/cosmopolitan) C compiler into
a single **fat Actually Portable Executable** — one binary that runs on
Linux, macOS, Windows, FreeBSD, OpenBSD and NetBSD, on both x86_64 and
aarch64.

**Status: upstream's command set is implemented, bar the WebAssembly
build.**
Relay and direct paths both work, on two operating systems.
`tailcat-c` serves and connects, interoperates with the real Go tailcat in
both roles, finds a direct peer-to-peer path when one exists and falls back
to the relay when it stops working, and the *same fat binary* does it on
Linux and on Windows:

```console
$ echo 'the quick brown fox' | tailcat-c -v tcpGFwWCDMihnYWAeovm...
# relay tc301a.ipn.dev
# meowed: the server has added us as a peer
# tunnel up
# connected
```

and the Go server prints `the quick brown fox` on its own stdout. On a run
where a direct path is available, the same client reports finding one:

```console
# probing for a direct path (4 of our addresses offered)
# path: direct to 172.25.125.50:60857, 24ms (2 of 2 candidates proven)
```

and that one is against a **real Go tailcat server**, not against ourselves:
Tailscale's own disco protocol answering our probes.

It works the other way round too: `tailcat-c serve` mints an address that the
**real Go client** accepts, answers its WireGuard handshake as the responder,
and writes what it receives to stdout.

`scripts/live-cross.sh` runs one binary against itself across both operating
systems, in both directions, through a real relay:

```
one binary, 2047257 bytes, run by both operating systems

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

The last row turned out to be the one where the estimate was most wrong, and
in our favour: the SSH and SFTP subset `recv` and `ls` need — transport, key
exchange, publickey auth, one channel, and a version 3 file protocol in both
directions — came to about 2,900 lines rather than 20,000, because a drop box
and a listing need almost none of what makes a general `sshd` big.

## Scope

The original scope was the **DERP-relay-only interop core** — wire compatible
with real tailcat, but relaying rather than establishing direct paths, which
is what tailcat's own WebAssembly demo does. That deliberately dropped
`magicsock`'s hardest parts, on the grounds that they were a strict addition
and could come later without redesign.

They came later. STUN, netcheck, the disco protocol, path discovery and the
upgrade/fallback machinery are all here now, and the claim that they could be
added without redesign turned out to be true: the only structural change was
widening the connection key from a port pair to a four-tuple.

**Still out of scope**, in descending order of how much it would take:

- **`serve ssh` as a general shell server**, deliberately. `recv` serves
  sftp and nothing else, and a drop box that can run commands is not a drop
  box. Upstream's read-write and recursive file modes (`:rw`, `:wo+`) are
  not implemented either; PLAN.md 5.5 records what the recursive one trades
  away.
- The **browser/WebAssembly build**. Cosmopolitan does not target WASM, so
  this means a second toolchain and a second build of everything — arguably
  against the premise of a project whose whole point is one fat APE.
- **TLS 1.3**, which is blocked on something more interesting than effort;
  see [the note below](#tls-13-is-blocked-on-ed25519).

`forward`, `socks`, `ssh`/`cp` as clients, `ls`, `recv`, exit nodes, saved
identities, `browse` and `readme` are all here.

**Smaller things that are simply absent**, none of them hard, all of them
found by typing upstream's README at this binary rather than by reading our
own feature list:

- **Addresses published as DNS TXT records.** `tailcat ssh example.com`
  looks up a `tailcat=tc…` record. Ours says `bad address: malformed
  input`, which is true and unhelpful. It needs a resolver, and with it
  upstream's safety check -- probing a DNS-named server as a stranger would
  and refusing if that login succeeds -- because publishing an address makes
  it public and the server must then authenticate clients itself.
- **`socks` recognising a tailcat address as a URL hostname**, which is what
  makes the address argument optional there.
- **`ping --until-direct`**, which keeps pinging until a direct path works
  and exits non-zero if none does. Larger than it sounds, and larger than
  this list first claimed: `ping` here is relay-only. It opens a DERP
  connection, sends a meow ping and waits for the reply, and never attempts
  a direct path at all -- so there is nothing to loop on. The flag needs
  `ping` rebuilt on the client stack the pipe uses, which does have path
  discovery. That would also close the cosmetic gap where upstream reports
  `pong … via 203.0.113.7:41641` and we can only ever name the relay.
- **`genkey --fixed-region`** and **`genkey --region=<relay-hostname>`**.
  `--relay` pins a relay for `serve`, so what is missing is baking the choice
  into a *saved key* -- which is what makes a published address keep working
  across restarts.
- **Reaching a third address from the pipe form or `ssh -p ip:port`.**
  `forward` does this and `serve exit-node` is implemented, so this is
  plumbing an existing path into two more commands. Until then both refuse
  it by name; see bug 34 for what they did before.

Every instruction in upstream's README has been typed at our binary and the
result written down: [doc/upstream-readme.md](doc/upstream-readme.md). It is
a sharper question than the feature table asks, and it found three bugs that
the table would have called implemented.

## How it compares

### Size

Both columns are release builds of the same commit: upstream with its own
`-s -w` and the 75 `ts_omit_*` tags from `.goreleaser.yaml`, ours as cosmocc
emits it. (Running `strip` on an APE destroys it — `scripts/check-fat.sh`
will tell you so — and building without `-g` changes nothing, because cosmocc
keeps debug information in sibling files rather than in the executable.)

| | tailcat-c | tailcat (Go) |
|---|---:|---:|
| binary | **2.22 MB** | 17.70 MB |
| gzipped | **1.11 MB** | 6.85 MB |
| files needed for 6 OSes × 2 arches | **1** | 12 |

The ratio is about 8×, and **most of it is the feature gap below, not
craftsmanship**. A Go binary also carries a runtime, a garbage collector and
reflection metadata that a C program does not, which accounts for a good part
of the rest.

Where our 2.22 MB actually goes, as `size` reports text+data on the x86_64
objects — so these are code and initialised data, not file offsets, and they
do not sum to the binary:

| | |
|---|---:|
| Mbed TLS | 249 KB |
| **all of our own code** | **189 KB** |
| the compiled-in CA bundle | 181 KB |
| the embedded usage text (`readme`) | 5.3 KB |
| Cosmopolitan libc, and two architectures of everything | the remainder |

Everything we wrote — addresses, CBOR, JSON, crypto, DERP, WireGuard, TCP,
UDP, STUN, disco, netcheck, path discovery, Ed25519, and an SSH and SFTP
client and server — now comes to 189 KB. For most of this project's life
that number was smaller than the list of certificate authorities the binary
ships with; the SSH subset added 42 KB and overtook it, and it now leads by
six.

Phases 3 through 5 added about 288 KB to the binary and roughly 6,000 lines
of source, which is the cost of everything from `serve <ports>` through
direct peer-to-peer paths.

### Features

| | tailcat-c | tailcat |
|---|:--:|:--:|
| **Data plane** | | |
| WireGuard tunnel (Noise IKpsk2) | ✅ | ✅ |
| Pre-shared key layer | ✅ | ✅ |
| DERP relay transport | ✅ | ✅ |
| Bring your own relay | ✅ | ✅ |
| Direct peer-to-peer path (NAT traversal, disco, STUN, netcheck) | ✅ | ✅ |
| Rekeying / session renewal | ✅ | ✅ |
| Cookie reply (DoS mitigation) | ✅ | ✅ |
| DERP map fetch | ✅ | ✅ |
| Region choice by latency | ✅ (netcheck) | ✅ (netcheck) |
| Multiple concurrent connections | ✅ | ✅ |
| Multiple concurrent clients | ✅ (8) | ✅ |
| UDP forwarding | ✅ (SOCKS5 UDP ASSOCIATE) | ✅ |
| Exit node (forward to any address) | ✅ | ✅ |
| Client allow list (`--allow`) | ✅ | ✅ |
| IPv4 into the tunnel via NAT64 | ✅ | ✅ |
| TLS to the relay | 1.2 ([why](#tls-13-is-blocked-on-ed25519)) | 1.2 + 1.3 |
| **Commands** | | |
| pipe stdin/stdout to a server | ✅ | ✅ |
| `serve` | ports, ranges, `all`; many clients | full |
| `parse` | ✅ (byte-identical JSON) | ✅ |
| `version` | ✅ | ✅ |
| `ping` | ✅ | ✅ (`--until-direct`) |
| `resolve` | ✅ | ✅ |
| `forward` (local TCP port forwarding) | ✅ | ✅ |
| `socks` (SOCKS5 proxy) | ✅ CONNECT + UDP ASSOCIATE, one server | ✅ (many servers) |
| `socks <cmd>` with `all_proxy`, `--` optional | ✅ | ✅ |
| `ssh` / `cp` (both exec the system ssh and scp) | ✅ | ✅ |
| `ls` (SFTP remote listing) | ✅ (in-process SFTP client) | ✅ |
| SSH *server* (`serve ssh`) | serves sftp for `recv`; no shell, no PTY | ✅ |
| `recv` (file drop box, receiving) | ✅ (flat, write-only) | ✅ |
| `cp` *into* a `tailcat recv` drop box | ✅ | ✅ |
| `genkey`, `printpub` (saved identities) | ✅ | ✅ |
| `readme` | ✅ (embeds doc/usage.md, not this file) | ✅ (embeds README.md) |
| `browse`, `forward --open-browser` | ✅ | ✅ |
| `--flag=value` as well as `--flag value` | ✅ | ✅ |
| `--timeout` as a duration (`2m`, `1h30m`) | ✅ | ✅ |
| **Not here** | | |
| addresses in DNS TXT records | ❌ | ✅ (`tailcat ssh example.com`) |
| `socks` with the address omitted | ❌ | ✅ (tc-addr as a URL hostname) |

| `ping --until-direct` | ❌ | ✅ |
| `genkey --fixed-region` | ❌ (`--relay` pins one for `serve`) | ✅ |
| `genkey --region=<relay-hostname>` | ❌ (`--relay` does it for `serve`) | ✅ |
| reaching a third address from the pipe or `ssh -p` | ❌ (`forward` does it) | ✅ (`-p ip:port`) |
| `serve` services: `ssh`, `no-auth-ssh`, `exec`, `files` | ❌ | ✅ |
| bare `tailcat` starts a server | ❌ (prints usage) | ✅ |
| **Platforms** | | |
| Linux, Windows | ✅ tested | ✅ |
| macOS, FreeBSD, OpenBSD, NetBSD | built, untested | ✅ (macOS) |
| aarch64 | ✅ all 36 test binaries pass on real aarch64 instructions (qemu-user) | ✅ |
| Browser (WebAssembly) | ❌ | ✅ |
| Persistent keys on disk | ✅ | ✅ |

So: tailcat-c does the **whole data path** — address, relay, tunnel, TCP,
UDP, and the direct peer-to-peer path with its NAT traversal — in both roles
and interoperably, plus everything built on top of it: serving ports,
forwarding, SOCKS, exit nodes, `ssh` and `cp`, saved identities, and the SSH
and SFTP subset behind `recv` and `ls`.

What is left is the **browser build**, which Cosmopolitan cannot target, and
two deliberate omissions: `serve ssh` as a general shell server, and
upstream's read-write and recursive file modes. A drop box that can run
commands is not a drop box.

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
make live-netcheck # STUN probes and region choice against the real relay list
make live-direct   # two of ours finding a direct path between them
make live-exitnode # reach a third address through an exit node
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
$ make diag5     # ~6s     did I just break the build
$ make diag3     # ~1m     both toolchains, sanitizers, fuzzing, crosscheck
$ make diag1     # long    the above from a clean tree, plus every live test
```

The first two are measured on this machine, warm; level 3 varies from about
forty seconds to a minute and a half depending on how much needs rebuilding.
Level 1's duration is
deliberately not given a number here: it grew by eight live tests when bug 19
was fixed and by two aarch64 stages after that, and the figure that used to
sit in this comment predates both. It prints its own total, and every stage
inside it times itself, which is the number to trust.

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
$ tailcat-c netcheck                       # UDP, NAT type, relay latency
$ tailcat-c serve exit-node,22             # forward anywhere this machine can reach
$ tailcat-c forward <addr> 13306:192.168.1.10:3306
$ tailcat-c ls <tc-addr>:photos           # list what a server offers
$ tailcat-c recv ~/inbox                   # receive files; senders name nothing
$ tailcat-c serve --allow nodekey:...      # only that client may connect
$ tailcat-c socks <addr> 1080             # CONNECT and UDP ASSOCIATE
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

37 test binaries, 10,185 assertions, under two toolchains and on both
architectures. The method matters
more than the count, and it is the same one everywhere: **check against
something that is not ours.**

| Layer | The external anchor |
|---|---|
| addresses | upstream's own `tailcat_test.go` vectors, plus 2,000 random addresses generated by the real Go package and required to re-encode byte-identically |
| crypto | `golang.org/x/crypto` and wireguard-go's exported KDFs, with RFC 7693 and RFC 7748 values as fixed points |
| meow, disco, STUN | upstream's own encoders, via `tools/genvectors` |
| UDP over IPv6 | packets built and checksummed by **gopacket** |
| NAT64 | RFC 6052 §2.4's worked example, and `inet_pton`, which embeds a dotted quad itself |
| Ed25519 | RFC 8032's published vectors, reached by feeding its own seeds to Go's `crypto/ed25519` |
| IPv6 formatting | our output fed back through `inet_pton` |
| SSH | `golang.org/x/crypto/ssh` for the wire encodings and the cipher, and a **real OpenSSH 9.6 client** for the protocol itself |
| the SFTP drop box | a real `scp` and `sftp` carrying out the attacks, with the check on the filesystem afterwards rather than on what the client printed |
| the SSH and SFTP *clients* | a real Go tailcat file server, via `golang.org/x/crypto/ssh` and `github.com/pkg/sftp` |
| opening a browser | the real `rundll32 url.dll,FileProtocolHandler`, checked by watching a loopback listener for the request a browser actually made |
| everything timing-dependent | simulated networks where loss, delay, NAT behaviour and the clock are arguments |

Where a test passed on the first run, the response has generally been to
**mutate the code and check the test notices**. That has been worth doing:
of ten mutations to the path-discovery logic, six survived the first pass —
including, embarrassingly, every one aimed at the rule the whole design rests
on, because no scenario had one-way reachability. Of eleven to the UDP mux,
two had to be *rewritten* before they were the right mutations: one was a
false catch that merely failed to compile, and one modelled the wrong bug.

The SSH work added about sixty more, across the wire format, the packet
layer, key exchange, userauth, channels and the drop box, and produced three
results worth separating:

- **Caught, and by something stronger than an assertion.** Removing the
  length bound in `tc_ssh_get_string` does not fail a check, it aborts under
  ASan -- that argument turned out to be the only thing between a hostile
  length field and a stack buffer.
- **Survived, and the mutation was right.** Deleting the `has_signature`
  check from publickey auth changed no test result, because a parsed query
  form has an all-zero signature that fails verification anyway. The test
  asserted the outcome without exercising the guard meant to produce it,
  which is bug 13's shape exactly. Now closed.
- **Survived, and the mutation was wrong.** Deleting the empty-list early
  return from the same function is *equivalent*: with no keys the search loop
  finds nothing and denies regardless. Recorded as equivalent rather than
  papered over with a test that would prove nothing.

`browse` added twenty-five more, and a fourth result: **survived because
something else on the machine did the job.** Three mutations to the
browser-opening code -- ignoring `$BROWSER` entirely, trying only its first
entry, and forking once where it forks twice -- all passed a suite that was
watching the right thing. The reason is that `xdg-open` implements the same
`$BROWSER` convention we do, so a build that skipped our handling still ended
up running the recorder, by a longer route. The test now empties `$PATH`
first, which makes every opener that has to be *found* unavailable, so what
reaches the recorder can only have come from the code under test. With that
one change all twenty-five die.

That is the general shape and worth naming: a test that passes because the
environment supplied the behaviour is not testing the code, and the way to
find out is to take the environment away.

A surviving mutation is a gap in the tests, unless it is equivalent -- or
unless the environment is quietly standing in for the code. A caught one only
counts if it was the right mutation.

The address layer specifically is checked three ways:

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

`tests/fuzz_tcp.c` is the newest and took three attempts to make honest,
which is the interesting part. Generating random packets and feeding them in
was nearly useless: over 200,000 iterations it opened 76 connections, because
a packet must clear a checksum, a port lookup and a state check before it
reaches anything worth fuzzing. It exercised the length checks thoroughly and
the reassembly queue barely at all. So it now runs two real stacks against
each other, exchanging real data, and corrupts a fraction of the packets in
flight, with one uncorrupted connection carrying a byte counter as an
integrity oracle -- because a reassembly bug that silently reorders or
duplicates data crashes nothing and would pass every crash-based check.

Then the counters were printed, and they said 64 accepted connections at
20,000 iterations and 64 at 200,000. The churn opened connections and never
closed any, so both tables filled to `TC_TCP_MAX_CONNS` and stayed there: a
ten-fold longer run did exactly the same work. Fixing that turned up bugs 20
and 21 within minutes, one after the other, each of which had been holding
the table full in its own way.

The lesson is the one the file was written for, one level up, so every fuzz
harness now **asserts its own reach** and fails if it stops getting there --
no connection accepted, no byte carried end to end, nothing corrupted, or a
connection table that never turned over. A fuzzer that has quietly stopped
reaching the code looks identical, from the outside, to one that is finding
no bugs.

A smaller instance of the same thing: every harness seeded itself with
`strtoull(argv[2]) | 1`, which maps seeds 2 and 3 -- and 4 and 5, and so on
-- to the same state. Half of every seed sweep was a verbatim repeat of the
run before it, and the sweep looked twice as wide as it was.

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

## TLS 1.3 is blocked on Ed25519

Not on effort, and not on code size, which is what the plan originally
assumed. This is worth writing down because the answer is the opposite of the
obvious one.

Enabling TLS 1.3 in Mbed TLS 3.6 is easy: `MBEDTLS_SSL_PROTO_TLS1_3`, the PSA
crypto layer it requires (`MBEDTLS_PSA_CRYPTO_C` and HKDF — and *not*
`MBEDTLS_PSA_CRYPTO_CONFIG`, whose defaults drag in ARIA, Camellia, CCM and
DES), about twenty more source files, and a `psa_crypto_init()` before the
first context. It builds, it links, and it costs 232 KB.

It also cannot connect to a single relay.

DERP servers append a self-signed **meta certificate** to the chain, encoding
the server's public key in its CommonName so a client can skip a round trip.
They send it only on TLS 1.3, because 1.3 encrypts the certificate chain and
1.2 does not — see `initMetacert` in `tailscale.com/derp/derpserver`. That
certificate is **Ed25519**, which Mbed TLS 3.6 cannot parse at all, so the
chain is rejected whole, before any verification, with `X509 - Signature
algorithm (oid) is unsupported`.

The irony is exact: the gain 1.3 would have unlocked is upstream's "fast
start", which reads the DERP key out of that same meta certificate — and the
meta certificate is the thing that makes 1.3 unusable. Making it work means
teaching a vendored TLS library to skip certificates it cannot parse in the
middle of chain validation, which is not a change to make for an optimisation
we do not implement.

Nothing is given up by staying on 1.2 here: 1.2 with ECDHE and AEAD suites is
not a weak configuration, and `tc_tls_last_version()` reports what was
actually negotiated, so this is checkable rather than assumed.

**Ed25519 now exists** (`tc/ed25519.h`), so the missing piece is no longer
the algorithm — it is that Mbed TLS's X.509 parser has no hook to hand an
unknown signature algorithm to. Teaching a vendored TLS library to call out
to ours in the middle of chain validation is a bigger and more delicate
change than writing the curve was, and it is still in service of an
optimisation we do not implement. Worth revisiting; not worth rushing.

## Vendoring an SSH server

**Decided and done:** the subset was written, not vendored. It is kept here
because a decision whose reasoning is thrown away is one that gets
relitigated, and because the licence analysis is the part that would have to
be redone first.

`recv` and `ls` both sit behind SSH, and it was the largest single thing
left. PLAN.md's original note said "realistically: vendor an existing
implementation rather than write one", which is sound advice that turns out
to have a licence attached, so the decision belonged here rather than buried
in a plan.

This project is **BSD-3-Clause**, matching upstream tailcat, and it links
everything statically into one executable. That makes the licence of anything
vendored a licence question about the *whole binary*, not about a file.

### The candidates

| | Licence | Server? | Notes |
|---|---|---|---|
| **TinySSH** | public domain | yes | ~4k lines. Uses curve25519, ed25519, ChaCha20-Poly1305 — the primitives we already have. No PTY, no port forwarding, modern algorithms only. |
| **Dropbear** | MIT (+ public-domain libtom*) | yes | ~30k lines, and a *program*, not a library. Brings libtomcrypt and libtommath, duplicating crypto we already vendor. |
| **OpenSSH portable** | BSD-ish, mixed | yes | The reference implementation, and deeply Unix-specific. Porting `sshd` into a library inside an APE is a large job on its own. |
| **libssh** | LGPL-2.1 | yes | Static linking obliges us to let recipients relink. Possible for an open project, awkward for a single-file APE whose whole selling point is that it is one file. |
| **wolfSSH** | GPLv3 or commercial | yes | GPLv3 would relicense this project. |
| **libssh2** | BSD-3 | **no** | Client only. Listed because it is the one people suggest first and it cannot do this. |

### The decision

**Write the subset, and take TinySSH as the reference rather than the
dependency.** That is what happened; see Phases 5.4 and 5.5 in the roadmap.

The reasoning was that we do not need an SSH server. We need `sftp` reachable
over SSH with publickey authentication, which is a much smaller thing:

- transport and key exchange (RFC 4253) — `curve25519-sha256`, which is
  X25519 and SHA-256, **both already here**;
- `chacha20-poly1305@openssh.com` for the cipher, **already here**;
- publickey userauth (RFC 4252);
- one channel, and only the `subsystem`/`exec` request (RFC 4254).

No PTY allocation, no agent forwarding, no port forwarding, no interactive
shell, no `scp` protocol. Those are most of what makes a general `sshd` big,
and all of them are things a drop box should *not* have.

The one genuine gap **was Ed25519**, and it is now closed: `tc/ed25519.h`
implements RFC 8032 in 877 lines, checked against RFC 8032's published
vectors and byte-for-byte against Go's `crypto/ed25519`. So `ssh-ed25519`
host and user keys are available without an `ecdsa-sha2-nistp256` fallback,
and the "no unvendored crypto beyond Mbed TLS" property survives.

Estimate with the crypto in hand was **~2,500 lines for the SSH subset and
~1,500 for SFTP**, against ~30k for vendoring Dropbear and then carrying a
second crypto stack forever.

It came to about 2,900 for both, plus another 1,100 for the client halves
that `ls` needed and the estimate had not counted — so the estimate was close
for what it covered and forgot that a client is a separate thing from a
server. Vendoring would have needed a port of comparable size, as the note
below predicted, and a second crypto stack for ever.

### If you would rather vendor

Take **TinySSH** — public domain is the only licence here that costs nothing
— but budget for the port rather than the drop-in: it is Unix-only, expects
`fork`/`exec` and a supervising inetd-style parent, and depends on its own
NaCl. Under Cosmopolitan on Windows that is the part that will hurt, and it
is the same work as writing the subset, arranged differently.

**Do not take wolfSSH** unless you intend to relicense, and **do not take
libssh** unless you are willing to ship relinkable objects alongside the
binary, which defeats the one-file premise.

### The hazard this unlocks

Worth stating before any of it is written. `recv` is a **write-only drop
box**, and upstream's design is the one to copy rather than improve on: the
server chooses every stored filename, so a sender can neither overwrite
anything nor learn what is already in the directory. The recursive mode
(`:wo+`, `--accept-dirs`) trades exactly that away, and upstream documents
the trade rather than hiding it. Any implementation here should do the same,
and the tests should assert the flat mode's guarantees directly.

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

**16. Every compressible IPv6 address formatted wrong.** *(Phase 4.3, found
by the first disco test that printed one.)* The zero-run compressor emitted
one colon for the run, then suppressed the separator on the group after it,
so `2001:db8::1` came out as `2001:db8:1`. The formatter had shipped with
exactly one IPv6 assertion covering it -- RFC 5769's STUN vector, which
happens to have no zero groups at all -- so the entire compression path was
dead code as far as the suite was concerned. A test vector chosen by someone
else is only an anchor for the cases it contains. The replacement test walks
RFC 5952's rules and then feeds our own output back through `inet_pton`,
because a formatter checked only against a parser I also wrote proves that
the two agree, not that either is right.

**17. The server dropped the direct traffic it had just been sent.**
*(Phase 4.4, found by the first end-to-end run.)* The two sides of a session
decide independently where to send their own packets, so one routinely proves
a direct path seconds before the other does -- the design says so explicitly.
The receive side then demultiplexed arriving datagrams by asking "is this the
path *I* chose?", which is false for exactly that window, so the client
upgraded, sent its traffic directly, and the server threw it away. Every unit
test passed: the state machine was right, and the code that consumed its
answers asked the wrong question. Fixed with `tc_path_knows`, which asks
whether the address belongs to this peer at all rather than whether we agree
about it. The lesson is not about NATs -- it is that a component can be
correct and still be wired up against a rule it states in its own header.

**18. Editing the Mbed TLS config rebuilt nothing.** *(Phase 5.3, found by a
link that should have worked.)* Mbed TLS reaches our config through its own
`build_info.h`, which arrives via `-isystem` — and `-MMD` deliberately stops
at system headers, so the dependency chain never reached
`third_party/mbedtls_config.h`. Turning on TLS 1.3 therefore linked a
`cipher_wrap.o` compiled against a config that no longer existed, and the
symptom was a wall of missing ARIA and Camellia symbols that had nothing to
do with the change. Fixed by naming the config as an explicit prerequisite.
Same class as 14, found the same way, in the one part of the build where the
usual mechanism was silently inapplicable.

**19. The vector freshness check had never once passed.** *(Found by running
the level 1 diagnostic for the first time in months.)* Level 1 regenerates
`tests/crypto_vectors.h` and diffs it, on the principle that a stale
generated header is a test that has quietly stopped checking what it claims
to. The check was added in Phase 2.1. The cookie-exchange vectors were added
in Phase 2.3, and wireguard-go's `CookieChecker` draws its mac2 secret and
every reply nonce from `crypto/rand` -- so from that moment the file could
never match itself, and the stage failed every time it ran. It simply had not
run: level 1 is the only level that includes it, level 3 runs on every push,
and level 1 had not been invoked since. A check nobody runs and a check that
always fails are the same check.

Two fixes, and the second is the one that matters. The comparison now
excludes the block that cannot be reproduced, with the reason stated in both
the script and the generated file. And level 1 gained the **eight live tests
that were never in it** -- `live-allow`, `live-exitnode`, `live-socksudp`,
`live-forward`, `live-genkey`, `live-multi`, `live-recv`, `live-ssh` -- three
of which were written in the same session that found this. The README said
level 1 ran "every live test". It ran nine of seventeen.

**20. A corrupt SYN cost a table slot, permanently.** *(Found by the TCP
fuzzer, which ran out of connections.)* The demultiplexer checks a SYN's
flags and ports, then opens a connection and hands it the segment -- and the
connection validates the whole thing again, checksum included, rejecting a
bad one by dropping it without touching its state. So a corrupt SYN left a
connection sitting in `LISTEN`, holding nothing. `accept_syn` tested only for
`CLOSED`, so it kept it; a connection in `LISTEN` never reaches `CLOSED`, so
the reaper could never free it; and `TC_TCP_MAX_CONNS` is 64. Sixty-four
corrupt SYNs from an authenticated peer and the listener stopped answering
for good. It was pushed onto the accept backlog too, so the application was
handed a connection that would never establish and never close.

Fixed by requiring `SYN_RECEIVED` -- the one state a bare SYN can produce --
rather than enumerating the ways it can fail.

**21. A peer that vanished held its slot for ever.** *(Same fuzz run, one
layer down.)* An established connection with nothing to send has no
retransmission timer, so nothing at all was watching it. A peer that crashed,
was unplugged, or whose reset was lost in the tunnel left this side
`ESTABLISHED` until the process exited. On a general-purpose host that is
untidy; against a 64-entry table it is the same permanent exhaustion as 20,
reached by a route that requires no hostility whatsoever -- just a laptop
closing its lid.

Fixed with keepalive probes: silence is not evidence, so after a minute of it
a probe goes out, and the connection is dropped only after six of those go
unanswered. Probing rather than simply timing out is the whole of it, since
an interactive session may legitimately sit idle for hours.

That fix contained a third bug and revealed a fourth. The third: the idle
timer is re-armed by every segment that arrives, in *any* state, but is only
acted on in the synchronised ones -- so `tc_tcp_next_deadline` would report a
time the tick declined to act on, the deadline would never advance, and a
caller that sleeps until the next deadline would spin at full speed instead.
A wrong answer is loud; a busy loop is silent, and it is somebody's battery.
Both now share one `ka_active` predicate, because the failure mode of the tick
and the deadline disagreeing is precisely that.

The fourth: our own probe carries a garbage octet, so it is answered by the
path that re-acknowledges old *data*, and a tailcat-to-tailcat test could
never notice that a **zero-length** probe drew no reply at all. RFC 793 asks
for an acknowledgement to exactly that segment, and a Linux kernel at the far
end of the tunnel sends one by default -- so its keepalives went unanswered
and it would eventually reset a perfectly good connection. Found by mutation
testing, not by the fuzzer: disabling the new code changed no test result,
which is the only reason it was looked at again.

All four were locked down with direct tests before the fix was believed, and
each of those tests was checked against a mutation that reintroduces the bug
it covers.

**22. Every SSH handshake packet was four bytes out of alignment.** *(Phase
5.4, found by the first real `ssh` client to connect.)* Whether the packet
length field counts toward the block alignment depends on the cipher.
`chacha20-poly1305@openssh.com` encrypts it separately under its own key and
leaves it outside the aligned region; the `none` cipher in force before
NEWKEYS does not, so RFC 4253's plain rule applies and the length field
counts like everything else. We used the AEAD rule for both.

Every packet of the handshake was therefore misaligned and OpenSSH rejected
all of them with `padding error: need 212 block 8 mod 4`. Nothing offline
could have caught it: every vector in `tests/ssh_vectors.h` is encrypted,
because vectors are generated from the cipher, and the one test that pinned
the padding rule directly asserted the AEAD rule against a *plaintext*
cipher -- so it was confirming the bug. Our encoder and our decoder agreed
perfectly with each other throughout.

This is the clearest case yet for the project's own rule about anchors. The
packet layer's vectors were produced by Go written from the same OpenSSH
document as the C, so both sides could be -- and in this respect both were --
wrong in the same way. Only a peer written from neither could tell.

**23. A rekey request was ignored, and the client hung.** *(Phase 5.4,
found by being asked where the limitation was written down.)* The sequence
number is the cipher nonce, so it must never wrap, and the server stopped at
2^32 packets rather than letting it. That much was recorded -- in the
README's TODO list, though not in PLAN.md -- and it was the harmless half.

The half that actually happens is a peer *asking* to rekey. OpenSSH starts a
key exchange on its own schedule, and RFC 4253 section 9 has the initiator
wait for a KEXINIT in reply. `tc_ssh_server_read` had no case for KEXINIT, so
the request fell through to `default: break;` and was dropped in silence. The
client then waited for a reply that was never coming: measured with
`-o RekeyLimit=16K` over 200KB, `ssh` was killed by `timeout` after 12 seconds
having printed **nothing at all** to stderr.

Rekeying is now implemented as a responder, and three details in it are each
a silent corruption rather than a clean failure if wrong: the session id must
*not* change, the sequence number must *not* reset, and the two NEWKEYS
messages are not symmetric -- our send key goes in after ours goes out, their
receive key only after theirs comes in. All three are caught by mutation.

The lesson is about the documentation rather than the code. The limitation
had been written down, which felt like diligence, and what was written down
described the unreachable half of it accurately and missed the half that
happens in every long session. Being asked "is that in the plan?" was what
produced the second reading.

The test is written accordingly: it fails if the transfer is corrupted, if
`ssh` hangs, *and* if no rekey actually took place -- because a client that
ignored `RekeyLimit` would otherwise pass it, which is the same shape of
mistake as a fuzzer that stopped reaching the code it was aimed at.
**24. Bug 7, reintroduced in a new file four years later.** *(Phase 5.5,
found by the drop box working under host gcc and failing under cosmocc.)*
`tests/livesshd.c` needed to turn a hex key into bytes, so it grew a small
`unhex` using `sscanf("%2x")`. That is precisely bug 7: cosmo's `sscanf` does
not honour that field width reliably, so the key decoded correctly under
glibc and wrongly under cosmocc.

The symptom was the same as bug 7's, and just as misleading. The entire SSH
handshake succeeded -- key exchange, host key, cipher, service accept -- and
authentication failed with `Permission denied (publickey)`, which points at
the authentication code. It was not the authentication code. The host key
survived a corrupt decode because a client told not to check host keys does
not check it; only the authorized key has to match exactly, so only it failed.

Worth recording because the first instinct was to suspect the new code. The
fix for bug 7 lived inside the file that had it, so nothing stopped the same
mistake being made again in a file written years later -- and the second
toolchain caught it a second time, which is the argument for having one.

**25. `recv` refused every connection it existed to accept.** *(Found by
the first run over a real tunnel.)* Connections are admitted by an accept
filter that consults the served port set, and `recv` serves no local ports at
all -- so the SYN for port 22, where its own SSH server listens, was refused
before the accept loop that would have recognised it. The feature could not
work at all, and everything it is built from was passing.

Nothing offline could have found it. The SFTP policy, the SSH server and the
drop box are each driven by a real OpenSSH over a socket, and all of that was
green; the filter only exists on the tunnel path, and a tunnel needs a relay.
It took one deliberate live run, which is what live-recv-serve now is.

The shape is worth noting: every component was tested and the wiring between
two of them was not, because the wiring is the part that only exists in the
whole. That is the same reason `make live-cli` exists at all.

**26. Our SSH server replied to a channel request only after doing the
work.** *(Phase 5.5, found by our own SSH client.)* `on_start` ran the entire
application -- the whole SFTP session -- and the `CHANNEL_SUCCESS` for the
request that started it went out afterwards. RFC 4254 section 4 has the
requester wait for that reply before using the channel, so a client that
waits deadlocks: ours sent the subsystem request and blocked, the server sat
inside the application waiting for data that would never come.

It had worked against every real client tried, because OpenSSH does not wait
-- it sends optimistically. The bug was invisible until something that
follows the specification more strictly connected, and the first thing that
did was our own client on the day it was written. Fixed by splitting the
decision from the work: `tc_ssh_accept_fn` answers, and only then does
`tc_ssh_start_fn` run.

**27. The SFTP client insisted on our own server's handle length.** *(Phase
5.5, found by `make live-ls` against a real Go server.)* A file handle is
opaque and entirely the server's to choose -- ours are eight bytes, Go's
`pkg/sftp` uses its own, OpenSSH uses four. The client-side parser required
exactly eight, so it interoperated with itself and nothing else. It got as
far as a successful `stat` before failing on the first `opendir`, which is
the most misleading place for it to stop: everything up to the point where a
server-chosen value comes back works perfectly.

Both of these are the same lesson in two directions. A protocol has two ends,
and writing both from one reading gives two implementations that agree with
each other. Bug 26 needed a stricter *client* than the one we had been
testing with; bug 27 needed a server that was not ours.

**28. A bare `make` stopped building anything.** *(Phase 5.9, found while
measuring the binary for 5.10 and wondering why it had not changed.)* The
rule that regenerates `src/usage_text.c` was written just above `all:`, and
make takes the **first non-special target in the file** as its default goal.
So `make` regenerated a documentation file, printed one line, exited 0, and
built nothing. Every diagnostic level kept passing, because each of them
names its targets. It was found by a number that refused to move: the binary
was the same size after a change that should have grown it. The rule now
sits below `all`, with a comment saying why it has to.


**29. Nothing after the first non-zero stage in a diagnostic ever ran.**
*(Found by running a level 1 diagnostic to the end, which had not happened
before.)* `scripts/diagnostic.sh` runs under `set -e`, and `stage()` did
`sh -c "$*"` followed by `rc=$?`. Under `set -e` the shell exits on the
untested non-zero, so `rc` was never read: the FAIL branch, the SKIP branch
and the summary at the bottom were all unreachable, and the comment promising
that a stage "keeps going on failure so one broken thing does not hide the
state of everything after it" described the opposite. Level 1 reached the
qemu stage, found no emulator, and stopped — with twenty-four live interop
stages, the only ones that prove interop, never run.

**30. No exit code could mean "skipped".** *(Found by fixing 29 and watching
what the newly-reachable SKIP branch reported.)* The convention was that exit
2 meant "the tooling is not installed". Every stage is a `make` target, and
make exits 2 for *any* recipe failure, so a script's "I have no scp" and "the
test failed" arrive as the same byte. The live drop-box stage was failing and
was reported as skipped: a green run with a broken test inside it, which is
worse than the abort in 29. Moving the code to 77 does not help — make
flattens that to 2 as well, which is worth checking rather than assuming. So
the exit-code convention is gone; prerequisites are declared at the call site
with `--need`, and anything non-zero is a failure.

**31. Four cleanup traps aborted before cleaning up.** *(Found by 30, once a
real failure could be seen.)* `[ -n "$pid" ] && kill "$pid"` is an AND-list,
and it ends non-zero whenever the server has already exited — tripping
`set -e` inside the EXIT trap, so the `rm -rf` after it never ran.
`live-dropbox.sh` exited 1 with all six of its adversarial checks passed, and
had leaked a temp directory on every run it had ever done; there were 31 in
`/tmp`. Three sibling scripts carry the identical line and had been lucky.

Bugs 29 and 31 are the same shell footgun in two places, and 30 is what made
31 invisible. The harness now has a self-test: `sh scripts/diagnostic.sh
selftest` runs synthetic stages through the real `stage()` and asserts
nineteen things, including that exit 2 reports FAIL "because that is all make
ever says". It runs at the start of every level, and deliberately not through
`stage()` — if `stage()` is what is broken, a check routed through it cannot
report.

**32. `ssh` and `cp` never passed their tail through, and one way of failing
was silent.** *(Phase 6, found by typing upstream's README at our binary.)*
A comment in `src/cli/main.c` said those subcommands "take the tail of argv
rather than the parsed list". They did not. So:

- `tailcat-c ssh <addr> ls -la` died on `unknown flag -la`.
- `tailcat-c cp -r photos/ <addr>:` died on `unknown flag -r` — an example in
  our own usage text.
- `tailcat-c ssh <addr> ls -l` **worked**, having quietly eaten the `-l` as
  though it were the one belonging to our own `ls -l`. The remote command ran
  without it and nothing said so.

The third is the one worth remembering. The first two are an error message;
the third is a wrong answer, and the user has no way to notice. Flag parsing
now stops when the subcommand turns out to be `ssh` or `cp`, with `-p` the
one exception, because upstream's `-p` is its own too.

**33. `--timeout=2m` meant two seconds.** *(Phase 6, same walk.)* Upstream
takes a Go duration; we took an integer through `strtoul`, which stops at the
first character it does not understand and reports nothing. `--timeout=30s`
became 30, which is right by accident and is why it survived; `--timeout=2m`
became 2. The command still ran, it just gave up fifty-eight seconds early.
There is now a parser in `src/duration.c` taking `ns`, `us`, `ms`, `s`, `m`
and `h`
and compounds of them, keeps a bare number meaning seconds, rounds up so a
sub-second timeout cannot become zero — zero means "no deadline" to every
caller here — and refuses everything else rather than reading a prefix.

Its own tests found an overflow in it before it shipped: rounding with
`(total + NS_PER_S - 1) / NS_PER_S` wraps for a total near the top of the
range, and two nanosecond counts that each fit and together do not were
accepted and returned 0. Dividing before rounding fixes it. Written down
because the lesson is about the test, not the arithmetic: the case was in the
file because "a sum that overflows only when added" is a thing to check, not
because anyone suspected that line.


**34. A port argument was read as far as it parsed and no further.**
*(Phase 6, found while writing down the gaps rather than while testing.)*
`tailcat-c <addr> 10.0.0.1:22` connected to **port 10** of the server and
said nothing. `strtoul` with no endptr check stops at the first dot and
keeps the prefix, which is bug 33's defect in a second place nobody had
thought to look.

It matters because that string is not a typo: upstream documents
`tailcat ssh -p 10.0.0.1:22 <tc-addr>` for reaching a third address through
an exit node, and `-p` is handed straight to the pipe form. So following
upstream's own documentation produced a connection to the wrong port of the
right machine.

Ports now have to be the whole argument. The host:port form gets its own
message naming the command that does work, because "bad port" would have
been true and useless -- the user typed something valid, at the wrong
program.

Three bugs of one kind now: 33, 34, and the `-l` half of 32 are all a parser
accepting a prefix and discarding the rest. The lesson is not about
`strtoul`. It is that **every one of them still ran**, and the only visible
difference between right and wrong was a number nobody had a reason to
check.

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

- **Direct paths, with limits.** A session starts on the relay and moves to a
  direct path once one has been proven, falling back if it stops working. What
  is missing is the rest of what `magicsock` does: no relay-to-relay
  discovery, no UDP relay allocation (disco `0x04` and up), no path MTU
  discovery, and no interface preference beyond the round trip it produces.
  Two peers that both sit behind symmetric NATs will stay on the relay, which
  is the correct answer rather than a limitation -- but upstream has a UDP
  relay for that case and we do not.
- **UDP is reachable only through SOCKS.** `socks` implements UDP ASSOCIATE,
  which is upstream's surface for it too -- `forward` is TCP-only in both
  implementations. Fragmented SOCKS datagrams (`FRAG` non-zero) are dropped,
  which RFC 1928 permits and every implementation does.
- **The SSH server serves sftp and nothing else.** No shell, no PTY, no
  port or agent forwarding, no `exec` for `recv` — every one of those is a
  way to reach something other than the directory being served, and a drop
  box needs none of them. `ssh` and `cp` remain *clients* that exec the
  system ssh and scp with us as a `ProxyCommand`, which is exactly what
  upstream does for those two as well.
- **No rekeying as the initiator.** A peer may start a key exchange at any
  point and we complete it, keeping the session id; we never start one. The
  sequence number is the cipher nonce and must not wrap, so a session stops
  at 2^32 packets — unreachable against any peer that rekeys at all.
- **No WASM build.** Cosmopolitan does not target it.
- **`ls` is in-process, as upstream's is.** Upstream's `ls` is the one file
  command it does *not* shell out for: it links `golang.org/x/crypto/ssh`
  and `github.com/pkg/sftp` and drives them over its own tunnel. Ours does
  the same with `tc/sshclient.h` and the client half of `tc/sftp.h`, so it
  needs no `sftp` binary — which on Windows is not a given — and prints what
  upstream prints. `make live-ls` checks it against a real Go file server.

  What it does not do is read files: `ls` lists, and there is no `get`. A
  read client is a different feature from a listing one, and `cp` already
  covers fetching by execing scp.
- **`ssh` turns off host key checking**, because the destination it gives ssh
  is a hash of the address rather than a host anyone holds a key for, and the
  address already authenticates the server: reaching it required the
  pre-shared key and the server's public key. A `known_hosts` entry keyed on a
  synthetic name would add a prompt and no security.
- **`socks` reaches one server**, the one in its address. Upstream can route
  across several at once by giving each a `tc...` hostname; we take only the
  one from the command line.

  Destinations *are* honoured now, following upstream's rule: the hostname
  `server.tailcat` (or an empty host) means the server itself, and anything
  else is a destination to reach **through** it, which needs `serve
  exit-node`. **This changed in Phase 5**: `socks` used to ignore the
  destination host entirely and use only the port, because there was no way
  to reach anything else. A client that relied on that needs to say
  `server.tailcat` now -- which is also what it would have to say to
  upstream.

  Hostnames are resolved **on the client's machine**, as upstream resolves
  them. SOCKS5 exists partly so a proxy can resolve names, and one that
  refused them would break every ordinary client -- but the consequence is
  real: the query is visible to whoever sees this machine's DNS, and a name
  that means something different on the far side of the tunnel resolves to
  the wrong thing.
- **netcheck does not probe hairpinning or port mapping.** A relay is chosen
  by STUN round trip as upstream's netcheck does, and the NAT mapping is
  classified as stable or destination-dependent. What is missing is whether
  we can reach our own mapped address, and UPnP/PMP/PCP -- each a separate
  mechanism rather than a reading of these probes. `tailcat-c netcheck`
  prints what is measured.
- **`serve` with no ports handles one client and one connection**, then
  exits -- it writes to one stdout, so a second client would have nowhere to
  go. That is upstream's behaviour too. `serve <ports>` has no such limit and
  takes up to 8 clients and 64 connections at once.
- **The address is a bearer credential.** Anyone holding it can connect, so
  it is exactly as secret as the least careful place it has been pasted, and
  it cannot be narrowed after the fact. It is the only
  credential -- *unless* `--allow` is given, which restricts by client node
  key exactly as upstream's does. Without it, and especially with `serve
  exit-node`, anyone holding the address can reach anything the serving
  machine can, including its own loopback services and its cloud metadata
  endpoint. `--allow` is the answer and it is off by default, which is
  upstream's default too.

### TLS

- **TLS 1.2 only**, and not for the reason this entry used to give. Enabling
  1.3 in Mbed TLS 3.6 turned out to be easy; what blocks it is that DERP's
  1.3-only meta certificate is **Ed25519**, which Mbed TLS cannot parse, so
  the chain is rejected whole. See
  [TLS 1.3 is blocked on Ed25519](#tls-13-is-blocked-on-ed25519). Tailscale's
  relays accept 1.2 and ECDHE with AEAD suites is not a weak configuration —
  but it does mean upstream's "fast start" optimisation is unavailable, since
  reading the relay's key from that certificate requires 1.3.
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

- **A read timeout is recoverable and a write timeout is not.** Both exist
  (`tc_derp_set_read_timeout`, `tc_derp_set_write_timeout`), but they are not
  symmetric: a timed-out read leaves the TLS record layer holding what it
  had, so a later read resumes mid-record, whereas a timed-out write may have
  emitted part of a frame and the stream cannot be trusted afterwards. The
  headers say so at both declarations.
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

- [x] **TCP keepalive and idle timeout.** Done, and overdue: see bug 21. An
      established connection with nothing to send had no timer at all, so a
      peer that vanished held its table slot until the process exited. After
      `TC_TCP_KEEPALIVE_IDLE_MS` of silence a probe goes out, and after
      `TC_TCP_KEEPALIVE_PROBES` unanswered ones the connection is dropped.

      What remains, and is much smaller: a connection in `FIN_WAIT_2` whose
      peer is alive but never closes. The probes are answered, so it is not
      the vanished-peer case, and no timer bounds it. Linux caps it at 60
      seconds (`tcp_fin_timeout`) for the same reason we would need to.
- [ ] **Reaping is caller-driven.** `tc_tcp_mux_reap` has to be called or
      closed connections hold their table slots; nothing does it on a timer.
- [x] **Tiered local diagnostics** (`make diag5/3/1`) with a pre-push hook.
      Deliberately not hosted CI: the live tests dial Tailscale's production
      relays, and pointing a robot at someone else's infrastructure on every
      push is not a reasonable default.
- [ ] **Run the aarch64 half.** `check-fat` proves it compiles, links and is
      present in every binary; for most of this project's life nothing had
      ever *executed* it, which made it the largest untested claim here.
      **Three of the four rungs are now done and the suite passes on aarch64
      instructions**; the last one needs hardware, or a full-system emulator
      to exercise Cosmopolitan's own aarch64 runtime rather than only ours.
      - [x] **Build x86_64 with `-funsigned-char`** and run the whole suite —
            `make test-unsigned-char`, and a level 1 stage.

            The concern was real and now measured: `__CHAR_UNSIGNED__` is
            **undefined for cosmo's x86_64 and defined for its aarch64**, so
            plain `char` is signed in one half of every fat binary we ship
            and unsigned in the other. `if (c < 0)` on a `char` means
            different things in the two halves, and `json.c`, `cbor.c`,
            `base64url.c` and `http.c` are full of character handling that
            *mostly* uses `uint8_t`. "Mostly" was the word hiding it.

            All 35 test binaries pass under the other signedness, so the
            arithmetic is clean. That removes the largest *class* of aarch64
            risk without an emulator.
      - [x] **qemu-user** — `make test-aarch64`, which needs
            `qemu-user-static` installed and skips with instructions when it
            is not.

            The plan assumed this would need `assimilate` to flatten an APE
            into a plain ELF. **It does not.** cosmocc already leaves a plain
            statically-linked aarch64 ELF beside each binary as
            `<name>.aarch64.elf`, and qemu-user runs those directly — no APE
            loader, no binfmt registration.

            **Run, and it passes.** All 36 test binaries and 9,979 assertions,
            on real aarch64 instructions under qemu-user 8.2.2, first attempt,
            including the parts most likely to be architecture-sensitive:
            Ed25519's 1,511 checks of bignum arithmetic, 842 of Noise, 1,241
            of the UDP mux, and the whole SSH and SFTP stack.

            Two of everything, both halves executed. Until this ran, half of
            every binary in this repository had been compiled and never once
            invoked, and the case for it resting on `-funsigned-char` above
            was an argument rather than a measurement.

            Ubuntu ships the emulator as `qemu-aarch64-static` and not
            `qemu-aarch64`, which is why the level 1 stage accepts either
            name.
      - [ ] **qemu-system** with a real aarch64 Linux: slow, but the only
            option that exercises Cosmopolitan's own aarch64 runtime rather
            than just our instructions. qemu-user translates syscalls to the
            host kernel, so it tests our code and not Cosmopolitan's.
      - [ ] **Real hardware** beats all of the above if any is to hand.
- [ ] **Test on macOS and the BSDs.** Both architectures now execute their
      own instructions, so what is left is the *operating systems*: Linux and
      Windows are covered and the other four are not. That is now the largest
      untested claim in the project, and unlike the aarch64 half it cannot be
      closed with an emulator and a package — it needs the machines.
- [ ] **Thread-safety review** of `tc_derp_client`, or an explicit statement
      that callers must serialise it. Nothing here is threaded today — the
      SSH server and client are blocking state machines driven by an event
      loop, which is why their reads pump rather than wait — so this is about
      what a future caller may assume, not about a bug.
- [ ] Revisit **TLS 1.3**. Ed25519 now exists here, so the remaining blocker
      is narrower than it was: Mbed TLS's X.509 parser has no hook to hand an
      unknown signature algorithm to ours, and the certificate in question is
      one we would then skip rather than verify. Still in service of an
      optimisation we do not implement.
- [ ] Refresh the **CA bundle** and decide on a cadence for it.
- [ ] Consider making the address-parser limits runtime-configurable.
- [ ] **Refresh the DERP map cache in the background** rather than only on a
      miss, so a long-lived process does not pay a fetch mid-session.
- [x] **Rekeying for the SSH server.** Done as a responder: a peer may
      start a key exchange at any point and we complete it, keeping the
      session id fixed so the new keys stay bound to the identity proven at
      the start. `make live-sshd` moves 2MB with `RekeyLimit=16K`, which is
      about 120 exchanges, and requires the byte count to survive all of
      them. We never initiate, so the sequence number wrapping at 2^32
      packets is still a hard stop -- unreachable against any peer that
      rekeys at all. See bug 23.
- [ ] **Fuzz the DERP frame codec.** It parses attacker-influenced lengths
      straight off a socket, which is the same shape as the TCP reassembly
      queue, and that is where bugs 20 and 21 came from. It has vectors and
      no fuzzer.
- [ ] **Extend mutation testing beyond the modules that have had it.** Path
      discovery, the UDP mux, TCP, the SSH wire format, the packet layer, key
      exchange, userauth, channels and the drop box have all been mutated;
      the address codec, CBOR, JSON, Noise and DERP have not. Every module
      that has been mutated so far gave up at least one untested assertion,
      and two of them gave up a real bug.

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
      Rekeying and the cookie/DoS exchange landed later, in phases 2.2 and
      2.3.
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
over SSH, so the *server* half needed an SSH server — Phases 5.4 and 5.5,
rather than the ~300 lines that entry estimated. Its *client* half worked
from the start, because `cp` execs the system scp, which speaks exactly that
protocol; `make live-recv` has been delivering a file into a real `tailcat
recv` drop box since then.

- [x] **Phase 4 — direct peer-to-peer paths.** A UDP transport, a STUN
      client, netcheck, the disco protocol, and the path discovery and
      upgrade machinery that uses them. A session starts on the relay, moves
      to a direct path once one is *proven* — only an answered Ping counts —
      and moves back if it goes quiet. Tested against a simulated network
      where NAT behaviour, loss, delay and the clock are all arguments, then
      against reality: `make live-direct` for two of ours, and `make
      live-cli`, which now shows our client going direct to a **real Go
      tailcat server** using Tailscale's own disco protocol.

- [x] **Phase 5.1, 5.2 — datagrams and exit nodes.** UDP through the tunnel,
      checked against packets built by `gopacket` because an IPv6 UDP
      checksum covers a pseudo-header and a wrong one is invisible to a
      loopback test. NAT64 for IPv4 destinations, anchored to RFC 6052's
      published example. Exit-node mode on both muxes and both ends of the
      CLI, off unless asked for by name, with `make live-exitnode` checking
      that a server which was *not* asked to forward refuses.

- [x] **Phase 5.3 — TLS 1.3, attempted and reverted.** See
      [above](#tls-13-is-blocked-on-ed25519). Kept from it:
      `tc_tls_last_version()`, and a Makefile fix — Mbed TLS objects now
      depend on `mbedtls_config.h` explicitly, because `-MMD` stops at the
      `-isystem` header that includes it, so editing the config rebuilt
      nothing.

- [x] **Phase 5.1 and 5.7 — SOCKS5 UDP ASSOCIATE and `--allow`.** The two things
      that finished the CLI's exposure of what the data plane could already
      do. `socks` now relays datagrams (RFC 1928 §7) with an association
      owned by its TCP control connection, so a forwarder is never left
      running for whoever finds the port; `--allow` restricts a server by
      client node key, as upstream's does. `tc_allow_permits` refuses the
      all-zero key *before* the no-list shortcut, because checking after it
      would have admitted that key in exactly the permissive case where
      nobody is looking. `make live-socksudp` and `make live-allow` check
      both against real clients.

- [x] **Ed25519 of our own.** RFC 8032 in 877 lines — radix-2^51 field
      arithmetic, extended Edwards coordinates, cofactorless verification and
      the `S < L` canonicity check — against RFC 8032's published vectors and
      byte-for-byte against Go's `crypto/ed25519`. Written because the SSH
      subset needs `ssh-ed25519` and because vendoring a second crypto stack
      for one curve was the wrong trade. It also narrows the TLS 1.3 blocker
      without removing it.

- [x] **TCP hardening.** Two ways an authenticated peer could permanently
      exhaust the 64-entry connection table, both found by making the TCP
      fuzzer assert its own reach rather than trusting it: a corrupt SYN left
      an unreapable connection in `LISTEN`, and a peer that simply vanished
      left one in `ESTABLISHED` with no timer watching it. Keepalive probes
      close the second. Bugs 20 and 21 above have the detail, including the
      third bug the fix contained and the fourth it revealed.

- [x] **Phase 5.4 — an SSH subset.** The licence question was
      [decided](#vendoring-an-ssh-server) rather than deferred: write the
      subset, with TinySSH as a reference and not a dependency. RFC 4251's
      wire types, the binary packet protocol with
      `chacha20-poly1305@openssh.com`, `curve25519-sha256`, `ssh-ed25519`
      host keys, publickey authentication, one channel, and rekeying as a
      responder — server and client both, in 2,900 lines against the ~20,000
      of Go a general implementation takes. `make live-sshd` puts a real
      OpenSSH 9.6 client against our server and `make live-sshloop` runs our
      own two halves against each other.

- [x] **Phase 5.5 — SFTP, the drop box, and `recv`.** A version 3 codec, a
      write-only drop box whose central rule is that *the server chooses
      every stored filename*, and the `recv` subcommand that serves it on
      port 22 of the tunnel. `make live-dropbox` carries out the attacks with
      a real `scp` and `sftp` and checks the filesystem afterwards rather
      than what the client printed; `make live-recv-serve` does it through a
      real relay.

- [x] **`ls`, in-process.** Upstream's `ls` is the one file command it does
      not shell out for, so ours does not either: an SSH client and an SFTP
      client over our own tunnel, printing what upstream prints. `make
      live-ls` lists a directory served by a real Go tailcat.

**Phases 1 through 5 are done**, apart from the browser build, which
Cosmopolitan cannot target, and TLS 1.3, which is blocked on Mbed TLS's X.509
parser rather than on effort. What is left of upstream's surface is two
deliberate omissions: `serve ssh` as a general shell server, and the
read-write and recursive file modes. See [PLAN.md](PLAN.md) for the detail.

## Licence

BSD-3-Clause, matching upstream tailcat. Portions are ports of
Tailscale-authored code; see `upstream-tailcat/LICENSE`.
