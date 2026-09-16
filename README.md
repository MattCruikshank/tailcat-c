# tailcat-c

A rewrite of [tailcat](https://github.com/tailscale/tailcat) in C11, built
with the [Cosmopolitan](https://github.com/jart/cosmopolitan) C compiler into
a single **fat Actually Portable Executable** — one binary that runs on
Linux, macOS, Windows, FreeBSD, OpenBSD and NetBSD, on both x86_64 and
aarch64.

**Status: in progress.** The address layer is complete and verified
wire-compatible against the real Go implementation. The network layers are
not written yet. See [Roadmap](#roadmap).

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

## Build

Requires the [cosmocc](https://github.com/jart/cosmopolitan) toolchain:

```sh
mkdir -p ~/cosmocc && cd ~/cosmocc
curl -fsSL -o cosmocc.zip https://cosmo.zip/pub/cosmocc/cosmocc.zip
unzip -o cosmocc.zip
```

Then:

```sh
make            # build
make test       # unit tests; also asserts every binary is a fat APE
make fuzz       # fuzz the address parser under ASan + UBSan (host gcc)
make interop    # cross-check against the real Go tailcat library
```

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

### Cosmopolitan-specific findings

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

## Roadmap

- [x] **M1 — Addresses.** base64url, strict CBOR, the `Addr` codec, golden
      vectors, differential testing against Go, fuzzing.
- [ ] **M2 — Crypto.** Vendor mbedTLS for X25519, ChaCha20-Poly1305, HKDF,
      the CSPRNG and TLS; add BLAKE2s, which WireGuard needs and mbedTLS
      lacks. Verified against RFC 7539/7693/8439 vectors. Using a maintained
      library rather than hand-rolling is a deliberate call for a
      security-critical rewrite.
- [ ] **M3 — DERP client.** HTTP upgrade, the frame protocol, the key
      exchange, send/recv paths.
- [ ] **M4 — WireGuard.** Noise IK handshake with the pre-shared key mixed
      in, transport encryption, the replay window, rekeying.
- [ ] **M5 — meow bootstrap.** The 4-byte-magic ping/pong tailcat uses over
      DERP to introduce the two peers (see upstream `disco.go`).
- [ ] **M6 — Minimal TCP.** A two-peer userspace TCP: state machine, RTO,
      fast retransmit, window management. Replaces gvisor's netstack.
- [ ] **M7 — CLI.** The netcat-style stdin/stdout pipe mode.

## Licence

BSD-3-Clause, matching upstream tailcat. Portions are ports of
Tailscale-authored code; see `upstream-tailcat/LICENSE`.
