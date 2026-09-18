<!--
The shape of this file -- its sections, their order, and the worked examples
they are built around -- follows the README of the tailcat project:

    https://github.com/tailscale/tailcat
    Copyright (c) 2020 Tailscale Inc & contributors.
    SPDX-License-Identifier: BSD-3-Clause

This program is a port of that one and is under the same licence; the terms
and that notice are in LICENSE. The prose and the terminal output here
describe this implementation, which differs from upstream in the ways the
second section sets out.
-->

# tailcat-c

**[tailcat](https://github.com/tailscale/tailcat), rewritten in C and built by
the [Cosmopolitan C Compiler](https://justine.lol/cosmopolitan/) into a single
file that runs on six operating systems and two processor architectures.**

Upstream tailcat is a Go program: a remix of Tailscale's open source pieces
that gives you a WireGuard-encrypted tunnel between two machines with no
Tailscale account, no control plane, and no root. One side runs a server and
gets back a short **tailcat address**; the other side passes that address to a
client. You exchange the address however you like -- chat, email, a DNS record
-- and everything after that is encrypted end to end. The first connection
bootstraps through a DERP relay, and then the two sides look for a direct
peer-to-peer path and usually find one.

This program does the same job, from scratch, in C.

`tailcat-c` is one file. Not one per platform -- **one file**, an [Actually
Portable Executable](https://justine.lol/ape.html) carrying both x86-64 and
aarch64 code and running unmodified on Linux, macOS, Windows, FreeBSD, OpenBSD
and NetBSD. No runtime, no installer, no shared libraries, nothing to
configure. Copy it and run it.

It is not a wrapper. No Go is involved in the build and none of Tailscale's
code is linked in: the WireGuard implementation, the Noise handshake, the DERP
relay client, the NAT-traversal protocol, the TCP/IP stack, the SSH server and
client and the SFTP layer are all written here. The only third-party library is
[Mbed TLS](https://github.com/Mbed-TLS/mbedtls), for TLS to the relay.

**It interoperates with upstream in both directions**, which is the point and
the only claim worth making. A real Go `tailcat` client reaches a `tailcat-c`
server, and a `tailcat-c` client reaches a real Go `tailcat` server. Both
directions are checked against the real binary over real relays before every
release.

For how that was verified, and the 48 bugs the verification caught, see
[PORT.md](PORT.md). This file is the manual.

## What this port does not do

Most of upstream's surface is here. These are the parts that are not. None of
them is an oversight: each is either a deliberate trade or something the
toolchain cannot reach.

- **There is no Go library.** Upstream's CLI is a thin shell over an importable
  package, and a large part of its documentation is that API. Here the
  command-line tool *is* the program. Everything it can do it does through
  flags, and nothing is importable. To embed tailcat in a Go program, use
  upstream.

- **There is no browser build.** Upstream compiles to WebAssembly and has a web
  demo that interoperates with the CLI. Cosmopolitan does not target
  WebAssembly, so this cannot. That is a toolchain limit, not a backlog item.

- **TLS 1.2 to the relay, not 1.3.** The relay connection is TLS and this one
  negotiates 1.2. The blocker is Mbed TLS's X.509 parser rather than the
  handshake: it will not parse the Ed25519 certificates the 1.3 path needs.
  The tunnel inside is WireGuard either way, so this affects how the relay
  connection is secured and nothing about your data.

- **Fewer SSH key algorithms.** An authorized key may be ed25519, ECDSA on
  P-256 or P-384, or RSA verified with SHA-256 or SHA-512 -- which covers every
  key anyone actually has. Upstream additionally takes `ssh-rsa` and `ssh-dss`,
  which sign with SHA-1; the `sk-*` hardware-token forms; P-521, which this
  Mbed TLS build does not carry; and OpenSSH certificates. A line naming one of
  those is skipped and counted, and a file with no usable key left is an error
  rather than a server nobody can log in to.

- **No pseudo-terminal on Windows.** Cosmopolitan's `forkpty` is `ENOSYS`
  there, so `serve ssh` sessions on Windows run on pipes -- the same fallback
  OpenSSH uses, which means no job control and no terminal resizing on that
  platform. Every other platform gets a real pty.

- **Smaller concurrency limits.** Eight tunnel clients at once, and `socks`
  holds up to four servers. Upstream's limits are whatever the machine will
  bear. These are fixed allocations, chosen so the program never calls `malloc`
  on a path an attacker can reach.

- **Four of the six platforms have never been run.** Linux and Windows are
  tested on every release run, on both architectures. macOS, FreeBSD, OpenBSD
  and NetBSD are compiled and linked into the same binary and have never
  executed an instruction. Treat them as untested. The plan for fixing that is
  [BSD-plan.md](BSD-plan.md).

- **`readme` prints something else.** Upstream embeds its own README;
  `tailcat-c readme` embeds [doc/usage.md](doc/usage.md), a concise manual
  rather than a document about a port.

Smaller differences are noted where they come up below. The full
feature-by-feature comparison, including everything that *is* here, is the
table in [PORT.md](PORT.md#features).

## Install

There are no packages and no per-platform downloads, because there is nothing
to choose between: the binary is the same file everywhere.

Build it with [cosmocc](https://github.com/jart/cosmopolitan):

```sh
$ make
$ ./build/cosmo/tailcat-c version
```

That produces `build/cosmo/tailcat-c`. Copy it to any of the six supported
systems and run it; on Windows, rename it to `tailcat-c.exe` first.

`make test` builds and runs the test suite. `make CC=gcc SANITIZE=1 test` does
the same under the host compiler with AddressSanitizer and
UndefinedBehaviorSanitizer, which is worth doing: the two toolchains disagree
often enough to be useful.

## Usage

### Pipe stdin/stdout between two machines

The server starts and prints its ephemeral address:

```sh
$ tailcat-c
# listening with new address: tcXXXXXXXXX
(waiting)
```

The client sends to it:

```sh
$ echo hello | tailcat-c tcXXXXXXXXX
```

and the server prints what arrived, then exits:

```sh
$ tailcat-c
# listening with new address: tcXXXXXXXXX
hello
$
```

### Expose local ports through the tunnel

`serve` takes ports, ranges, and `all`:

```sh
$ tailcat-c serve 8080,8443          # or: tailcat-c serve all
# listening with new address: tcXXXXXXXXX
# serving 8080,8443 to localhost, up to 8 clients
```

The client names the port after the address:

```sh
$ tailcat-c tcXXXXXXXXX 8080
```

### Forward local ports to a tailcat server

To make a served port an ordinary local TCP port -- for a browser, a database
client, or anything else that speaks neither SOCKS nor stdio -- use `forward`:

```sh
$ tailcat-c forward tcXXXXXXXXX 18080:8080 3306
# 127.0.0.1:18080 -> the server's port 8080
# 127.0.0.1:3306 -> the server's port 3306
```

A local port of 0 asks the operating system for a free one; each listener
prints the port it got.

A mapping may also name an address *beyond* the server, which needs the server
running as an exit node:

```sh
$ tailcat-c serve exit-node
# acting as an exit node: clients may reach anything this machine can

$ tailcat-c forward tcXXXXXXXXX 3001:172.23.52.30:3001 13306:[2001:db8::1]:3306
```

IPv6 destinations go in brackets. The pipe and `ssh -p` take the same
destination syntax; see [Misc commands](#misc-commands).

Listeners bind to `127.0.0.1` by default. Use `--bind 0.0.0.0` only when
clients on other machines should be able to reach them. `--verbose` before the
subcommand turns on networking logs. Ctrl-C stops forwarding.

### Open a browser to a tailcat server

```sh
$ tailcat-c serve 80
$ tailcat-c browse tcXXXXXXXXX
```

`browse` is shorthand for `forward --open-browser <tc-addr> 0:80`: it forwards
a free local port to the server's port 80 and opens a browser there once the
listener is up. `--open-browser` works with any single `forward` mapping.

### Public-key-authenticated SSH server

```sh
$ tailcat-c serve --ssh-authorized-keys ~/.ssh/authorized_keys ssh
# listening with new address: tcXXXXXXXXX
# serving a shell to 3 authorized keys
```

The flag takes a file, a literal public key line, or a GitHub account, and
sources can be comma-separated or the flag repeated. A `user@github` source
fetches `https://github.com/user.keys` once, before the server starts:

```sh
$ tailcat-c serve --ssh-authorized-keys alice@github,./contractor.pub ssh
```

Every source must exist and produce at least one usable key, or startup fails
-- a server that came up with an empty list would be one nobody can log in to,
and its operator would have no way to tell.

Key options such as `command=` and `from=` are **refused**, not ignored. Each
one is a restriction, and reading the key while dropping it would grant more
than the file says. Upstream refuses them for the same reason. For a forced
command, see [Run a command per connection](#run-a-command-per-connection).

Which algorithms are accepted, and which are not, is in [What this port does
not do](#what-this-port-does-not-do).

`serve ssh` without `--ssh-authorized-keys` fails; use `no-auth-ssh` explicitly
when the tunnel identity is enough.

### Auth-free SSH server

```sh
$ tailcat-c serve no-auth-ssh
# listening with new address: tcXXXXXXXXX
# WARNING: serving a shell with no client authentication
# anyone who has this address can run commands as you on this machine
# the address is the only secret: treat it exactly like a password
# `serve ssh --ssh-authorized-keys ...` asks for a key as well
```

> [!WARNING]
> With `no-auth-ssh` the address **is** the credential: anyone who learns it
> gets a shell as the user running the server. Share it only over private
> channels, and never publish it -- not in a DNS TXT record, not anywhere. An
> SSH server reachable by DNS name must authenticate clients some other way:
> `--allow` at the tunnel layer, `--ssh-authorized-keys` at the SSH layer, or
> both.

The client side, either way:

```sh
$ tailcat-c ssh tcXXXXXXXXX
$ tailcat-c ssh tcXXXXXXXXX ls -la
```

`ssh` and `cp` exec the system `ssh` and `scp` with a ProxyCommand that runs
this program, so you get your own client, your own config, and scp's progress
display.

### Run a command per connection

Like inetd, `exec` runs a command for each incoming connection with the
connection as its stdin and stdout. The command comes after `--`:

```sh
$ tailcat-c serve exec -- /usr/bin/fortune
```

The command's stderr goes to the server's. It gets the peer's node key in
`$TAILCAT_PEER_KEY` (in `--allow`'s format) and the peer's tunnel address in
`$TAILCAT_REMOTE_ADDR`.

Given with `ssh` or `no-auth-ssh`, the command replaces the shell instead, like
OpenSSH's `ForceCommand`: every session runs only that command, on a pty if the
client asked for one, and the server offers no shell, no client-chosen command
and no SFTP. Whatever the client asked to run arrives in
`$SSH_ORIGINAL_COMMAND`.

```sh
$ tailcat-c serve --ssh-authorized-keys alice@github ssh -- ./deploy.sh
$ tailcat-c serve no-auth-ssh -- git-upload-pack /srv/repo.git
```

### Send and receive files

To receive, run a drop box and share the address it prints:

```sh
$ tailcat-c recv ~/inbox
# listening with new address: tcXXXXXXXXX
# receiving files into /home/you/inbox
```

The sender:

```sh
$ tailcat-c cp report.pdf tcXXXXXXXXX:
```

The drop box is write-only, and the rule underneath it is that **the server
chooses every stored filename**: a sender cannot list the directory, read
anything back, overwrite an existing file, or say where its file goes.
`recv --accept-dirs` takes directory trees instead, and then senders do keep
their own names.

To offer files, serve a directory:

```sh
$ tailcat-c serve files                    # the current directory, read-only
$ tailcat-c serve --files /pub:rw files    # a given one, read-write
# serving /pub read-write over SFTP
```

```sh
$ tailcat-c ls -l tcXXXXXXXXX
$ tailcat-c cp tcXXXXXXXXX:report.pdf .
```

`ls` speaks SFTP in-process, so it works with no OpenSSH installed.

Every path is confined to the served directory. Upstream does that with Go's
`os.Root`, which refuses to traverse `..` or a symlink at the system-call
level. C has no such thing, so the walk here resolves `..` before any of it
reaches the filesystem and opens each component with `openat(O_NOFOLLOW)`: a
symlink is refused rather than followed, which is the part a `realpath()` check
cannot do without losing a race.

The file service speaks SFTP, so stock `sftp` and `scp` work against it given a
ProxyCommand through this program -- the same trick `cp` and `ssh` use. The
`ssh` and `no-auth-ssh` servers serve SFTP too, with the same access as the
shell.

Transfers are not compressed. SFTP has no compression of its own and neither
does the SSH transport here; compress before sending if it matters.

### Misc commands

`ping` reports whether the reply came back over a relay or a direct path.
`--until-direct` keeps trying until a direct path works, and exits non-zero if
none does:

```sh
$ tailcat-c ping --until-direct tcXXXXXXXXX
pong in 61ms via DERP(nyc)
pong in 3ms via 203.0.113.7:41641
```

Upstream prints fractional milliseconds here and this prints whole ones: both
of its clocks measure in whole milliseconds, so the decimals would be invented.

Run a command behind a SOCKS5 proxy over the tunnel:

```sh
$ tailcat-c socks tcXXXXXXXXX curl http://server.tailcat:8081/
```

In a SOCKS request the hostname `server.tailcat` means the server itself. A
tailcat address also works directly as a URL hostname, so the address argument
is optional:

```sh
$ tailcat-c socks curl http://tcXXXXXXXXX:8081/
```

(Addresses are case-sensitive. That works with curl and most command-line
tools, but not with browsers, which lowercase hostnames.)

Reach a third address through a server acting as an exit node, from the pipe or
from `ssh`:

```sh
$ tailcat-c tcXXXXXXXXX 10.0.0.1:22
$ tailcat-c ssh -p 10.0.0.1 tcXXXXXXXXX        # a bare address means its 22
$ tailcat-c ssh -p 10.0.0.1:2222 tcXXXXXXXXX
```

`parse` prints what an address contains, without connecting to anything:

```sh
$ tailcat-c parse tcXXXXXXXXX
{
    "ServerPublic": "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34",
    "RegionID": 302
}
```

That output is byte-identical to upstream's for the same address, which is
checked on every release run against 500 addresses the Go binary generates.

`resolve` turns a short address -- one naming a relay region by number, so
clients must fetch the relay list -- into a longer self-contained one with the
relay's details embedded, which clients can connect to faster and offline. A
server can print that form directly with `serve --full-address`.

`netcheck` reports UDP reachability, NAT behaviour and relay latency.
`version` prints the version. `readme` prints the manual.

## Key management

A server's address contains its WireGuard public key and an independent
WireGuard pre-shared key, so the saved key material decides who can reach you.

* **Ephemeral keys, the default.** Each run generates a fresh key in memory and
  prints an address nobody has ever seen. When the process exits the key is
  gone and the address is dead for good, so sharing it only ever refers to that
  one run.

* **Saved keys.** `genkey` writes a key to disk so the address stays the same
  across restarts. The flip side: anyone you have *ever* given that address to
  can connect to any future server using it, unless you restrict clients with
  `serve --allow`.

The startup line says which kind is in use, so you can tell a fresh single-use
server from one re-listening on an address you may have shared before.

Pre-shared keys are on by default and strongly recommended. `--psk=false` on
`serve` or `genkey` produces shorter addresses for compatibility with tailcat
clients v0.5.0 and earlier, but gives up post-quantum protection and protection
from a relay operator that can see both peers' public keys.

```sh
$ tailcat-c genkey --key default --region nyc
# wrote /home/you/.config/tailcat/keys/default.private.json
tcXXXXXXXXX

# later; the key named "default" is used automatically once it exists:
$ tailcat-c serve 8080
# listening with saved key "default": tcXXXXXXXXX

# ... unless you ask for a one-off ephemeral key:
$ tailcat-c serve --key new 8080
# listening with new address: tcXXXXXXXXX
```

`default` is a magic name: once it exists, plain `tailcat-c` uses it instead of
generating an ephemeral key, and the startup line is what tells you which
happened. `--key new` forces an ephemeral one, `--key <name>` picks a different
saved key, `genkey --delete --key default` removes it, and `genkey --list`
lists what you have.

Addresses can also be published as DNS TXT records and looked up by name. A DNS
name works anywhere an address does:

```sh
# if example.com has a TXT record "tailcat=tc..."
$ tailcat-c example.com 8080
$ tailcat-c ssh example.com
$ tailcat-c ping example.com
```

> [!WARNING]
> An address is normally a secret: knowing it is what lets a client connect. A
> DNS TXT record is **not** secret. It is public, world-readable and actively
> scanned. Publishing an address in DNS hands that capability to the whole
> internet, which is only safe if the server authenticates clients by something
> other than knowledge of the address: `serve --allow` at the tunnel layer, or
> `serve --ssh-authorized-keys ... ssh` for SSH. Never publish the address of a
> `no-auth-ssh` server, or any other server that trusts whoever connects --
> that is a shell on your machine, published in a TXT record.

## Examples

### Protected SSH server over DNS

An SSH server reachable from anywhere by name, with no inbound ports open,
where WireGuard authenticates the client before the SSH server sees a packet.

> [!WARNING]
> `--allow` below is not decoration. The TXT record makes the address public,
> so having the address no longer proves anything and the server must
> authenticate clients itself -- here by allowing exactly one client node key.
> Without it, anyone who reads the record can connect.

On the client, generate an identity. It prints the public key, which is all the
server needs:

```sh
client$ tailcat-c genkey --client --key client-default
# wrote /home/you/.config/tailcat/keys/client-default.private.json
nodekey:cfb6bfa77a0654d7450947fd6acef17d2cd848da1d30b2540b13dac272ddfd16
```

On the server, generate a key pinned to its nearest relay region, then serve
SSH to that client alone:

```sh
server$ tailcat-c genkey --key default --fixed-region
# wrote /home/you/.config/tailcat/keys/default.private.json
tcXXXXXXXXX

server$ tailcat-c serve --allow nodekey:cfb6bf...ddfd16 22
# listening with saved key "default": tcXXXXXXXXX
```

Publish the address:

```
my-server.example.com. 300 IN TXT "tailcat=tcXXXXXXXXX"
```

And the client side is just:

```sh
client$ tailcat-c ssh my-server.example.com
```

Client modes use the saved `client-default` key automatically when it exists,
so no extra flags are needed to present the allowed identity. Anyone else's
handshake is ignored: they cannot reach the SSH server, or even learn that one
is running.

As a safety net, `ssh` probes a DNS-named destination before connecting. It
tries to log in the way a stranger would -- a freshly generated client key, no
SSH credentials -- and if that succeeds it refuses to connect and says why,
because anyone who reads the record could do the same. The probe dials whatever
`-p` names, so it checks the destination you are actually about to use.
`--skip-dns-safety-check` skips it.

Why `--fixed-region`: it measures the nearest relay region once, now, and bakes
it into the key file and the printed address, so restarts rendezvous in the
same place and the published address stays valid. The default, `--region auto`,
bakes in "choose at startup" instead -- fine for one-off use, wrong for an
address published in DNS. `--region <name>` pins an explicit one and
`--region list` shows the choices.

### Bring your own relay

Nothing requires Tailscale's relays. [Run your own DERP
server](https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp) and
generate a key that uses it by naming its hostname -- or several,
comma-separated -- as the region:

```sh
server$ tailcat-c genkey --key default --region derp.example.com
tcXXXXXXXXX

server$ tailcat-c serve 22
```

The address then embeds your relay's hostname:

```sh
$ tailcat-c parse tcXXXXXXXXX
{
    "ServerPublic": "nodekey:8022c28ea8f52ec7a0a51b644ce00fef3aae150731a01c61a3abd3ac26e14a49",
    "Region": [
        {
            "Nodes": [
                {
                    "HostName": "derp.example.com"
                }
            ]
        }
    ]
}
```

so clients need no extra flags and neither side ever contacts Tailscale's relay
list or relays. It is also the one `genkey` form that makes no network request
at all. If you run a fleet, serve your own relay list as JSON and point both
sides at it with `--derpmap-url`.

## How it works

### Tailcat addresses

A server is identified by a **tailcat address**: `tc` followed by
base64-encoded [CBOR](https://cbor.io/) containing

- the server's WireGuard public key (Curve25519, 32 bytes),
- a separate path-discovery public key (Curve25519, 32 bytes),
- by default an independent WireGuard pre-shared key (256 random bits), which
  stops a relay operator that can see both public keys from joining the tunnel
  and protects recorded traffic against a future quantum attacker,
- and relay information: either a small integer naming one of the default
  relays, or full relay details, so a custom relay can be used or a client can
  skip fetching the relay list.

A typical address with a region number is about 140 bytes; with relay details
embedded it is longer but self-contained.

The default address is a **secret bearer capability**, because it contains the
pre-shared key. Share it only with clients that should be able to connect.

### Network stack

This is where the port diverges most from upstream, so it is worth being
precise. Upstream reuses Tailscale's own components: `magicsock` for the
transport, gVisor's netstack for userspace TCP/IP, and Tailscale's WireGuard
implementation. **None of that is here.** The equivalents are:

- **WireGuard** -- the Noise IKpsk2 handshake, the transport keys, rekeying and
  cookie replies, written here against the protocol specification and checked
  against golden vectors and against `wireguard-go` over a real socket.
- **The relay transport** -- a DERP client: the framing, the key exchange and
  reconnection. It multiplexes the tunnel over a relay and over direct UDP.
- **NAT traversal** -- STUN endpoint discovery, the disco protocol, the
  call-me-maybe exchange and hole-punching, and the netcheck that picks a
  region by latency.
- **TCP/IP** -- a small userspace TCP stack. Connections are terminated inside
  the process, so there is no TUN device, no routing change and no root,
  exactly as upstream promises; the code doing it is not gVisor.
- **TLS** -- Mbed TLS, the one third-party library, for the relay connection
  only.

### Connection flow

1. **The server starts.** It generates or loads a WireGuard keypair and, by
   default, a pre-shared key, connects to a relay, and prints its address. Then
   it waits.

2. **The client parses the address** for the server's public key,
   path-discovery key, optional pre-shared key and relay. It generates its own
   ephemeral keypair and connects to the same relay. The path-discovery key is
   separate so it can appear in cleartext direct-path frames without revealing
   the WireGuard public key, and the pre-shared key stays the secret capability
   even when a relay operator sees both peers' public keys.

3. **Discovery handshake.** The client sends a **Meow** message through the
   relay carrying its node public key. The server adds the client as a peer,
   reconfigures, and replies **Meowed**.

4. **WireGuard tunnel.** With both sides configured as peers, the handshake
   proceeds over the relay. Once it completes, the tunnel is up.

5. **NAT traversal.** In parallel each side advertises its UDP endpoints -- the
   public address learned by STUN, plus local interface addresses -- and both
   attempt hole-punching. On success the traffic moves to a direct path; on
   failure the relay keeps carrying it, just more slowly.

6. **Data transfer.** The client dials a TCP port through the tunnel, and the
   server dispatches the connection by port: forwarding to localhost, piping to
   stdout, running an SSH session, and so on.

### Addressing

Each peer derives a deterministic IPv6 address from its WireGuard public key.
That is an implementation detail rather than something users see, and upstream
notes it may change; this port follows whatever upstream does, because the two
have to agree.

## Interoperability

Interoperating with upstream is the whole purpose, so it is tested rather than
asserted. Every release run puts this program against the real Go `tailcat`
binary over real relays, in both directions -- a Go client against this server
and this client against a Go server -- for the pipe, served ports, forwarding,
SOCKS, exit nodes, `ls`, `recv`, SSH and file serving. Saved key files are
exchanged both ways too, since an address is a function of its key, and a key
file only one implementation could read would not be a saved identity at all.

The SSH server is additionally checked against real OpenSSH rather than against
upstream, which is the stronger test for that layer: both implementations here
were written from the same RFCs, and OpenSSH was not.

## Security

The address is a bearer credential. Everything else follows from that, and the
warnings above are the load-bearing parts of this document.

This port has not been audited. It is a from-scratch implementation of
cryptographic protocols in C, which is exactly the combination that warrants
scepticism. What verification exists is described in [PORT.md](PORT.md),
including what it does not cover -- and four of the six platforms it claims
have never been run.

To report a security issue in *upstream* tailcat, see [upstream's
SECURITY.md](https://github.com/tailscale/tailcat/blob/main/SECURITY.md). For
this port, open an issue on this repository.

## Stability

No promises about the CLI, its output, or anything else. Upstream makes none
either, and this follows upstream.

The public relays belong to Tailscale, not to this project. They are rate
limited, have no uptime guarantee, and access may be withdrawn at any time. If
you depend on this, [run your own relay](#bring-your-own-relay).

## Licence and attribution

BSD-3-Clause, matching upstream tailcat. [LICENSE](LICENSE) is upstream's,
copied unchanged, because that is what the licence asks of a derivative: a
redistribution in source form has to carry the copyright notice, the
conditions and the disclaimer along with it.

This program is a port of [tailcat](https://github.com/tailscale/tailcat),
copyright (c) 2020 Tailscale Inc & contributors, and this file follows the
structure of upstream's README. The protocols it implements -- WireGuard, DERP,
disco, STUN -- are Tailscale's and their authors'. WireGuard is a registered
trademark of Jason A. Donenfeld.

Mbed TLS is vendored under `third_party/`, under the Apache-2.0 licence.

## History

Upstream tailcat began in September 2023 as "derpcat", written on a flight, and
was open sourced in August 2026.

This port started from the observation that the whole of it -- data plane and
all -- could be made into a single file that runs anywhere, with no runtime and
nothing to install, if it were written in C for the Cosmopolitan toolchain.
Whether that was worth doing is a matter of taste. Whether it was done
correctly is a matter of evidence, and [PORT.md](PORT.md) is the evidence.
