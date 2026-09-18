# Walking upstream's README with our binary

Every instruction in
[upstream's README](https://github.com/tailscale/tailcat/blob/main/README.md),
typed as a reader would copy it, run against `build/cosmo/tailcat-c` and
nothing else.

The feature table in [README.md](../README.md#features) already says what is
implemented. This asks a different and harsher question: **what does a person
following upstream's documentation actually see?** A feature can be present
and still fail that test, because the flag was spelled differently, or the
argument was eaten by the wrong parser, or the thing it talks to is on the
other side of an interop gap.

The Go library section is skipped — we are a CLI, not an importable
package — as is Install, which is about packaging.


## Two walks

**The first walk** covered thirty-one command forms and found three bugs, two
of them silent. They are recorded below, because the way they hid is the
reusable part.

**The second walk** happened because this document had stopped being one. Four
`serve` services and two file modes were implemented after the first walk, and
their rows were added here *by hand, from implementation knowledge* — real
evidence, out of unit and live tests, but not the evidence this document exists
to collect. The prompt was a question worth asking of any document like it:
*did we actually do that?* The rows said ✅; nobody had typed them.

The second walk found **two more bugs and eleven differences**, and the first
bug is the one that justifies the whole exercise: an interop failure against
the real Go binary, in a direction nothing here tests.


## What the second walk found

**Bug 43 — the real `tailcat ls` cannot talk to our file server or drop box.**

```
$ tailcat ls <our-serve-files-address>
SSH handshake: ssh: handshake failed: ssh: unable to authenticate,
attempted methods [none], no supported methods remain
```

That is the reference implementation refusing us, reproduced with a freshly
built `upstream-tailcat`. Our SSH server sets `any_key_authenticates`, which
demands the *publickey* method with a valid signature and rejects `none`.
Upstream's server sets `NoClientAuthHandler` whenever there are no authorized
keys — so `recv`, `serve files` and `no-auth-ssh` all accept `none` — and
upstream's `ls` client sets no `Auth` field at all, so `none` is the only
method it ever offers.

Our own `ls` fails the same way and for the same reason. `main.c` says
`opts.user_seed = NULL; /* 'none' only, as upstream's ls offers */`. That
comment is correct about upstream's *client* and was never true of our
*server*.

It is invisible to the live suite because of how the coverage happens to sit:

| test | direction | why it passes |
|---|---|---|
| `live-ls` | our `ls` → **their** server | their server accepts `none` |
| `live-recv-serve` | `scp` → our server | `scp` always offers a key |
| `live-dropbox` | `scp`/`sftp` → our server | same |
| — | **their `ls` → our server** | **not covered** |

Two tests each cover half of a square, and the missing corner is the broken
one. Demanding a key that is then not checked is also theatre: the server
accepts *any* key, so requiring one adds nothing and costs interop.

**Bug 44 — `cp -r` is broken.**

```
$ tailcat-c cp -r ./tree <addr>:
/usr/bin/scp: stat local "-r": No such file or directory
```

`cp` emits `--` and then every argument, so a flag in front of the operands
lands after the separator and `scp` reads it as a filename. The first walk
found and fixed this shape for `ssh` (bug 32), and the `serve ssh` work fixed
`ssh`'s argument scanning again (bug 40); `cp` was never given either
treatment. `cp -r` appears in upstream's README **and in our own usage
document**, which makes this the second time this project has shipped a broken
command that its own documentation recommends.


## Differences the second walk found

None of these are bugs. They are things a reader following upstream's
documentation would find do not work here.

| Upstream's instruction | Here |
|---|---|
| `serve --ssh-authorized-keys=a,b ssh` | ❌ comma-separated sources: we read the whole string as one path. Ours is repeatable instead — `--ssh-authorized-keys a --ssh-authorized-keys b` |
| `serve files` (bare) | ❌ upstream serves the current directory read-only; we refuse and ask for `--files` |
| `serve --files=/pub:rw` (no service word) | ❌ upstream: "giving `--files` implies the 'files' service"; we refuse |
| a forced command sees `$SSH_ORIGINAL_COMMAND` | ❌ not set; we log the client's request and drop it |
| `ssh`/`no-auth-ssh` also serve SFTP | ❌ we refuse the `sftp` subsystem on a shell server |
| `--serve=<list>` as a root flag | ❌ missing; only the `serve` subcommand |
| `--json` (`{"listenAddr": …}` on stdout) | ❌ missing |
| `--listen` for `socks` | ⚠️ we call it `--bind`, which upstream uses for `forward` |
| `genkey --embed-derp-map` | ❌ missing |
| `TAILCAT_DERPMAP_URL` environment variable | ❌ not read; `--derpmap-url` works |
| `genkey --region=list` | ⚠️ works, but we require `--key` first |

Flags, counted: upstream has 24 and so do we, and they are not the same 24. We
lack `embed-derp-map`, `json`, `listen` and `serve`; we add `help`,
`insecure`, `no-psk` (our older spelling of `--psk=false`) and `relay`.

One thing that looks like a difference and is not: upstream's README writes
`--ssh-authorized-keys=~/.ssh/authorized_keys`, and a shell does not expand
`~` after an `=`. Upstream's own usage text writes `"$HOME/.ssh/..."`
instead. The literal tilde fails for upstream too.


## What the second walk confirmed

| Instruction | Result |
|---|---|
| `serve --ssh-authorized-keys=<file> ssh` + `ssh <addr> ls -la` | ✅ a real directory listing came back |
| `serve no-auth-ssh -- <cmd>` | ✅ the forced command replaced the client's |
| `recv <dir>` + `cp report.pdf <addr>:` | ✅ |
| `serve --files=<dir>:wo+ files`, `recv --accept-dirs` | ✅ (see `make live-dropbox-tree`) |
| `serve ssh` without `--ssh-authorized-keys` fails | ✅ and names the alternative |
| `--verbose` before the subcommand | ✅ |
| `genkey --region=list` | ✅ names and IDs match upstream's |
| `--psk=false` | ✅ |


## What the first walk found

**Three bugs, and the two quiet ones are the point.**

| | | |
|---|---|---|
| `tailcat ssh <addr> ls -l` silently dropped the `-l` | Our global `-l` flag (for `ls -l`) was parsed before the subcommand was known, so it swallowed an argument meant for the remote command. The command ran without it and nothing said so. | fixed, bug 32 |
| `tailcat ssh <addr> ls -la`, `cp -r`, `ssh <addr> sh -c ...` | Rejected outright: `unknown flag -la`. `cp -r` appears in *our own* usage document. | fixed for `ssh`, bug 32 — but see bug 44, which is `cp -r` still broken |
| `--timeout=2m` meant two seconds | Upstream takes a Go duration; we took an integer through `strtoul`, which stops at the first character it does not understand. `--timeout=30s` was right by accident, which is why it survived. | fixed, bug 33 |


## The data plane, addresses, keys and DNS

Walked first, unchanged since, and covered continuously by the live suite.

| Instruction | Result |
|---|---|
| `tailcat` (bare) → address, waits, unblocks on `echo hello \| tailcat <addr>` | ✅ |
| `serve 8080,8443`, `serve all` | ✅ |
| `tailcat <addr> 8080` | ✅ |
| `forward <addr> 18080:8080 3306` | ✅ |
| a local port of `0` asks the OS for a free one | ✅ |
| `serve exit-node` + `forward <addr> 3001:172.23.52.30:3001` | ✅ |
| `forward --bind=0.0.0.0 <addr> 18080:8080` | ✅ |
| `browse <addr>`, `forward --open-browser <addr> 0:80` | ✅ |
| `serve exec -- /usr/bin/fortune`, `$TAILCAT_PEER_KEY`, `$TAILCAT_REMOTE_ADDR` | ✅ |
| `ping --until-direct <addr>`, and the `via DERP(…)` / `via <ip:port>` line | ✅ |
| `socks <addr> curl …`, and a tc-address as a URL hostname | ✅ |
| `parse <addr>` JSON | ✅ byte-identical; pinned by `make parse-interop` |
| `resolve <addr>`, and parsing the result | ✅ |
| `serve --full-address` | ✅ |
| `genkey --key=default --region=nyc`, `--fixed-region`, `--client`, `--list`, `--delete` | ✅ |
| `default` is magic: plain `serve` picks it up, `--key=new` forces ephemeral | ✅ and the startup line says which |
| DNS TXT: `tailcat example.com 8080`, `ssh`, `ping` | ✅ |
| `ssh` probes a DNS-named server and refuses an open one | ✅ |
| `--skip-dns-safety-check` | ✅ |
| `serve --allow=nodekey:… 22` | ✅ |
| `genkey --key=default --region=derp.example.com` (self-hosted relay) | ❌ not implemented |


## What is missing, in one place

| Missing | Upstream spelling | Nearest thing here |
|---|---|---|
| a *self-hosted* relay in a saved key | `genkey --region=derp.example.com` | `serve --relay host` |
| a third address from the pipe | `ssh -p 10.0.0.1:22 <addr>` | `forward <addr> 2222:10.0.0.1:22` |
| SFTP on a shell server | `serve ssh` also answers `sftp` | `serve files`, separately |
| a service list as a flag | `--serve=22,80` | the `serve` subcommand |
| machine-readable startup | `--json` | parse the `# listening` line |
| the DERP map from the environment | `TAILCAT_DERPMAP_URL` | `--derpmap-url` |
| embedding relay nodes at genkey time | `genkey --embed-derp-map` | `serve --full-address`, at serve time |


## Cosmetic differences

We print `# listening with new address:` where upstream prints `# 🐈 Server
listening with new address:`, and `# relay region 301 (nyc)` where upstream
prints `# Selected bootstrap relay region 301, New York City`. Both carry the
same facts in the same order. Dropping the emoji is deliberate: this binary
writes to Windows consoles that do not reliably have a font for it.


## Reproducing this

There is no script. The walk is done by hand because the judgement — "works",
"differs", "is a bug" — is the part that matters and is not something a
script should be deciding. What *is* automated is the part with a right
answer: `make parse-interop` pins `parse`'s output against the real binary,
and the live stages in level 1 cover the data plane against a real Go tailcat
in both directions.

The second walk's decisive step is worth keeping as a recipe, because it is
the one no amount of testing against ourselves would have reached: **build the
real binary and point it at ours.**

```sh
(cd upstream-tailcat && go build -o ../build/tailcat-upstream ./cmd/tailcat)
./build/cosmo/tailcat-c serve --files=/tmp/pub files &   # ours
./build/tailcat-upstream ls <addr>                        # theirs
```
