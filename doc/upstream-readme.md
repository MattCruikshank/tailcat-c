# Walking upstream's README with our binary

Every instruction in
[upstream's README](https://github.com/tailscale/tailcat/blob/main/README.md),
typed as a reader would copy it, run against `build/cosmo/tailcat-c` and
nothing else. Thirty-one command forms plus the end-to-end examples.

The feature table in [README.md](../README.md#features) already says what is
implemented. This asks a different and harsher question: **what does a person
following upstream's documentation actually see?** A feature can be present
and still fail that test, because the flag was spelled differently, or the
output was shaped differently, or an argument was eaten by the wrong parser.

It found three bugs. Two of them were silent. All three are fixed; this
records what they were, because the way they hid is the reusable part.

The Go library section is skipped — we are a CLI, not an importable
package — as is Install, which is about packaging.


## What it found

**Three bugs, and the two quiet ones are the point.**

| | | |
|---|---|---|
| `tailcat ssh <addr> ls -l` silently dropped the `-l` | Our global `-l` flag (for `ls -l`) was parsed before the subcommand was known, so it swallowed an argument meant for the remote command. The command ran without it and nothing said so. | fixed, bug 32 |
| `tailcat ssh <addr> ls -la`, `cp -r`, `ssh <addr> sh -c ...` | Rejected outright: `unknown flag -la`. `cp -r` appears in *our own* usage document. | fixed, bug 32 |
| `--timeout=2m` meant two seconds | Upstream takes a Go duration; we took an integer through `strtoul`, which stops at the first character it does not understand. `--timeout=30s` was right by accident, which is why it survived. | fixed, bug 33 |

The `ssh`/`cp` pass-through had a comment in `src/cli/main.c` claiming those
subcommands "take the tail of argv rather than the parsed list". They did
not, and never had. The comment described an intention. Flag parsing now
stops when the subcommand turns out to be `ssh` or `cp` -- `-p` excepted,
because upstream's `-p` is its own flag too -- so the tail reaches the real
ssh and scp verbatim, which is checked by running them with a stand-in that
prints its argv.

**Two more were found before this ran at all**, by reading the argument
parser while planning the walk, and are already fixed:

- `--flag=value` was not accepted anywhere, and upstream's README is written
  almost entirely in that form. Nearly every flag example produced
  `unknown flag`.
- `parse` printed a key/value table where upstream prints JSON, so
  `tailcat parse … | jq .ServerPublic` worked against the real thing and not
  against ours. It is now byte-identical, checked by `make parse-interop`.


## The data plane

Upstream's headline example, both ends our binary:

```
$ tailcat-c serve
# relay tc301a.ipn.dev
# listening with new address: tcpGFwWCAoH1s9mkr4rk2L6QXOic0cOEIg_0J-iEiuyBuJC…

$ echo hello | tailcat-c tcpGFwWCAoH1s9mkr4rk2L6QXOic0cOEIg_0J-iEiuyBuJC…
```

and `hello` appears on the server. Works.

| Instruction | Result |
|---|---|
| `tailcat` (bare) | ✅ starts a one-shot server, as upstream does |
| `tailcat <addr>` | ✅ |
| `serve 8080,8443` | ✅ |
| `serve all` | ✅ |
| `serve exit-node` | ✅ |
| `forward <addr> 18080:8080 3306` | ✅ both mappings |
| `forward --bind=0.0.0.0 <addr> 18080:8080` | ✅ |
| `forward <addr> 3001:172.23.52.30:3001` | ✅ exit-node form |
| `browse <addr>` | ✅ |
| `socks <addr> 1080` | ✅ |
| `socks <addr> -- curl …` | ✅ |
| `socks <addr> curl …` (no `--`) | ✅ since the walk |
| `socks curl http://<tc-addr>:8081/` | ✅ the address argument is optional, and a tc-addr hostname names the server to reach |
| `socks <addr-a> …` and `<addr-b> …` through one proxy | ✅ up to four servers, dialled on demand |
| `ping --until-direct <addr>` | ✅ a pong a second until one is direct; non-zero if none is |
| `ping <addr>` | ✅ `pong in 61ms via DERP(nyc)`, upstream's format exactly. Works in both directions with the real tailcat — verified. |

One retest worth recording: upstream's `ping` first appeared to fail against
our server with `context deadline exceeded`. That was the test's fault — a
`serve` with no ports and the default 10s timeout. Given ports and 30s,
upstream pings us in 5.61ms, over a direct path. Not a gap.


## Addresses

| Instruction | Result |
|---|---|
| `parse <addr>` | ✅ **byte-identical JSON**, checked over 500 generated addresses by `make parse-interop` |
| `resolve <addr>` | ✅ byte-identical output |
| `serve --full-address` | ✅ |

`parse` prints the pre-shared key, as upstream does. That reverses an earlier
choice here; the reasoning is in `src/cli/main.c`, and it comes down to the
address having arrived as `argv`, where it is already readable by anyone on
the machine.


## Shells, files and flags

| Instruction | Result |
|---|---|
| `ssh <addr> uptime` | ✅ |
| `ssh <addr> ls -la`, `ssh <addr> sh -c …` | ✅ since bug 32 |
| `ssh -p 2222 user@<addr>` | ✅ the port reaches the ProxyCommand, the user survives |
| `cp report.pdf <addr>:` | ✅ |
| `cp -r photos/ <addr>:` | ✅ since bug 32 |
| `ls -l <addr>` | ✅ |
| `recv <dir>` | ✅ (an existing directory; both implementations refuse a missing one) |
| `--timeout=30s`, `2m`, `1h30m`, `500ms` | ✅ since bug 33 |

The `ssh` and `cp` rows were checked by putting a stand-in `ssh` and `scp` on
`$PATH` that print their argv, because "the command ran" and "the command ran
with the arguments the user typed" are different claims and bug 32 was the
difference.


## Keys

| Instruction | Result |
|---|---|
| `genkey --key=default --region=nyc` | ✅ names resolve, and to upstream's numbers — `nyc` → 301, `sfo` → 302 |
| `genkey --key=k --region=list` | ✅ |
| `genkey --list` | ✅ |
| `genkey --client --key=client-default` | ✅ prints `nodekey:…` |
| `genkey --delete --key=default` | ✅ |
| `printpub` | ✅ |
| `serve 8080` with a saved `default` | ✅ picks it up silently, as upstream documents |
| `serve --key=new 8080` | ✅ forces an ephemeral one |
| `--psk=false` | ✅ 104-byte address without a PSK; `--psk=true` and the default give 152 |
| `genkey --region=derp.example.com` | ❌ bring-your-own-relay at genkey time. Good error: `no region matching "derp.example.com"; try --region list`. `--relay` does this for `serve`. |
| `genkey --fixed-region` | ✅ measures the nearest relay once and records it in the key |

Guarding against a saved key being replaced works, and says why:
`already exists; --force to replace it (every client with the old address
loses access)`.


## Services we do not implement

These all fail cleanly and **name the feature**, which is the behaviour to
keep:

```
$ tailcat-c serve ssh
tailcat-c: the "ssh" service is not implemented here; see the feature table in README.md
```

Same for `no-auth-ssh` and `files`. `exec` is implemented now — a command per
connection, with the connection as its stdin and stdout, and the caller's key
and address in its environment.

By contrast the *flags* belonging to the remaining features report only
`unknown flag` — `--ssh-authorized-keys` and `--files`. "Unknown" is true but
less useful than "not implemented here": a reader cannot tell a typo from a
missing feature, and these are the last two places that distinction is lost.

(This paragraph named five flags when the walk was first written.
`--fixed-region`, `--until-direct` and `--skip-dns-safety-check` have since
been implemented, which is the more satisfying way for the list to get
shorter.)


## DNS names

A DNS name works anywhere an address does, if its TXT records hold
`tailcat=tc…`:

| Instruction | Result |
|---|---|
| `tailcat-c ssh example.com` | ✅ |
| `example.com 8080`, `ping`, `forward`, `socks`, `ls`, `browse`, `resolve` | ✅ |
| `parse example.com` | ❌ **on purpose** — `parse` decodes an address and never dials one, so a lookup there is a DNS query nobody asked for. Upstream's `parse` does not resolve either. |
| `--skip-dns-safety-check` | ✅ before or after the subcommand |

`ssh` to a DNS-named destination probes it first, as upstream's does: a
fresh tunnel key and a throwaway SSH key, which is what a stranger who read
the public record would have. If that gets in, connecting is refused.

One rule here is worth reading the source for, because it is not obvious and
it is not ours: **an argument with a valid tailcat address among its DNS
labels is refused rather than looked up.** `tcABC….example.com`, or an
address pasted with a trailing dot, would otherwise put a bearer credential
into a cleartext DNS query — to a resolver the user does not control, and
onward from there. The typo is easy and the disclosure cannot be undone.
Upstream refuses the same case; see `src/net/dnsaddr.c`.


## Cosmetic differences

Worth knowing if anything greps our output:

| | upstream | tailcat-c |
|---|---|---|
| startup | `# 🐈 Server listening with new address:` | `# listening with new address:` |
| relay choice | `# Selected bootstrap relay region 302, San Francisco` | `# relay tc301a.ipn.dev` |

Ours is ASCII throughout, deliberately: the same binary starts on six
operating systems and they do not agree about what a terminal does with the
rest of Unicode.


## What is missing, in one place

Scattered through the tables above; collected here because "what does this
not do" is a question worth being able to answer without reading a
walkthrough. PLAN.md 6.2 has what each would cost.

| Missing | Upstream spelling | Nearest thing here |
|---|---|---|
| a *self-hosted* relay in a saved key | `genkey --region=derp.example.com` | `serve --relay host` |
| a third address from the pipe | `ssh -p 10.0.0.1:22 <addr>` | `forward <addr> 2222:10.0.0.1:22` |
| shell, forced command, file server | `serve ssh`, `no-auth-ssh`, `exec`, `files` | `recv`, `ls` |

The four `serve` services are refusals rather than omissions — PLAN 5.4 and
5.5 record the reasoning, and it is mostly that a drop box which can run
commands is not a drop box. Everything else on this list is simply not
written yet, and none of it is large.

One thing the walk changed rather than recorded: `-p 10.0.0.1:22` and the
pipe form's port argument used to accept that string and connect to port
10. They now refuse it and name `forward`, which is the command that does
work. A documented gap is fine; a silent wrong connection is not.


## Reproducing this

There is no script. The walk was done by hand because the judgement — "works",
"differs", "is a bug" — is the part that matters and is not something a
script should be deciding. What *is* automated is the part with a right
answer: `make parse-interop` pins `parse`'s output against the real binary,
and the twenty-four live stages in level 1 cover the data plane against a
real Go tailcat in both directions.
