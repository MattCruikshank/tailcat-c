# tailcat-c

Netcat over WireGuard, through Tailscale's DERP relays. One address is all
either side needs: no account, no daemon, no configuration file.

This is what `tailcat-c readme` prints. README.md in the source tree is a
different document -- an engineering log about how this was built and verified
-- and is not what you want at a terminal.


## The idea

A server prints an address. Anyone holding that address can reach it. The
address contains a public key, a pre-shared key and a relay, so possession of
it is what grants access -- treat it as a password.

    $ tailcat-c serve
    # listening with new address: tcpGFwWCDMihnYWAeovm...

    $ echo hello | tailcat-c tcpGFwWCDMihnYWAeovm...

Traffic starts on a relay, which never sees anything but WireGuard-encrypted
packets, and moves to a direct peer-to-peer path when one can be proved.


## Sending and receiving

Pipe stdin to a server and its output back:

    tailcat-c <tc-addr> [port]

Serve one connection and write it to stdout, then exit:

    tailcat-c
    tailcat-c serve

Run a command for each connection instead, with the connection as its stdin
and stdout, like inetd:

    tailcat-c serve exec -- /usr/bin/fortune

The command gets the caller's node key in $TAILCAT_PEER_KEY and its address
in $TAILCAT_REMOTE_ADDR.

Serve local ports, to many clients at once:

    tailcat-c serve 22,80,8000-8999
    tailcat-c serve all
    tailcat-c serve exit-node,22      # also forward anywhere this machine can reach

`exit-node` has to be asked for by name because it makes this machine a proxy
for everything it can reach, including its own loopback services.


## Files

Receive files into a directory, as a write-only drop box:

    tailcat-c recv ~/inbox

The sender chooses nothing. Names are the server's, nothing is overwritten,
the directory cannot be listed and nothing can be read back.

Share a directory instead, for reading:

    tailcat-c serve --files ~/public files

Or for reading and writing:

    tailcat-c serve --files ~/shared:rw files

Read-only is the default, because handing out write access by accident is not
recoverable. Everything is confined to that directory: `..` cannot climb out
of it and a symlink is refused rather than followed, so a link inside the
directory pointing anywhere else is not served. `recv <dir>` is the same
command with the third mode, `--files <dir>:wo files`.

Copy files, using the system `scp`:

    tailcat-c cp report.pdf <tc-addr>:
    tailcat-c cp -r photos/ <tc-addr>:

List what a server offers:

    tailcat-c ls <tc-addr>
    tailcat-c ls -l <tc-addr>:photos


## Shells and proxies

## A shell

Serve one, to named keys:

    tailcat-c serve --ssh-authorized-keys ~/.ssh/authorized_keys ssh
    tailcat-c serve --ssh-authorized-keys "ssh-ed25519 AAAAC3..." ssh
    tailcat-c serve --ssh-authorized-keys alice@github ssh

The three forms are a file, a literal key, and a GitHub account -- the last
fetches `https://github.com/alice.keys`, says so before it does, and refuses
to start if it cannot. Only ed25519 keys can be verified here; others in a
file are skipped, and a file with none left is an error rather than a server
nobody can log into.

Key options are refused, not ignored. A line like `command="/usr/bin/backup"
ssh-ed25519 AAAA...` restricts that key, and reading the key while dropping
the restriction would grant more than the file says.

To run one fixed command instead of a shell:

    tailcat-c serve --ssh-authorized-keys ~/.ssh/authorized_keys ssh -- \
        /usr/bin/backup

Or serve a shell to anyone holding the address:

    tailcat-c serve no-auth-ssh

**That last one has no client authentication at all.** Anyone with the
address can run commands as the user who started it, so the address is a
password -- and unlike a password it is printed to the terminal and pasted
into chat windows. `serve ssh` asks for a key as well, and `--allow` narrows
which tunnels may connect in either case.

Sessions get a real terminal where the platform has one. On Windows there are
no pseudo-terminals, so they run on pipes; clients print "PTY allocation
request failed" and carry on, which is what `ssh -T` does deliberately. The
server says which it is at startup.

Run a command on a server, using the system `ssh`:

    tailcat-c ssh <tc-addr> uptime
    tailcat-c ssh -p 2222 user@<tc-addr>

Forward a local port through the tunnel:

    tailcat-c forward <tc-addr> 8080
    tailcat-c forward <tc-addr> 18080:80
    tailcat-c forward <tc-addr> 13306:192.168.1.10:3306   # via an exit node

Open a browser on a web server at the far end. A free local port is chosen,
forwarded to the server's port 80, and a browser is pointed at it:

    tailcat-c browse <tc-addr>
    tailcat-c forward --open-browser <tc-addr> 0:8080     # any other port

$BROWSER is honoured if it is set: a colon-separated list, each entry a
command with optional arguments and an optional %s where the URL goes.
Otherwise it is xdg-open, open, or the Windows default handler. On a headless
machine or over ssh, the URL is printed instead of guessed at.

A SOCKS5 proxy, optionally running a command with `all_proxy` set:

    tailcat-c socks <tc-addr> 1080
    tailcat-c socks <tc-addr> curl https://example.com
    tailcat-c socks curl http://<tc-addr>:8081/   # the address may be omitted

A tailcat address used as a hostname names the server to reach, so one proxy
can front several of them and needs no address of its own.
    tailcat-c socks <tc-addr> 1080 -- curl https://example.com

The argument after the address is the listening port if it reads as one and
the start of a command if it does not. `--` is only needed for a command
whose name is a number.

In a SOCKS request, the hostname `server.tailcat` means the server itself.
Any other name is a destination to reach *through* it, which needs
`serve exit-node` at the far end.


## Identities

Without a saved key a server's address changes on every restart, which makes
it useless in a script or a service file.

    tailcat-c genkey --key default
    tailcat-c genkey --key default --fixed-region   # pin the nearest relay
    tailcat-c serve --key default
    tailcat-c printpub --key default

Restrict who may connect, by client node key:

    tailcat-c serve --allow nodekey:abc123...,nodekey:def456...


## Names instead of addresses

If a DNS name has a TXT record holding `tailcat=<address>`, it works anywhere
an address does:

    my-server.example.com.  300  IN  TXT  "tailcat=tcGFwWCDMihnYWAeovm..."

    tailcat-c ssh my-server.example.com
    tailcat-c my-server.example.com 8080

**A TXT record is public and an address is a password**, so a server named
in DNS has to check its clients some other way -- `serve --allow` is the one
here. `ssh` checks for you: before connecting to a DNS-named server it tries
to log in the way a stranger would, and refuses if that works.
`--skip-dns-safety-check` turns that off.

An argument with an address inside it is refused rather than looked up, so a
mistyped paste cannot send your address to a DNS server.


## Inspecting

    tailcat-c parse <tc-addr>       # describe an address
    tailcat-c resolve <tc-addr>     # embed the relay, for offline use
    tailcat-c ping <tc-addr>                  # time the round trip
    tailcat-c ping --until-direct <tc-addr>   # and wait for a direct path

Each pong says which path answered, a relay or a peer-to-peer address:

    pong in 61ms via DERP(nyc)
    pong in 2ms via 203.0.113.7:41641

`--until-direct` keeps going until one is direct, and exits non-zero if none
is before `--timeout` (ten seconds by default), so a script can use it to
check that NAT traversal works.
    tailcat-c netcheck              # UDP, NAT type and relay latency
    tailcat-c version


## Flags

    --key NAME          saved identity to use, or "new" for an ephemeral one
    --allow KEYS        comma-separated client nodekey: list, or "none"
    --files DIR[:MODE]  directory for `serve files`; MODE is ro, rw or wo
    --ssh-authorized-keys SPEC
                        for `serve ssh`: a file, a literal key, or
                        user@github. May be given more than once.
    --relay HOST        serve through this relay instead of choosing one
    --full-address      embed the relay in the address, so clients need no map
    --bind ADDR         listen address for forward and socks (default 127.0.0.1)
    --open-browser      for forward: open a browser at the local listener
    --timeout DUR       give up after DUR: seconds, or 30s, 2m, 1h30m
                        (0 = never)
    --derpmap-url URL   where to fetch the relay list
    --insecure          skip TLS verification of the relay
    -v                  explain what is happening
    -p PORT             port for the pipe and ssh forms

Flags take either spelling: --key default or --key=default.

After `ssh` and `cp`, everything is handed to the real ssh and scp, so their
flags are theirs: `tailcat-c ssh <tc-addr> ls -la` and `tailcat-c cp -r dir/
<tc-addr>:` do what they look like. The exception is -p, which names a port
on the tailcat server.


## What to be careful about

**The address is a bearer credential.** Anyone who has it can connect, it
cannot be narrowed afterwards, and it is exactly as secret as the least
careful place it has been pasted. `--allow` restricts by client key and is off
by default.

**`serve no-auth-ssh` is a shell for anyone holding the address.** It is the
only service here where the address alone is enough to run commands: every
other one has something narrower behind it -- a directory, a fixed command, a
set of ports. Prefer `serve ssh` with a key list, and `--allow` on top.

**`serve exit-node` reaches everything this machine can**, including loopback
services and a cloud metadata endpoint. Use `--allow` with it.

**`ssh` disables host key checking**, because the destination it gives ssh is
a hash of the address rather than a host anyone holds a key for -- and the
address already authenticated the server.


## Where the rest is

Source, the full feature comparison with upstream tailcat, and the
verification notes: https://github.com/MattCruikshank/tailcat-c
