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

    tailcat-c serve

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

Copy files, using the system `scp`:

    tailcat-c cp report.pdf <tc-addr>:
    tailcat-c cp -r photos/ <tc-addr>:

List what a server offers:

    tailcat-c ls <tc-addr>
    tailcat-c ls -l <tc-addr>:photos


## Shells and proxies

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
    tailcat-c socks <tc-addr> -- curl https://example.com

In a SOCKS request, the hostname `server.tailcat` means the server itself.
Any other name is a destination to reach *through* it, which needs
`serve exit-node` at the far end.


## Identities

Without a saved key a server's address changes on every restart, which makes
it useless in a script or a service file.

    tailcat-c genkey --key default
    tailcat-c serve --key default
    tailcat-c printpub --key default

Restrict who may connect, by client node key:

    tailcat-c serve --allow nodekey:abc123...,nodekey:def456...


## Inspecting

    tailcat-c parse <tc-addr>       # describe an address
    tailcat-c resolve <tc-addr>     # embed the relay, for offline use
    tailcat-c ping <tc-addr>        # time the round trip
    tailcat-c netcheck              # UDP, NAT type and relay latency
    tailcat-c version


## Flags

    --key NAME          saved identity to use, or "new" for an ephemeral one
    --allow KEYS        comma-separated client nodekey: list, or "none"
    --relay HOST        serve through this relay instead of choosing one
    --full-address      embed the relay in the address, so clients need no map
    --bind ADDR         listen address for forward and socks (default 127.0.0.1)
    --open-browser      for forward: open a browser at the local listener
    --timeout SEC       give up after SEC seconds (0 = never)
    --derpmap-url URL   where to fetch the relay list
    --insecure          skip TLS verification of the relay
    -v                  explain what is happening
    -p PORT             port for the pipe and ssh forms


## What to be careful about

**The address is a bearer credential.** Anyone who has it can connect, it
cannot be narrowed afterwards, and it is exactly as secret as the least
careful place it has been pasted. `--allow` restricts by client key and is off
by default.

**`serve exit-node` reaches everything this machine can**, including loopback
services and a cloud metadata endpoint. Use `--allow` with it.

**`ssh` disables host key checking**, because the destination it gives ssh is
a hash of the address rather than a host anyone holds a key for -- and the
address already authenticated the server.


## Where the rest is

Source, the full feature comparison with upstream tailcat, and the
verification notes: https://github.com/MattCruikshank/tailcat-c
