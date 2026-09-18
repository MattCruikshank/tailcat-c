# SPDX-License-Identifier: BSD-3-Clause
#
# A SOCKS5 client for the live tests.
#
# Two modes, because two things need proving:
#
#   socks-client.py <proxy-port> <dest-port>
#       connect to the proxy given on the command line.
#
#   socks-client.py --from-env <dest-port>
#       find the proxy in $all_proxy, the way curl and friends do. This is
#       what `tailcat-c socks <addr> -- <cmd>` has to set for a child that
#       knows nothing about tailcat.
#
# The destination host is deliberately a name that does not resolve: the proxy
# reaches exactly one server and ignores it, so a client that only works
# because the name resolved would be proving the wrong thing.
import os
import socket
import struct
import sys


def proxy_from_env():
    p = os.environ.get("all_proxy") or os.environ.get("ALL_PROXY") or ""
    if not p.startswith("socks5"):
        sys.stderr.write("all_proxy is not a socks5 URL: %r\n" % p)
        sys.exit(3)
    hostport = p.split("//", 1)[1].rstrip("/")
    host, _, port = hostport.rpartition(":")
    return host, int(port)


def main():
    # --host NAME asks for a specific destination hostname rather than the
    # server itself. A tailcat address is a legal one: upstream lets an
    # address stand in for a hostname so that one proxy can front several
    # servers, and `socks` then needs no address of its own.
    argv = sys.argv[1:]
    want_host = None
    if argv and argv[0] == "--host":
        want_host = argv[1].encode()
        argv = argv[2:]

    if argv[0] == "--from-env":
        host, port = proxy_from_env()
        dest_port = int(argv[1])
    else:
        host, port = "127.0.0.1", int(argv[0])
        dest_port = int(argv[1])

    s = socket.create_connection((host, port), timeout=30)
    s.settimeout(30)

    # Greeting: version 5, one method, "no authentication".
    s.sendall(b"\x05\x01\x00")
    got = s.recv(2)
    if got != b"\x05\x00":
        sys.stderr.write("greeting refused: %r\n" % got)
        sys.exit(4)

    # Upstream's name for the far end of the tunnel. Anything else is a
    # destination to reach *through* the server, which needs it to be an exit
    # node -- so a proxy client that wants the server itself has to say so.
    name = want_host if want_host is not None else b"server.tailcat"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name +
              struct.pack("!H", dest_port))
    rep = s.recv(10)
    if rep[0:2] != b"\x05\x00":
        sys.stderr.write("connect refused: %r\n" % rep)
        sys.exit(5)

    payload = sys.stdin.buffer.read()
    s.sendall(payload)
    s.shutdown(socket.SHUT_WR)

    out = b""
    while True:
        b = s.recv(4096)
        if not b:
            break
        out += b
    sys.stdout.write(out.decode("utf-8", "replace"))


main()
