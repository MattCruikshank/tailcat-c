#!/bin/sh
# One SOCKS proxy, several tailcat servers, selected by the request.
#
# Upstream lets a tailcat address stand in for a destination hostname:
#
#     tailcat socks curl http://<tc-addr>:8081/
#
# which is why its `socks` needs no address of its own, and why one proxy can
# front more than one server. This checks both halves of that, because either
# could pass alone and mean nothing:
#
#   - a proxy started with *no* address dials a server named in a request,
#     bringing the tunnel up on demand;
#   - two requests naming two different servers reach two different servers,
#     and the answers do not come from the same place.
#
# The second is the one worth being careful about. If both connections went to
# whichever tunnel happened to exist, the test would still see two replies --
# so the two services answer with their own names and the check is that each
# reply came from the right one.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
PORT_A="${PORT_A:-18101}"
PORT_B="${PORT_B:-18102}"
SOCKS_PORT="${SOCKS_PORT:-18103}"

WORK=$(mktemp -d)
cleanup() {
	for v in SVC_A SVC_B SRV_A SRV_B PROXY; do
		eval "pid=\${$v:-}"
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null || true
		fi
	done
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Two services that answer with their own name, so a reply identifies which
# server carried it.
service() {
	cat > "$WORK/svc$1.py" <<SVCEOF
import socket, threading
def serve(c):
    got = b""
    while True:
        b = c.recv(4096)
        if not b:
            break
        got += b
    c.sendall(b"server$1-said: " + got)
    c.shutdown(socket.SHUT_WR)
    c.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $2))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
SVCEOF
	python3 "$WORK/svc$1.py" > /dev/null 2>&1 < /dev/null &
}

address_of() {
	i=0
	while [ $i -lt 40 ]; do
		a=$(sed -n 's/.*: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$1" | head -1)
		if [ -n "$a" ]; then
			printf '%s' "$a"
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	return 1
}

echo "starting two local services"
service A "$PORT_A"
SVC_A=$!
service B "$PORT_B"
SVC_B=$!
sleep 1

echo "starting two tailcat servers, one per service"
"$CLI" serve "$PORT_A" > /dev/null 2> "$WORK/a.log" &
SRV_A=$!
"$CLI" serve "$PORT_B" > /dev/null 2> "$WORK/b.log" &
SRV_B=$!

ADDR_A=$(address_of "$WORK/a.log") || {
	echo "live-socks-many: server A never printed an address" >&2
	cat "$WORK/a.log" >&2
	exit 1
}
ADDR_B=$(address_of "$WORK/b.log") || {
	echo "live-socks-many: server B never printed an address" >&2
	cat "$WORK/b.log" >&2
	exit 1
}
if [ "$ADDR_A" = "$ADDR_B" ]; then
	echo "live-socks-many: the two servers minted the same address" >&2
	exit 1
fi

echo
echo "\$ tailcat-c socks $SOCKS_PORT          # no address at all"
"$CLI" -v socks "$SOCKS_PORT" > /dev/null 2> "$WORK/proxy.log" &
PROXY=$!
sleep 3

ask() {
	printf '%s\n' "$2" |
		timeout 90 python3 scripts/socks-client.py --host "$1" \
			"$SOCKS_PORT" "$3" 2>> "$WORK/client.err" || true
}

R_A=$(ask "$ADDR_A" "first" "$PORT_A")
echo "    asking for server A's address: $R_A"
R_B=$(ask "$ADDR_B" "second" "$PORT_B")
echo "    asking for server B's address: $R_B"

if ! printf '%s' "$R_A" | grep -qF "serverA-said: first"; then
	echo >&2
	echo "live-socks-many: the request naming server A did not reach it." >&2
	sed 's/^/    /' "$WORK/client.err" >&2
	cat "$WORK/proxy.log" >&2
	exit 1
fi
if ! printf '%s' "$R_B" | grep -qF "serverB-said: second"; then
	echo >&2
	echo "live-socks-many: the request naming server B did not reach it." >&2
	echo "  (a proxy that sent everything down one tunnel would fail here," >&2
	echo "   which is the point of two services with two names)" >&2
	sed 's/^/    /' "$WORK/client.err" >&2
	cat "$WORK/proxy.log" >&2
	exit 1
fi

echo
echo "ok   live-socks-many         one proxy, started with no address,"
echo "                              dialled two different servers named"
echo "                              in two requests, and each reply came"
echo "                              back from the right one"
