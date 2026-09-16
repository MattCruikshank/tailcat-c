#!/bin/sh
# `forward` and `socks` against a real Go tailcat server.
#
# The reverse of live-serve-ports: there a Go client reached a local service
# through our server; here a local client reaches a service through our
# *client*, with the upstream Go binary serving. Between the two, both ends of
# the proxy have now been driven by something that is not ours.
#
# The mapping direction is the thing worth proving. `18080:PORT` must listen
# on 18080 and reach PORT -- reversed, it would still connect and would do
# entirely the wrong thing.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"
SVCPORT="${SVCPORT:-18082}"
LOCALPORT="${LOCALPORT:-18083}"
SOCKSPORT="${SOCKSPORT:-18084}"

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

WORK=$(mktemp -d)
cleanup() {
	for v in SVC_PID SRV_PID FWD_PID SOCKS_PID; do
		eval "pid=\${$v:-}"
		[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	done
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# The service echoes what it was sent, after reading to EOF, so a half close
# that does not cross the tunnel shows up as a hang rather than a subtlety.
cat > "$WORK/svc.py" <<SVCEOF
import socket, threading
def serve(c):
    got = b""
    while True:
        b = c.recv(4096)
        if not b:
            break
        got += b
    c.sendall(b"service-said: " + got)
    c.shutdown(socket.SHUT_WR)
    c.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $SVCPORT))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
SVCEOF

echo "starting a local service on 127.0.0.1:$SVCPORT"
python3 "$WORK/svc.py" >/dev/null 2>&1 </dev/null &
SVC_PID=$!
sleep 1

echo "starting the real Go tailcat serving $SVCPORT"
"$UPSTREAM" serve "$SVCPORT" > "$WORK/srv.log" 2>&1 &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$WORK/srv.log" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-forward: the Go server never printed an address:" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi

# ---- forward -------------------------------------------------------------
echo
echo "\$ tailcat-c forward <addr> $LOCALPORT:$SVCPORT"
"$CLI" -v forward "$ADDR" "$LOCALPORT:$SVCPORT" >/dev/null 2>"$WORK/fwd.log" &
FWD_PID=$!

i=0
while [ $i -lt 40 ]; do
	grep -q 'tunnel up' "$WORK/fwd.log" && break
	sleep 1
	i=$((i + 1))
done
grep -E '^# 127' "$WORK/fwd.log" | sed 's/^/    /'

MSG="through the forward"
RESP=$(printf '%s\n' "$MSG" | timeout 40 python3 -c '
import socket,sys
s=socket.create_connection(("127.0.0.1", '"$LOCALPORT"'), timeout=30)
s.sendall(sys.stdin.buffer.read()); s.shutdown(socket.SHUT_WR)
out=b""
while True:
    b=s.recv(4096)
    if not b: break
    out+=b
sys.stdout.write(out.decode("utf-8","replace"))
' 2>/dev/null || true)

echo "    got: $RESP"
if ! printf '%s' "$RESP" | grep -qF "service-said: $MSG"; then
	echo >&2
	echo "live-forward: the forwarded reply did not come back." >&2
	echo "--- tailcat-c forward log ---" >&2
	cat "$WORK/fwd.log" >&2
	exit 1
fi
kill "$FWD_PID" 2>/dev/null || true
FWD_PID=""

# ---- socks ---------------------------------------------------------------
echo
echo "\$ tailcat-c socks <addr> $SOCKSPORT"
"$CLI" -v socks "$ADDR" "$SOCKSPORT" >/dev/null 2>"$WORK/socks.log" &
SOCKS_PID=$!

i=0
while [ $i -lt 40 ]; do
	grep -q 'tunnel up' "$WORK/socks.log" && break
	sleep 1
	i=$((i + 1))
done
grep -E '^# SOCKS5' "$WORK/socks.log" | sed 's/^/    /'

MSG2="through the socks proxy"
RESP2=$(printf '%s\n' "$MSG2" | timeout 40 python3 -c '
import socket,sys,struct
s=socket.create_connection(("127.0.0.1", '"$SOCKSPORT"'), timeout=30)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00", "greeting refused"
# CONNECT to example.invalid:PORT -- the host is ignored, only the port is
# used, because there is exactly one place this proxy can go.
host=b"example.invalid"
s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host +
          struct.pack("!H", '"$SVCPORT"'))
rep=s.recv(10)
assert rep[0:2] == b"\x05\x00", "connect refused: %r" % rep
s.sendall(sys.stdin.buffer.read()); s.shutdown(socket.SHUT_WR)
out=b""
while True:
    b=s.recv(4096)
    if not b: break
    out+=b
sys.stdout.write(out.decode("utf-8","replace"))
' 2>"$WORK/socks-client.err" || true)

echo "    got: $RESP2"
if ! printf '%s' "$RESP2" | grep -qF "service-said: $MSG2"; then
	echo >&2
	echo "live-forward: the SOCKS reply did not come back." >&2
	sed 's/^/    /' "$WORK/socks-client.err" >&2
	echo "--- tailcat-c socks log ---" >&2
	cat "$WORK/socks.log" >&2
	exit 1
fi

echo
echo "ok   live-forward             forward and socks both carried a local"
echo "                              client to a real Go tailcat server"
