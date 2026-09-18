#!/bin/sh
# A client reaching a third machine through a tailcat-c exit node.
#
# The unit tests prove the mux keeps flows apart and that exit-node mode is
# off unless asked for. What they cannot prove is that the two ends agree:
# that the client wraps an IPv4 destination into the NAT64 prefix, that the
# server unwraps it, that the destination survives as the connection's local
# address across a real WireGuard session, and that a server which was *not*
# told to be an exit node refuses.
#
# The "third machine" is a service on 127.0.0.1 that the server reaches by an
# address the client names -- which is precisely the thing an exit node does
# and precisely the thing an ordinary `serve` will not do.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
PORT="${PORT:-18087}"

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${SVC_PID:-}" ] && kill "$SVC_PID" 2>/dev/null || true
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/svc.py" <<'SVCEOF'
import socket, sys, threading
def serve(c):
    c.recv(65536)
    c.sendall(b"reached the third machine\n")
    c.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
SVCEOF

python3 "$WORK/svc.py" "$PORT" &
SVC_PID=$!
sleep 1

start_server() {
	"$CLI" -v serve "$@" > /dev/null 2> "$WORK/srv.log" &
	SRV_PID=$!
	ADDR=""
	i=0
	while [ $i -lt 40 ]; do
		ADDR=$(sed -n 's/.*\(tc[A-Za-z0-9_-]\{40,\}\).*/\1/p' "$WORK/srv.log" |
			head -1)
		[ -n "$ADDR" ] && break
		sleep 1
		i=$((i + 1))
	done
	if [ -z "$ADDR" ]; then
		echo "FAIL live-exitnode: the server never printed an address" >&2
		sed -n '1,30p' "$WORK/srv.log" >&2
		exit 1
	fi
}

RC=0

# ---- with exit-node on ---------------------------------------------------
echo "--- serve exit-node ---"
start_server exit-node

if ! grep -q 'acting as an exit node' "$WORK/srv.log"; then
	echo "FAIL live-exitnode: the server did not say it was an exit node" >&2
	RC=1
fi

# 19000 locally -> 127.0.0.1:$PORT as seen from the server.
timeout 90 "$CLI" -v forward "$ADDR" "19000:127.0.0.1:$PORT" \
	> /dev/null 2> "$WORK/fwd.log" &
FWD_PID=$!
sleep 12

OUT=$(printf 'hello\n' | timeout 20 python3 -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", 19000), timeout=15)
s.sendall(sys.stdin.buffer.read())
s.shutdown(socket.SHUT_WR)
data = b""
while True:
    b = s.recv(4096)
    if not b:
        break
    data += b
sys.stdout.write(data.decode())
' 2>/dev/null || true)

kill "$FWD_PID" 2>/dev/null || true
wait "$FWD_PID" 2>/dev/null || true

echo "client got: ${OUT:-<nothing>}"
grep -E 'exit node:|through the server' "$WORK/fwd.log" "$WORK/srv.log" || true

case "$OUT" in
*"reached the third machine"*)
	echo "ok   the client reached a third address through the exit node"
	;;
*)
	echo "FAIL live-exitnode: the forward did not carry anything" >&2
	tail -20 "$WORK/fwd.log" >&2
	tail -20 "$WORK/srv.log" >&2
	RC=1
	;;
esac

# ---- and the same destination from the pipe ------------------------------
#
# `forward` has always been able to name a third address; the pipe could not,
# and `ssh -p` therefore could not either, because it is the pipe that its
# ProxyCommand runs. The syntax is deliberately the mapping's far half, so
# somebody who has written 19000:127.0.0.1:8080 once can write the tail of it
# here. This is the same server, still an exit node, reached the other way.
OUT=$(printf 'hello\n' | timeout 60 "$CLI" -v "$ADDR" "127.0.0.1:$PORT" \
	2> "$WORK/pipe.log" || true)

echo "pipe got: ${OUT:-<nothing>}"
case "$OUT" in
*"reached the third machine"*)
	echo "ok   the pipe reached a third address through the exit node"
	;;
*)
	echo "FAIL live-exitnode: the pipe did not reach the third address" >&2
	tail -20 "$WORK/pipe.log" >&2
	RC=1
	;;
esac

# And it said where it was going, in the address the user typed rather than
# the NAT64 form it travels as.
if ! grep -q "connecting to 127.0.0.1:$PORT, through the server" \
	"$WORK/pipe.log"; then
	echo "FAIL live-exitnode: the pipe did not report the destination" >&2
	tail -20 "$WORK/pipe.log" >&2
	RC=1
else
	echo "ok   and named the destination as it was typed"
fi

kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true

# ---- and with it off -----------------------------------------------------
# The same request against a server that was not told to be an exit node. It
# must fail: turning a tunnel endpoint into a proxy for everything it can
# reach has to be a decision, and a default that quietly allowed it would be
# the most dangerous kind of bug here -- one that only shows up as a feature.
echo
echo "--- serve $PORT (no exit-node) ---"
start_server "$PORT"

timeout 60 "$CLI" -v forward "$ADDR" "19001:127.0.0.1:$PORT" \
	> /dev/null 2> "$WORK/fwd2.log" &
FWD_PID=$!
sleep 12

OUT2=$(printf 'hello\n' | timeout 15 python3 -c '
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", 19001), timeout=10)
    s.sendall(sys.stdin.buffer.read())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        b = s.recv(4096)
        if not b:
            break
        data += b
    sys.stdout.write(data.decode())
except Exception:
    pass
' 2>/dev/null || true)

kill "$FWD_PID" 2>/dev/null || true
wait "$FWD_PID" 2>/dev/null || true

case "$OUT2" in
*"reached the third machine"*)
	echo "FAIL live-exitnode: a server that was NOT an exit node forwarded" >&2
	echo "     anyway, which is the one outcome that must never happen" >&2
	RC=1
	;;
*)
	echo "ok   a server that was not asked to forward, did not"
	;;
esac

[ $RC -eq 0 ] && echo "ok   live-exitnode"
exit $RC
