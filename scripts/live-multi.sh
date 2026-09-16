#!/bin/sh
# Several real Go clients through one tailcat-c server at the same time.
#
# Each client gets its own WireGuard session, its own tunnel address and its
# own demultiplexer, so the thing that would go wrong if any of that were
# shared is exactly what this checks: every client asks the local service to
# echo a string only it knows, and every reply has to come back to the client
# that asked. A server that muddles sessions would still move bytes -- it
# would move them to the wrong peer.
#
# The clients are started together rather than in sequence, so their
# handshakes, rekeys and connections genuinely overlap.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"
PORT="${PORT:-18081}"
CLIENTS="${CLIENTS:-4}"

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${SVC_PID:-}" ] && kill "$SVC_PID" 2>/dev/null || true
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# An echo service that prefixes each reply, so a reply cannot be confused with
# the request that produced it.
cat > "$WORK/svc.py" <<SVCEOF
import socket, sys, threading
def serve(c):
    got = b""
    while True:
        b = c.recv(4096)
        if not b:
            break
        got += b
    c.sendall(b"echo:" + got)
    c.shutdown(socket.SHUT_WR)
    c.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $PORT))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
SVCEOF

echo "starting a local echo service on 127.0.0.1:$PORT"
python3 "$WORK/svc.py" >/dev/null 2>&1 </dev/null &
SVC_PID=$!
sleep 1

echo "starting tailcat-c serve $PORT"
"$CLI" -v serve "$PORT" > /dev/null 2> "$WORK/srv.log" &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 60 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$WORK/srv.log" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-multi: tailcat-c never printed an address:" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi
grep -E '^# serving' "$WORK/srv.log" | sed 's/^/    /'

echo
echo "starting $CLIENTS Go clients at once..."
n=1
PIDS=""
while [ $n -le "$CLIENTS" ]; do
	( printf 'client-%s-secret\n' "$n" |
	  timeout 60 "$UPSTREAM" "$ADDR" "$PORT" > "$WORK/out.$n" \
	      2>"$WORK/err.$n" ) &
	PIDS="$PIDS $!"
	n=$((n + 1))
done
# Only the clients. A bare `wait` also waits on the server and the local
# service, which are background jobs of this same shell and never exit, so it
# would hang for ever with every client long since finished.
for pid in $PIDS; do
	wait "$pid" || true
done

fail=0
n=1
while [ $n -le "$CLIENTS" ]; do
	want="echo:client-$n-secret"
	if ! grep -qF "$want" "$WORK/out.$n"; then
		echo "  client $n: MISSING its own reply" >&2
		sed 's/^/      /' "$WORK/out.$n" "$WORK/err.$n" >&2
		fail=1
	else
		# And it must not have received anybody else's.
		m=1
		while [ $m -le "$CLIENTS" ]; do
			if [ "$m" != "$n" ] &&
			   grep -qF "client-$m-secret" "$WORK/out.$n"; then
				echo "  client $n: saw client $m's data -- sessions crossed" >&2
				fail=1
			fi
			m=$((m + 1))
		done
		echo "  client $n: got its own reply, and nobody else's"
	fi
	n=$((n + 1))
done

echo
echo "what the server saw:"
grep -cE 'introduced itself' "$WORK/srv.log" |
	sed 's/^/    clients introduced: /'
grep -cE 'accepted a connection' "$WORK/srv.log" |
	sed 's/^/    connections accepted: /'

INTRO=$(grep -cE 'introduced itself' "$WORK/srv.log" || true)
if [ "$INTRO" -lt "$CLIENTS" ]; then
	echo "live-multi: only $INTRO of $CLIENTS clients were admitted" >&2
	fail=1
fi

if [ "$fail" != "0" ]; then
	echo >&2
	echo "--- server log ---" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi

echo
echo "ok   live-multi               $CLIENTS real Go clients served at once,"
echo "                              each seeing only its own traffic"
