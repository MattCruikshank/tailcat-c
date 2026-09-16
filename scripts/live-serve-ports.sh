#!/bin/sh
# `tailcat-c serve <ports>` proxying a real local service to a real Go client.
#
# The whole Phase 3 point in one check: a service that knows nothing about
# tailcat, reached from the outside through the tunnel. The local service is a
# throwaway HTTP responder on a high port; the client is the upstream Go
# `tailcat`, so nothing on the far side is ours.
#
# It also covers the half-close, which is the part a naive proxy gets wrong:
# the responder waits to read end-of-request before answering, so if the
# client's EOF is not carried through the tunnel it hangs instead of replying.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"
PORT="${PORT:-18080}"

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

OUT=$(mktemp)
ERR=$(mktemp)
SVC=$(mktemp)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${SVC_PID:-}" ] && kill "$SVC_PID" 2>/dev/null || true
	rm -f "$OUT" "$ERR" "$SVC"
}
trap cleanup EXIT

REPLY_BODY="served from localhost:$PORT through the tunnel"

# A local service that reads until EOF and then answers. Reading to EOF first
# is deliberate: it only replies if the half close arrived.
cat > "$SVC" <<SVCEOF
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $PORT))
s.listen(4)
sys.stderr.write("listening\n")
sys.stderr.flush()
while True:
    c, _ = s.accept()
    got = b""
    while True:
        b = c.recv(4096)
        if not b:
            break
        got += b
    c.sendall(b"$REPLY_BODY\n")
    c.sendall(b"you said: " + got)
    c.shutdown(socket.SHUT_WR)
    c.close()
SVCEOF

echo "starting a local service on 127.0.0.1:$PORT (it answers only after EOF)"
python3 "$SVC" 2>/dev/null &
SVC_PID=$!
sleep 1

echo "starting tailcat-c serve $PORT"
"$CLI" -v serve "$PORT" > /dev/null 2> "$ERR" &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 60 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$ERR" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-serve-ports: tailcat-c never printed an address:" >&2
	cat "$ERR" >&2
	exit 1
fi

grep -E '^# serving' "$ERR" | sed 's/^/    /'

echo
echo "\$ echo 'hello from the client' | tailcat <addr> $PORT"
printf 'hello from the client\n' | "$UPSTREAM" "$ADDR" "$PORT" > "$OUT" 2>&1 || true

echo "    what came back:"
sed 's/^/      /' "$OUT"

if ! grep -qF "$REPLY_BODY" "$OUT"; then
	echo >&2
	echo "live-serve-ports: the local service's reply did not come back." >&2
	echo "--- tailcat-c log ---" >&2
	cat "$ERR" >&2
	exit 1
fi
if ! grep -qF "you said: hello from the client" "$OUT"; then
	echo >&2
	echo "live-serve-ports: the request did not reach the local service" >&2
	echo "intact, or its end-of-input never arrived. The service only" >&2
	echo "answers after reading EOF, so a half close that is not carried" >&2
	echo "through the tunnel shows up exactly here." >&2
	cat "$ERR" >&2
	exit 1
fi

echo
echo "\$ tailcat <addr> 9999   # a port the server was not told to serve"
if printf 'x' | timeout 20 "$UPSTREAM" "$ADDR" 9999 >/dev/null 2>&1; then
	echo "live-serve-ports: an unserved port was reachable" >&2
	exit 1
fi
echo "    refused, as it should be"

echo
echo "ok   live-serve-ports         a real Go client reached a real local"
echo "                              service through the tunnel, half close"
echo "                              and port gating included"
