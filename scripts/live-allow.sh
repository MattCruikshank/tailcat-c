#!/bin/sh
# A server's --allow list, against real clients through a real relay.
#
# The unit tests prove the list parses and matches. What they cannot prove is
# that it is enforced at the right moment and against the right key: the node
# key the *relay* reports, not the one a packet claims for itself.
#
# Both halves are checked, and the second is the one worth having. A list that
# admits the right client is easy; a list that silently admits the wrong one
# looks exactly the same from the allowed client's side, and that is precisely
# the bug that would ship.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
PORT="${PORT:-18088}"

WORK=$(mktemp -d)
# Keys go in a scratch config dir so this never touches a real one.
export XDG_CONFIG_HOME="$WORK/cfg"
mkdir -p "$XDG_CONFIG_HOME"
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
    c.sendall(b"the service answered\n")
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

# Two client identities. Only the first goes on the list.
GOOD=$("$CLI" genkey --key allowed --client 2>/dev/null | tail -1)
BAD=$("$CLI" genkey --key refused --client 2>/dev/null | tail -1)
case "$GOOD" in nodekey:*) ;; *) echo "FAIL: genkey did not print a nodekey: $GOOD" >&2; exit 1;; esac
case "$BAD" in nodekey:*) ;; *) echo "FAIL: genkey did not print a nodekey: $BAD" >&2; exit 1;; esac
echo "allowed: $(printf '%.24s' "$GOOD")..."
echo "refused: $(printf '%.24s' "$BAD")..."

"$CLI" -v serve --allow "$GOOD" "$PORT" > /dev/null 2> "$WORK/srv.log" &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*\(tc[A-Za-z0-9_-]\{40,\}\).*/\1/p' "$WORK/srv.log" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "FAIL live-allow: the server never printed an address" >&2
	sed -n '1,30p' "$WORK/srv.log" >&2
	exit 1
fi

RC=0

try_client() {
	key="$1"
	out=$(printf 'hello\n' |
		timeout 45 "$CLI" --key "$key" "$ADDR" "$PORT" 2>/dev/null || true)
	printf '%s' "$out"
}

echo
echo "--- the allowed client ---"
OUT=$(try_client allowed)
case "$OUT" in
*"the service answered"*)
	echo "ok   the allowed client got through"
	;;
*)
	echo "FAIL live-allow: the allowed client was refused" >&2
	tail -20 "$WORK/srv.log" >&2
	RC=1
	;;
esac

echo
echo "--- the client that is not on the list ---"
# Its address is identical -- the address is not the credential any more.
OUT=$(try_client refused)
case "$OUT" in
*"the service answered"*)
	echo "FAIL live-allow: a client that is NOT on the list got through," >&2
	echo "     which is the only outcome that makes the feature worthless" >&2
	RC=1
	;;
*)
	echo "ok   the client not on the list was refused"
	;;
esac

if grep -q 'not in --allow' "$WORK/srv.log"; then
	echo "ok   and the server said why, on its own stderr only"
else
	echo "FAIL live-allow: the server never logged the refusal" >&2
	RC=1
fi

# The refusal must be silence on the wire. The client should have timed out
# rather than been told anything, so nothing about "allow" may reach it.
echo
if printf '%s' "$OUT" | grep -qi 'allow\|refus\|denied'; then
	echo "FAIL live-allow: the refusal leaked a reason to the client" >&2
	RC=1
else
	echo "ok   the refused client was told nothing"
fi

[ $RC -eq 0 ] && echo && echo "ok   live-allow"
exit $RC
