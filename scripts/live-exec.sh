#!/bin/sh
# The `exec` service: a command per connection, the connection as its stdio.
#
# Upstream's shape, and the reason it is a *raw TCP* service rather than an
# SSH one -- `tailcat <tc-addr> 80 < /dev/null` reaches it, on a server with
# nothing on port 80, because exec is not a service beside the others but the
# thing the server does.
#
# Three claims, and the last two are the ones that could pass by accident:
#
#   - the command runs and its output comes back down the tunnel;
#   - each connection gets its *own* process, so two clients do not share one
#     command's stdin -- checked by having the command echo what it was sent,
#     with different text each time;
#   - $TAILCAT_PEER_KEY and $TAILCAT_REMOTE_ADDR reach the child, and the key
#     is the key of the client that actually connected.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cat > "$WORK/greet.sh" <<'SH'
#!/bin/sh
read line
echo "you said: $line"
echo "peer: $TAILCAT_PEER_KEY"
echo "from: $TAILCAT_REMOTE_ADDR"
SH
chmod +x "$WORK/greet.sh"

echo "\$ tailcat-c serve exec -- greet.sh"
"$CLI" serve exec -- "$WORK/greet.sh" > /dev/null 2> "$WORK/srv.log" &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$WORK/srv.log" |
		head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-exec: the server never printed an address" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi

# The client's own public key, so the peer key the command saw can be checked
# against the client that actually connected rather than merely being present.
CLIENT_KEY=$("$CLI" printpub 2>/dev/null || true)

run() {
	printf '%s\n' "$1" | timeout 60 "$CLI" "$ADDR" 80 2> "$WORK/c.err" || true
}

OUT1=$(run "first message")
echo "$OUT1" | sed 's/^/    /'

if ! printf '%s' "$OUT1" | grep -qF "you said: first message"; then
	echo >&2
	echo "live-exec: the command did not receive what was sent." >&2
	sed 's/^/    /' "$WORK/c.err" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi
if ! printf '%s' "$OUT1" | grep -q "^peer: nodekey:[0-9a-f]\{64\}$"; then
	echo "live-exec: TAILCAT_PEER_KEY was missing or malformed." >&2
	exit 1
fi
if ! printf '%s' "$OUT1" | grep -q "^from: \[.*\]:[0-9]"; then
	echo "live-exec: TAILCAT_REMOTE_ADDR was missing or malformed." >&2
	exit 1
fi
if [ -n "$CLIENT_KEY" ]; then
	if ! printf '%s' "$OUT1" | grep -qF "peer: $CLIENT_KEY"; then
		echo "live-exec: the peer key is not the connecting client's." >&2
		echo "  command saw: $(printf '%s' "$OUT1" | sed -n 's/^peer: //p')" >&2
		echo "  client is:   $CLIENT_KEY" >&2
		exit 1
	fi
fi

# A second connection must be a second process with its own stdin. If both
# shared one, the text below would come back attached to the first message
# or not at all.
OUT2=$(run "second message")
if ! printf '%s' "$OUT2" | grep -qF "you said: second message"; then
	echo >&2
	echo "live-exec: a second connection did not get its own process." >&2
	printf '%s\n' "$OUT2" | sed 's/^/    /' >&2
	exit 1
fi

echo
echo "ok   live-exec               a command ran per connection, with the"
echo "                              connection as its stdio, the peer's key"
echo "                              and address in its environment, and a"
echo "                              second connection got its own process"
