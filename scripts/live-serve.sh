#!/bin/sh
# End-to-end check of `tailcat-c serve` against the real Go tailcat client.
#
# The mirror of live-cli.sh: there we dial a Go server, here a Go client dials
# ours. It is the direction that exercises the passive open -- the DERP
# responder, the WireGuard responder, the demultiplexer's listener and accept
# path -- none of which the dialling direction touches.
#
# `serve` is given no --relay, so this also covers fetching the DERP map and
# choosing a region, then minting an address the Go implementation can parse.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

OUT=$(mktemp)
GOT=$(mktemp)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	rm -f "$OUT" "$GOT"
}
trap cleanup EXIT

MSG="a real go client dialled our server"

echo "starting tailcat-c serve (no --relay: it picks a region itself)..."
"$CLI" -v serve > "$GOT" 2> "$OUT" &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 60 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$OUT" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-serve: tailcat-c never printed an address:" >&2
	cat "$OUT" >&2
	exit 1
fi

echo
echo "tailcat-c chose its own relay:"
grep -E '^# (fetching|probing|relay|listening)' "$OUT" | head -5 | sed 's/^/    /'

echo
echo "\$ tailcat resolve <our address>   # the Go tool parses what we minted"
"$UPSTREAM" resolve "$ADDR" > /dev/null || {
	echo "live-serve: upstream could not resolve our address" >&2
	exit 1
}
echo "    ok"

echo
echo "\$ echo '$MSG' | tailcat <our address>"
printf '%s\n' "$MSG" | "$UPSTREAM" "$ADDR" 2>&1 | sed 's/^/    /' || true

sleep 1
if grep -qF "$MSG" "$GOT"; then
	echo
	echo "tailcat-c printed it on its own stdout:"
	grep -F "$MSG" "$GOT" | sed 's/^/    /'
	echo
	echo "ok   live-serve               a real Go client connected to our"
	echo "                              server and its bytes came out"
	exit 0
fi

echo "live-serve: our server did not print the payload." >&2
echo "--- our stdout ---" >&2
cat "$GOT" >&2
echo "--- our stderr ---" >&2
cat "$OUT" >&2
exit 1
