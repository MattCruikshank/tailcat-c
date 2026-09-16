#!/bin/sh
# End-to-end interoperability against a real tailcat server.
#
# Builds upstream tailcat, starts a server, resolves the short address it
# prints into a self-contained one, and hands that to build/livetailcat, which
# parses it, connects to the relay, meows, and completes a WireGuard
# handshake.
#
# Needs the network: it uses whichever public DERP relay the server picks.
set -eu

LIVETC="${LIVETC:-build/cosmo/livetailcat}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

OUT=$(mktemp)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	rm -f "$OUT"
}
trap cleanup EXIT

echo "starting a real tailcat server..."
"$UPSTREAM" > "$OUT" 2>&1 &
SRV_PID=$!

# Wait for it to pick a relay and print its address.
ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$OUT" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done

if [ -z "$ADDR" ]; then
	echo "live-tailcat: the server never printed an address:" >&2
	cat "$OUT" >&2
	exit 1
fi
echo "server address: $ADDR"

# The short form only names a relay region by number. Resolving embeds the
# relay's hostname and addresses, so the C side needs no DERP map fetcher --
# which it does not have yet.
RESOLVED=$("$UPSTREAM" resolve "$ADDR")
echo "resolved to a self-contained address (${#RESOLVED} chars)"
echo

if "$LIVETC" "$RESOLVED"; then
	echo
	echo "ok   live-tailcat             a real tailcat server accepted our meow"
	echo "                              and completed a WireGuard handshake"
	exit 0
fi

echo >&2
echo "live-tailcat: failed. Server output was:" >&2
cat "$OUT" >&2
exit 1
