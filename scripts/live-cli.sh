#!/bin/sh
# End-to-end check of the tailcat-c command against a real tailcat server.
#
# Starts the upstream Go server, resolves the address it prints, pipes a line
# through `tailcat-c`, and requires the server to print that line on its own
# stdout. This is the whole stack driven the way a user would drive it.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
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

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$OUT" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-cli: the server never printed an address:" >&2
	cat "$OUT" >&2
	exit 1
fi

RESOLVED=$("$UPSTREAM" resolve "$ADDR")

echo
echo "\$ tailcat-c parse <addr>"
"$CLI" parse "$RESOLVED" | sed 's/^/    /'

MSG="the quick brown fox jumps over the lazy dog"
echo
echo "\$ echo '$MSG' | tailcat-c <addr>"
printf '%s\n' "$MSG" | "$CLI" -v "$RESOLVED" 2>&1 | sed 's/^/    /'

sleep 1
if grep -qF "$MSG" "$OUT"; then
	echo
	echo "the go server printed it on its own stdout:"
	grep -F "$MSG" "$OUT" | sed 's/^/    /'
	echo
	echo "ok   live-cli                 tailcat-c piped a line to a real"
	echo "                              tailcat server end to end"
	exit 0
fi

echo "live-cli: the server did not print the payload. Output was:" >&2
cat "$OUT" >&2
exit 1
